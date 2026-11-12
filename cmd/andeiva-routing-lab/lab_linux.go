//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedflow"
	"github.com/AsterG/andeiva/internal/routednft"
)

var errLab = errors.New("ANDEIVA_ROUTING_LAB_FAILURE")

const ipPath = "/usr/sbin/ip"
const nftPath = "/usr/sbin/nft"

// A truncated output must be a failed observation, never a valid partial table.
type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > routednft.MaxObservation {
		return 0, errLab
	}
	return b.Buffer.Write(p)
}
func command(ctx context.Context, input []byte, path string, args ...string) ([]byte, error) {
	self, e := os.Executable()
	if e != nil {
		return nil, e
	}
	if !allowedExecutable(path, self) {
		return nil, errLab
	}
	// #nosec G204 -- Fixed executable allowlist above; all arguments originate in this isolated runner, never an API or shell.
	c := exec.CommandContext(ctx, path, args...)
	c.Stdin = bytes.NewReader(input)
	var out, diagnostic boundedBuffer
	c.Stdout = &out
	c.Stderr = &diagnostic
	if e := c.Run(); e != nil {
		return nil, fmt.Errorf("%w: %s", errLab, diagnostic.String())
	}
	return out.Bytes(), nil
}

type namespace struct {
	name     string
	identity os.FileInfo
	created  bool
}

func (n *namespace) verify() error {
	current, e := os.Lstat("/run/netns/" + n.name)
	if e != nil || !n.created || n.identity == nil || !os.SameFile(current, n.identity) || current.Mode()&os.ModeSymlink != 0 {
		return errLab
	}
	return nil
}
func (n *namespace) create(ctx context.Context) error {
	if _, e := os.Lstat("/run/netns/" + n.name); !os.IsNotExist(e) {
		return errLab
	}
	if _, e := command(ctx, nil, ipPath, "netns", "add", n.name); e != nil {
		return e
	}
	n.created = true
	info, e := os.Lstat("/run/netns/" + n.name)
	if e != nil {
		return e
	}
	n.identity = info
	return n.verify()
}

// open pins only this runner's namespace, checking both the path and the opened
// object. The executor additionally verifies nsfs/type and rejects host netns.
func (n *namespace) open() (*os.File, error) {
	if err := n.verify(); err != nil {
		return nil, err
	}
	path := "/run/netns/" + n.name
	before, err := os.Lstat(path)
	if err != nil || !sameNamespacePin(n.identity, before) {
		return nil, errLab
	}
	pin, err := os.Open(path) // #nosec G304 -- Internally generated namespace name, verified process-owned mount inode; opened inode is checked below.
	if err != nil {
		return nil, err
	}
	opened, err := pin.Stat()
	if err != nil || !sameNamespacePin(before, opened) || n.verify() != nil {
		return nil, errors.Join(errLab, pin.Close())
	}
	return pin, nil
}

func sameNamespacePin(expected, actual os.FileInfo) bool {
	return expected != nil && actual != nil && actual.Mode()&os.ModeSymlink == 0 && os.SameFile(expected, actual)
}

type networkPlanExecutor interface {
	Apply(context.Context, networkplan.Revision) error
	Verify(context.Context) error
	Restore() error
	Close() error
}

func applyTypedNetworkPlan(ctx context.Context, executor networkPlanExecutor) error {
	if err := executor.Apply(ctx, routednft.LabPolicy().Network); err != nil {
		return fmt.Errorf("network plan apply: %w", err)
	}
	if err := executor.Verify(ctx); err != nil {
		return fmt.Errorf("network plan verify: %w", err)
	}
	return nil
}

// The only override is an already-open FD 0 from the root-owned lab service
// definition, never an arbitrary descriptor number or a path from a caller.
func newLabNetworkExecutor(ctx context.Context, target *os.File, hostAnchorFD string) (*networkexecutor.Executor, error) {
	switch hostAnchorFD {
	case "":
		return networkexecutor.New(ctx, target)
	case "0":
		return networkexecutor.NewWithHost(ctx, target, os.Stdin)
	default:
		return nil, networkexecutor.ErrScope
	}
}

func closeTypedNetworkPlan(executor networkPlanExecutor) error {
	// Close must run even when restoration is uncertain, and its error is retained.
	restored := executor.Restore()
	return errors.Join(restored, executor.Close())
}
func (n *namespace) ip(ctx context.Context, args ...string) error {
	if e := n.verify(); e != nil {
		return e
	}
	_, e := command(ctx, nil, ipPath, append([]string{"-n", n.name}, args...)...)
	return e
}
func (n *namespace) exec(ctx context.Context, input []byte, path string, args ...string) ([]byte, error) {
	self, err := os.Executable()
	if err != nil || !allowedExecutable(path, self) {
		return nil, errLab
	}
	if e := n.verify(); e != nil {
		return nil, e
	}
	return command(ctx, input, ipPath, append([]string{"netns", "exec", n.name, path}, args...)...)
}
func (n *namespace) cleanup() error {
	if !n.created {
		return nil
	}
	if e := n.verify(); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, e := command(ctx, nil, ipPath, "netns", "delete", n.name)
	return e
}

type transport struct {
	gateway  *namespace
	self     string
	bindings []networkplan.ResolvedBinding
}

func (t transport) bindingCheck(ctx context.Context) error {
	data, e := t.gateway.exec(ctx, nil, t.self, "--binding-check")
	if e != nil {
		return e
	}
	var report networkplan.BindingReport
	if json.Unmarshal(data, &report) != nil || !equalBindings(report.Interfaces, t.bindings) {
		return errLab
	}
	return nil
}
func equalBindings(a, b []networkplan.ResolvedBinding) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (t transport) Check(ctx context.Context, b []byte) error {
	if e := t.bindingCheck(ctx); e != nil {
		return e
	}
	_, e := t.gateway.exec(ctx, b, nftPath, "-c", "-j", "-f", "-")
	return e
}
func (t transport) Apply(ctx context.Context, b []byte) error {
	if e := t.bindingCheck(ctx); e != nil {
		return e
	}
	_, e := t.gateway.exec(ctx, b, nftPath, "-j", "-f", "-")
	return e
}
func (t transport) Observe(ctx context.Context) ([]byte, error) {
	if e := t.bindingCheck(ctx); e != nil {
		return nil, e
	}
	return t.gateway.exec(ctx, nil, nftPath, "-j", "-n", "-y", "list", "table", "inet", routednft.TableName)
}

func run(args []string) error {
	if len(args) != 1 {
		return errLab
	}
	switch args[0] {
	case "--observe-current-flows":
		ctx, cancel := context.WithTimeout(context.Background(), routedflow.DumpTimeout)
		defer cancel()
		snapshot, e := routedflow.Collect(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(snapshot)
	case "--binding-check":
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		snapshot, e := networkinventory.Discover(ctx)
		if e != nil {
			return e
		}
		report, e := networkplan.Bind(routednft.LabPolicy().Network, snapshot)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	case "--group-listeners-empty":
		return verifyEmptyGatewaySockets()
	case "--serve-lan":
		return serve("198.18.0.2")
	case "--serve-wan":
		return serve("198.19.0.2")
	case "--probe-tcp":
		return probe("tcp", "198.19.0.2:18080")
	case "--probe-udp":
		return probe("udp", "198.19.0.2:18081")
	case "--probe-related":
		e := probe("udp", "198.19.0.2:18082")
		if !errors.Is(e, syscall.ECONNREFUSED) {
			return fmt.Errorf("related ICMP missing: %w", errors.Join(e, errLab))
		}
		return nil
	case "--probe-reverse":
		return probe("tcp", "198.18.0.2:18080")
	case "--probe-ipv6":
		e := probe("tcp6", "[fd00:19::2]:18080")
		var timeout net.Error
		if !errors.As(e, &timeout) || !timeout.Timeout() {
			return errors.Join(e, errLab)
		}
		return nil
	case "--hold":
		return hold()
	case "--run-isolated-lab", "--run-isolated-lab-with-flows", "--run-isolated-group-lab", "--run-isolated-group-lab-with-flows":
		release, e := os.ReadFile("/etc/os-release")
		if e != nil || runtime.GOARCH != "amd64" || os.Geteuid() != 0 || !bytes.Contains(release, []byte("ID=debian\n")) || !bytes.Contains(release, []byte("VERSION_ID=\"13\"")) {
			return errLab
		}
		signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(signalCtx, 55*time.Second)
		defer cancel()
		return labScenario(ctx, strings.HasSuffix(args[0], "-with-flows"), strings.HasPrefix(args[0], "--run-isolated-group-"))
	default:
		return errLab
	}
}

func serve(bind string) error {
	tcp, e := net.Listen("tcp4", bind+":18080")
	if e != nil {
		return e
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp4", bind+":18081")
	if e != nil {
		return e
	}
	defer udp.Close()
	go func() {
		var buf [64]byte
		for {
			n, peer, e := udp.ReadFrom(buf[:])
			if e != nil {
				return
			}
			if n == 4 && string(buf[:n]) == "ping" {
				_, _ = udp.WriteTo([]byte(peer.String()), peer)
			}
		}
	}()
	fmt.Println("READY")
	slots := make(chan struct{}, 8)
	for {
		c, e := tcp.Accept()
		if e != nil {
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { _ = c.Close(); <-slots }()
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))
			var b [4]byte
			for i := 0; i < 32; i++ {
				if _, e := io.ReadFull(c, b[:]); e != nil {
					return
				}
				if string(b[:]) != "ping" {
					return
				}
				if _, e := fmt.Fprintln(c, c.RemoteAddr().String()); e != nil {
					return
				}
			}
		}()
	}
}
func probe(network, target string) error {
	c, e := net.DialTimeout(network, target, 800*time.Millisecond)
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(800 * time.Millisecond))
	if _, e = c.Write([]byte("ping")); e != nil {
		return e
	}
	var b [128]byte
	n, e := c.Read(b[:])
	if e != nil {
		return e
	}
	fmt.Print(string(b[:n]))
	return nil
}
func hold() error {
	c, e := net.DialTimeout("tcp4", "198.19.0.2:18080", time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(c)
	if _, e = c.Write([]byte("ping")); e != nil {
		return e
	}
	if _, e = reader.ReadString('\n'); e != nil {
		return e
	}
	fmt.Println("FIRST")
	var trigger [1]byte
	if _, e = io.ReadFull(os.Stdin, trigger[:]); e != nil {
		return e
	}
	_ = c.SetDeadline(time.Now().Add(800 * time.Millisecond))
	if _, e = c.Write([]byte("ping")); e != nil {
		return e
	}
	if _, e = reader.ReadString('\n'); e == nil {
		return errors.New("ANDEIVA_REVOKED_SESSION_STILL_PASSES")
	}
	var timeout net.Error
	if !errors.As(e, &timeout) || !timeout.Timeout() {
		return e
	}
	fmt.Println("REVOKED")
	return nil
}

type child struct {
	cmd   *exec.Cmd
	lines *bufio.Reader
	input io.WriteCloser
}

func start(ctx context.Context, n *namespace, self, mode string) (*child, error) {
	if e := n.verify(); e != nil {
		return nil, e
	}
	// #nosec G204 -- Fixed ip binary, verified owned namespace, current executable and internally selected probe mode; no shell.
	c := exec.CommandContext(ctx, ipPath, "netns", "exec", n.name, self, mode)
	out, e := c.StdoutPipe()
	if e != nil {
		return nil, e
	}
	in, e := c.StdinPipe()
	if e != nil {
		return nil, e
	}
	c.Stderr = io.Discard
	if e = c.Start(); e != nil {
		return nil, e
	}
	return &child{c, bufio.NewReaderSize(out, 256), in}, nil
}
func (c *child) line(want string) error {
	s, e := c.lines.ReadString('\n')
	if e != nil || s != want+"\n" {
		return errLab
	}
	return nil
}

func lab(ctx context.Context, withFlows bool) (result error) {
	return labScenario(ctx, withFlows, false)
}

func labScenario(ctx context.Context, withFlows, withGroup bool) (result error) {
	hostNft, e := command(ctx, nil, nftPath, "-j", "-s", "list", "ruleset")
	if e != nil {
		return e
	}
	hostRoutes, e := command(ctx, nil, ipPath, "-j", "route", "show", "table", "all")
	if e != nil {
		return e
	}
	hostRoutes6, e := command(ctx, nil, ipPath, "-j", "-6", "route", "show", "table", "all")
	if e != nil {
		return e
	}
	token := make([]byte, 6)
	if _, e := rand.Read(token); e != nil {
		return e
	}
	prefix := "andrt-" + hex.EncodeToString(token)
	lan, gw, wan := &namespace{name: prefix + "-l"}, &namespace{name: prefix + "-g"}, &namespace{name: prefix + "-w"}
	fmt.Printf("LAB isolated namespaces %s %s %s\n", lan.name, gw.name, wan.name)
	// Cleanup only namespaces created by this process and whose inode still
	// matches. No existing host link, route, firewall table or sysctl is modified.
	defer func() {
		for _, n := range []*namespace{lan, wan, gw} {
			if e := n.cleanup(); e != nil {
				result = errors.Join(result, e)
			}
		}
		checkCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		a, e := command(checkCtx, nil, nftPath, "-j", "-s", "list", "ruleset")
		if e != nil || !bytes.Equal(a, hostNft) {
			result = errors.Join(result, errors.New("host nftables invariant failed"), e)
		}
		b, e := command(checkCtx, nil, ipPath, "-j", "route", "show", "table", "all")
		if e != nil || !bytes.Equal(b, hostRoutes) {
			result = errors.Join(result, errors.New("host routes invariant failed"), e)
		}
		c, e := command(checkCtx, nil, ipPath, "-j", "-6", "route", "show", "table", "all")
		if e != nil || !bytes.Equal(c, hostRoutes6) {
			result = errors.Join(result, errors.New("host IPv6 routes invariant failed"), e)
		}
		if result == nil {
			fmt.Println("PASS namespaces cleaned; host routes and nftables unchanged")
		}
	}()
	for _, n := range []*namespace{lan, gw, wan} {
		if e := n.create(ctx); e != nil {
			return e
		}
	}
	setup := []struct {
		n    *namespace
		args []string
	}{
		{lan, []string{"link", "add", "client0", "type", "veth", "peer", "name", "lan0", "netns", gw.name}},
		{wan, []string{"link", "add", "server0", "type", "veth", "peer", "name", "wan0", "netns", gw.name}},
		{lan, []string{"addr", "add", "198.18.0.2/24", "dev", "client0"}}, {wan, []string{"addr", "add", "198.19.0.2/24", "dev", "server0"}},
		{gw, []string{"link", "set", "lan0", "address", "02:00:00:00:01:01"}}, {gw, []string{"link", "set", "wan0", "address", "02:00:00:00:02:01"}},
		{lan, []string{"link", "set", "client0", "up"}}, {wan, []string{"link", "set", "server0", "up"}}, {gw, []string{"link", "set", "lan0", "up"}}, {gw, []string{"link", "set", "wan0", "up"}},
		{lan, []string{"route", "add", "default", "via", "198.18.0.1"}},
		{wan, []string{"route", "add", "198.18.0.0/24", "via", "198.19.0.1"}},
		{lan, []string{"-6", "addr", "add", "fd00:18::2/64", "dev", "client0", "nodad"}},
		{wan, []string{"-6", "addr", "add", "fd00:19::2/64", "dev", "server0", "nodad"}},
		{gw, []string{"-6", "addr", "add", "fd00:18::1/64", "dev", "lan0", "nodad"}},
		{gw, []string{"-6", "addr", "add", "fd00:19::1/64", "dev", "wan0", "nodad"}},
		{lan, []string{"-6", "route", "add", "default", "via", "fd00:18::1"}},
		{wan, []string{"-6", "route", "add", "fd00:18::/64", "via", "fd00:19::1"}},
	}
	for _, s := range setup {
		if e := s.n.ip(ctx, s.args...); e != nil {
			return e
		}
	}
	pin, e := gw.open()
	if e != nil {
		return e
	}
	// This recovery lifetime is independent of lab request cancellation. Its defer
	// runs after restoration, but before the earlier namespace cleanup defer.
	supervisorCtx, stopSupervisor := context.WithCancel(context.Background())
	defer stopSupervisor()
	network, e := newLabNetworkExecutor(supervisorCtx, pin, os.Getenv("ANDEIVA_LAB_HOST_ANCHOR_FD"))
	closeErr := pin.Close() // New owns a duplicated descriptor, not this caller pin.
	if e != nil {
		return fmt.Errorf("network executor constructor: %w", errors.Join(e, closeErr))
	}
	applied := false
	defer func() {
		cleanupErr := closeTypedNetworkPlan(network)
		result = errors.Join(result, cleanupErr)
		if applied && cleanupErr == nil {
			fmt.Println("PASS typed network plan applied/readback/restored")
		}
	}()
	if closeErr != nil {
		return closeErr
	}
	if !withGroup {
		if e = applyTypedNetworkPlan(ctx, network); e != nil {
			return e
		}
		applied = true
		fmt.Println("PASS typed network plan applied/readback")
	}
	if !withGroup {
		if e := enableFixtureForwarding(ctx, gw); e != nil {
			return e
		}
	}
	policy := routednft.LabPolicy()
	artifact, e := routednft.Compile(policy)
	if e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	data, e := gw.exec(ctx, nil, self, "--binding-check")
	if e != nil {
		return e
	}
	var bound networkplan.BindingReport
	if json.Unmarshal(data, &bound) != nil {
		return errLab
	}
	t := transport{gateway: gw, self: self, bindings: bound.Interfaces}
	var adapter policyAdapter
	var group *groupLab
	if withGroup {
		group, e = newGroupLab(ctx, network, t)
		if e != nil {
			return fmt.Errorf("group fixture create: %w", e)
		}
		defer func() { result = errors.Join(result, group.Close()) }()
		adapter, applied = group, true
		if e = enableFixtureForwarding(ctx, gw); e != nil {
			return e
		}
		// Local-In correctly denies unknown IPv6 control traffic. Static peer
		// neighbor entries let the existing IPv6 test reach the forward drop
		// counter, without adding an INPUT/forward allow for qualification.
		if e = lan.ip(ctx, "-6", "neigh", "add", "fd00:18::1", "lladdr", "02:00:00:00:01:01", "nud", "permanent", "dev", "client0"); e != nil {
			return e
		}
	} else {
		if e = t.Check(ctx, artifact.Create); e != nil {
			return e
		}
		if e = t.Apply(ctx, artifact.Create); e != nil {
			return e
		}
		adapter, e = routednft.NewAdapter(t, artifact.Revision)
		if e != nil {
			return e
		}
	}
	if _, e = adapter.Inspect(ctx); e != nil {
		return fmt.Errorf("initial readback: %w", e)
	}
	server, e := start(ctx, wan, self, "--serve-wan")
	if e != nil {
		return e
	}
	defer func() { _ = server.cmd.Process.Kill(); _ = server.cmd.Wait() }()
	if e = server.line("READY"); e != nil {
		return e
	}
	lanServer, e := start(ctx, lan, self, "--serve-lan")
	if e != nil {
		return e
	}
	defer func() { _ = lanServer.cmd.Process.Kill(); _ = lanServer.cmd.Wait() }()
	if e = lanServer.line("READY"); e != nil {
		return e
	}
	if group != nil {
		if e = group.qualifyColdRecoveryAndConfirm(ctx, lan); e != nil {
			return e
		}
	}
	for _, mode := range []string{"--probe-tcp", "--probe-udp"} {
		out, e := lan.exec(ctx, nil, self, mode)
		if e != nil || !strings.HasPrefix(string(out), "198.19.0.1:") {
			return fmt.Errorf("SNAT %s: %w", mode, errors.Join(e, errLab))
		}
		fmt.Printf("PASS %s SNAT peer=%s\n", mode, strings.TrimSpace(string(out)))
	}
	if withFlows {
		if e = t.bindingCheck(ctx); e != nil {
			return e
		}
		observed, e := gw.exec(ctx, nil, self, "--observe-current-flows")
		if e != nil {
			return e
		}
		if _, e = decodeSNATFlowSnapshot(observed); e != nil {
			return e
		}
		if _, e = adapter.Inspect(ctx); e != nil {
			return e
		}
		fmt.Printf("FLOW_OBSERVATION %s\n", bytes.TrimSpace(observed))
		fmt.Println("PASS current-namespace TCP/UDP conntrack tuples prove observed SNAT")
	}
	if _, e = lan.exec(ctx, nil, self, "--probe-related"); e != nil {
		return e
	}
	related, e := adapter.Inspect(ctx)
	if e != nil {
		return e
	}
	found := false
	for _, c := range related.Counters {
		if c.Rule == "udp-test:reply:related" && c.Packets > 0 {
			found = true
		}
	}
	if !found {
		return errors.New("related ICMP counter missing")
	}
	fmt.Println("PASS related ICMP port unreachable bound to current tuple and mark")
	beforeDrop := uint64(0)
	for _, c := range related.Counters {
		if c.Rule == "default-deny" {
			beforeDrop = c.Packets
		}
	}
	if _, e = lan.exec(ctx, nil, self, "--probe-ipv6"); e != nil {
		return e
	}
	ipv6, e := adapter.Inspect(ctx)
	if e != nil {
		return e
	}
	blocked := false
	for _, c := range ipv6.Counters {
		if c.Rule == "default-deny" && c.Packets > beforeDrop {
			blocked = true
		}
	}
	if !blocked {
		return errors.New("IPv6 did not reach forward deny")
	}
	fmt.Println("PASS IPv6 forward denied with observed counter")
	if _, e = wan.exec(ctx, nil, self, "--probe-reverse"); e == nil {
		return errors.New("unsolicited reverse passed")
	}
	fmt.Println("PASS unsolicited reverse denied")
	held, e := start(ctx, lan, self, "--hold")
	if e != nil {
		return e
	}
	defer func() { _ = held.cmd.Process.Kill(); _ = held.cmd.Wait() }()
	if e = held.line("FIRST"); e != nil {
		return e
	}
	denied := policy
	denied.Rules = append([]routednft.Rule{}, policy.Rules...)
	denied.Rules[0].Action = "deny"
	rev, e := routednft.Canonical(denied)
	if e != nil {
		return e
	}
	if e = adapter.Apply(ctx, rev); e != nil {
		return e
	}
	if _, e = held.input.Write([]byte{1}); e != nil {
		return e
	}
	if e = held.line("REVOKED"); e != nil {
		return e
	}
	fmt.Println("PASS existing TCP revoked by current deny")
	noNAT := policy
	noNAT.NAT = nil
	rev, e = routednft.Canonical(noNAT)
	if e != nil {
		return e
	}
	if e = adapter.Apply(ctx, rev); e != nil {
		return e
	}
	if out, e := lan.exec(ctx, nil, self, "--probe-tcp"); e != nil || !strings.HasPrefix(string(out), "198.18.0.2:") {
		return fmt.Errorf("routed without NAT: %w", errors.Join(e, errLab))
	}
	fmt.Println("PASS routed without NAT preserves source")
	natOnly := policy
	natOnly.Rules = nil
	rev, e = routednft.Canonical(natOnly)
	if e != nil {
		return e
	}
	if e = adapter.Apply(ctx, rev); e != nil {
		return e
	}
	if _, e = lan.exec(ctx, nil, self, "--probe-tcp"); e == nil {
		return errors.New("NAT authorized forwarding")
	}
	fmt.Println("PASS NAT does not authorize forwarding")
	observed, e := adapter.Inspect(ctx)
	if e != nil {
		return e
	}
	encoded, e := json.Marshal(observed)
	if e != nil {
		return e
	}
	fmt.Println(string(encoded))
	if group != nil {
		if e = group.qualifyExpiry(ctx, lan); e != nil {
			return e
		}
	}
	return nil
}

// The child is this reviewed executable in the owned gateway namespace. Treat
// even that bounded output as an observation, never as permission to forward.
func decodeSNATFlowSnapshot(data []byte) (routedflow.Snapshot, error) {
	if len(data) == 0 || len(data) > routednft.MaxObservation || !jsoncheck.UniqueControlFields(data) {
		return routedflow.Snapshot{}, errLab
	}
	var snapshot routedflow.Snapshot
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&snapshot) != nil || d.Decode(new(any)) != io.EOF || snapshot.SchemaVersion != 1 || snapshot.Flows == nil || len(snapshot.Flows) > routedflow.MaxFlows || snapshot.SkippedOtherProtocols < 0 || snapshot.SkippedOtherProtocols > routedflow.MaxMessages || snapshot.StartedAt.IsZero() || snapshot.FinishedAt.Before(snapshot.StartedAt) {
		return routedflow.Snapshot{}, errLab
	}
	seenTCP, seenUDP := false, false
	for _, flow := range snapshot.Flows {
		if !coherentFlow(flow) {
			return routedflow.Snapshot{}, errLab
		}
		port := uint16(18080)
		if flow.Original.Protocol == "udp" {
			port = 18081
		}
		if flow.Original.Source.Address.String() != "198.18.0.2" || flow.Original.Source.Port < 1024 || flow.Original.Destination.Address.String() != "198.19.0.2" || flow.Original.Destination.Port != port {
			continue
		}
		if flow.Reply.Source.Address.String() != "198.19.0.2" || flow.Reply.Source.Port != port || flow.Reply.Destination.Address.String() != "198.19.0.1" || flow.Reply.Destination.Port == 0 || !flow.SourceChanged || flow.DestinationChanged {
			return routedflow.Snapshot{}, errLab
		}
		if flow.Original.Protocol == "tcp" {
			seenTCP = true
		} else {
			seenUDP = true
		}
	}
	if !seenTCP || !seenUDP {
		return routedflow.Snapshot{}, errLab
	}
	return snapshot, nil
}

func coherentFlow(flow routedflow.Flow) bool {
	protocol := flow.Original.Protocol
	if protocol != "tcp" && protocol != "udp" {
		return false
	}
	for _, tuple := range []routedflow.Tuple{flow.Original, flow.Reply, flow.ForwardTranslated, flow.ReplyTranslated} {
		if tuple.Protocol != protocol || !tuple.Source.Address.Is4() || !tuple.Destination.Address.Is4() {
			return false
		}
	}
	return flow.ForwardTranslated.Source == flow.Reply.Destination && flow.ForwardTranslated.Destination == flow.Reply.Source && flow.ReplyTranslated.Source == flow.Original.Destination && flow.ReplyTranslated.Destination == flow.Original.Source && flow.SourceChanged == (flow.Original.Source != flow.ForwardTranslated.Source) && flow.DestinationChanged == (flow.Original.Destination != flow.ForwardTranslated.Destination)
}

// Both the namespace launcher and its inner executable use this fixed allowlist.
func allowedExecutable(path, self string) bool {
	return path == ipPath || path == nftPath || path == "/usr/sbin/sysctl" || (self != "" && path == self)
}
