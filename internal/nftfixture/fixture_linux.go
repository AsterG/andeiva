package nftfixture

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/firewallnft"
)

const ipPath = "/usr/bin/ip"
const nftPath = "/usr/sbin/nft"
const enterPath = "/usr/bin/nsenter"
const privPath = "/usr/bin/setpriv"

type namespace struct {
	handle *os.File
	inode  uint64
	keeper *exec.Cmd
	input  io.WriteCloser
}
type child struct {
	cmd   *exec.Cmd
	input io.Closer
}

type Fixture struct {
	mu         sync.Mutex
	self       string
	uid, gid   uint32
	host       uint64
	namespaces map[string]*namespace
	children   []child
	baseline   map[string][]byte
	sentinel   []byte
	closed     bool
}

// New requires the explicitly authorized Debian laboratory. It never installs
// tools, creates named namespaces, moves host interfaces or changes host sysctls.
func New(ctx context.Context, self string, uid, gid uint32) (_ *Fixture, err error) {
	if os.Geteuid() != 0 || uid == 0 || gid == 0 || !filepath.IsAbs(self) {
		return nil, errors.New("ANDEIVA_NFT_FIXTURE_PRIVILEGE")
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return nil, err
	}
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil || !bytes.Contains(osRelease, []byte("ID=debian\n")) || !bytes.Contains(osRelease, []byte("VERSION_ID=\"13\"")) {
		return nil, errors.New("ANDEIVA_NFT_FIXTURE_PLATFORM")
	}
	for _, path := range []string{self, ipPath, nftPath, enterPath, privPath} {
		if err := trustedExecutable(path); err != nil {
			return nil, fmt.Errorf("ANDEIVA_NFT_FIXTURE_EXECUTABLE: %s", path)
		}
	}
	f := &Fixture{self: self, uid: uid, gid: gid, namespaces: map[string]*namespace{}}
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	f.host, err = inode("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	f.baseline, err = hostSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	for _, role := range []string{"source", "gateway", "sink"} {
		cmd := exec.CommandContext(ctx, self, "--nft-fixture", "keeper")
		cmd.Env = fixedEnvironment()
		cmd.WaitDelay = 2 * time.Second
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
		input, err := cmd.StdinPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			_ = input.Close()
			return nil, err
		}
		ns := &namespace{keeper: cmd, input: input}
		f.namespaces[role] = ns
		ns.handle, err = os.Open("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/net")
		if err != nil {
			return nil, err
		}
		info, err := ns.handle.Stat()
		if err != nil {
			return nil, err
		}
		ns.inode = info.Sys().(*syscall.Stat_t).Ino
		if ns.inode == f.host {
			return nil, errors.New("ANDEIVA_NFT_FIXTURE_HOST_NAMESPACE")
		}
		for otherRole, other := range f.namespaces {
			if otherRole != role && other.inode == ns.inode {
				return nil, errors.New("ANDEIVA_NFT_FIXTURE_DUPLICATE_NAMESPACE")
			}
		}
	}
	if err := f.setup(ctx); err != nil {
		return nil, err
	}
	f.sentinel, err = f.readSentinel(ctx)
	if err != nil {
		return nil, err
	}
	if err := f.startListener(ctx); err != nil {
		return nil, err
	}
	if err := f.CheckListeners(ctx); err != nil {
		return nil, err
	}
	if err := f.CheckHost(ctx); err != nil {
		return nil, err
	}
	return f, nil
}

// CheckListeners verifies every positive control, including the always-denied
// transit service, independently of the gateway policy.
func (f *Fixture) CheckListeners(ctx context.Context) error {
	for _, protocol := range []string{"tcp", "udp"} {
		for port := 18080; port <= 18082; port++ {
			ok, err := f.ProbeLocal(ctx, protocol, port)
			if err != nil || !ok {
				if err == nil {
					err = errors.New("no echo response")
				}
				return fmt.Errorf("ANDEIVA_NFT_FIXTURE_LISTENER: %s/%d: %w", protocol, port, err)
			}
		}
	}
	return nil
}

func fixedEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
}
func trustedExecutable(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return errors.New("untrusted executable")
	}
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return errors.New("untrusted executable directory")
		}
		if dir == "/" {
			return nil
		}
	}
}
func inode(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Sys().(*syscall.Stat_t).Ino, nil
}

func (f *Fixture) checked(role string) (*namespace, error) {
	ns := f.namespaces[role]
	if f.closed || ns == nil || ns.handle == nil {
		return nil, errors.New("ANDEIVA_NFT_FIXTURE_CLOSED")
	}
	info, err := ns.handle.Stat()
	if err != nil || info.Sys().(*syscall.Stat_t).Ino != ns.inode || ns.inode == f.host {
		return nil, errors.New("ANDEIVA_NFT_FIXTURE_IDENTITY")
	}
	return ns, nil
}

func (f *Fixture) command(ctx context.Context, role, binary string, args []string, peer string, unprivileged, netAdmin bool) (*exec.Cmd, error) {
	if !f.allowedCommand(role, binary, args, peer, unprivileged, netAdmin) {
		return nil, errors.New("ANDEIVA_NFT_FIXTURE_COMMAND_DENIED")
	}
	ns, err := f.checked(role)
	if err != nil {
		return nil, err
	}
	argv := []string{"--net=/proc/self/fd/3", "--"}
	if unprivileged {
		argv = append(argv, privilegeArgs(f.uid, f.gid, netAdmin)...)
	}
	argv = append(argv, binary)
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, enterPath, argv...)
	cmd.Env = fixedEnvironment()
	cmd.WaitDelay = 2 * time.Second
	cmd.ExtraFiles = []*os.File{ns.handle}
	if peer != "" {
		other, err := f.checked(peer)
		if err != nil {
			return nil, err
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, other.handle)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}

func privilegeArgs(uid, gid uint32, netAdmin bool) []string {
	caps := "-all"
	if netAdmin {
		caps = "-all,+net_admin"
	}
	return []string{privPath, "--reuid=" + strconv.FormatUint(uint64(uid), 10), "--regid=" + strconv.FormatUint(uint64(gid), 10), "--clear-groups", "--bounding-set=" + caps, "--inh-caps=" + caps, "--ambient-caps=" + caps, "--no-new-privs", "--"}
}

func runBounded(ctx context.Context, cmd *exec.Cmd, input string) ([]byte, error) {
	var output boundedBuffer
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return output.Bytes(), fmt.Errorf("ANDEIVA_NFT_FIXTURE_COMMAND: %w: %s", err, output.String())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > 1024*1024-b.Len() {
		return 0, errors.New("ANDEIVA_NFT_FIXTURE_OUTPUT_LIMIT")
	}
	return b.Buffer.Write(p)
}

func (f *Fixture) run(ctx context.Context, role, binary string, args []string, peer string, input string) ([]byte, error) {
	adminDeny, compileErr := firewallnft.Compile(firewallnft.DefaultConfig())
	allowedDeny := compileErr == nil && role == "gateway" && binary == nftPath && slices.Equal(args, []string{"-j", "-f", "-"}) && input == string(adminDeny.Create)
	if input != "" && !allowedDeny && !(role == "gateway" && binary == nftPath && slices.Equal(args, []string{"-f", "-"}) && input == "add table inet andeiva_sentinel\n") {
		return nil, errors.New("ANDEIVA_NFT_FIXTURE_INPUT_DENIED")
	}
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd, err := f.command(deadline, role, binary, args, peer, false, false)
	if err != nil {
		return nil, err
	}
	return runBounded(deadline, cmd, input)
}

type setupCommand struct {
	role, binary string
	args         []string
	peer, input  string
}

func (f *Fixture) setupCommands() []setupCommand {
	var commands []setupCommand
	for _, role := range []string{"source", "gateway", "sink"} {
		commands = append(commands, setupCommand{role, ipPath, []string{"link", "set", "lo", "up"}, "", ""})
	}
	for _, link := range []struct{ gateway, peer, role string }{{"src0", "srcpeer", "source"}, {"dst0", "dstpeer", "sink"}} {
		commands = append(commands, setupCommand{"gateway", ipPath, []string{"link", "add", link.gateway, "type", "veth", "peer", "name", link.peer}, "", ""}, setupCommand{"gateway", ipPath, []string{"link", "set", link.peer, "netns", "/proc/self/fd/4"}, link.role, ""})
	}
	for _, item := range []struct{ role, dev, addr string }{{"source", "srcpeer", "198.18.0.2/30"}, {"gateway", "src0", "198.18.0.1/30"}, {"gateway", "dst0", "198.18.0.5/30"}, {"sink", "dstpeer", "198.18.0.6/30"}} {
		commands = append(commands, setupCommand{item.role, ipPath, []string{"address", "add", item.addr, "dev", item.dev}, "", ""}, setupCommand{item.role, ipPath, []string{"link", "set", item.dev, "up"}, "", ""})
	}
	for _, item := range []struct{ role, dst, via, dev string }{{"source", SinkIP + "/32", "198.18.0.1", "srcpeer"}, {"sink", SourceIP + "/32", "198.18.0.5", "dstpeer"}} {
		commands = append(commands, setupCommand{item.role, ipPath, []string{"route", "add", item.dst, "via", item.via, "dev", item.dev}, "", ""})
	}
	// /proc/sys/net is namespace scoped; this child first enters the pinned gateway.
	commands = append(commands, setupCommand{"gateway", f.self, []string{"--nft-fixture", "forward", strconv.FormatUint(f.host, 10)}, "", ""}, setupCommand{"gateway", nftPath, []string{"-f", "-"}, "", "add table inet andeiva_sentinel\n"})
	return commands
}

func (f *Fixture) setup(ctx context.Context) error {
	for _, command := range f.setupCommands() {
		if _, err := f.run(ctx, command.role, command.binary, command.args, command.peer, command.input); err != nil {
			return err
		}
	}
	return nil
}

func (f *Fixture) allowedCommand(role, binary string, args []string, peer string, unprivileged, netAdmin bool) bool {
	if !unprivileged && !netAdmin {
		for _, plan := range f.setupCommands() {
			if role == plan.role && binary == plan.binary && peer == plan.peer && slices.Equal(args, plan.args) {
				return true
			}
		}
		return role == "gateway" && binary == nftPath && peer == "" && (slices.Equal(args, sentinelArgs()) || slices.Equal(args, []string{"-j", "-f", "-"}))
	}
	if !unprivileged || f.uid == 0 || f.gid == 0 || binary != f.self || peer != "" {
		return false
	}
	if netAdmin {
		if role != "gateway" || len(args) != 4 || args[0] != "--guardian" || len(args[1]) != 32 || args[2] != strconv.FormatUint(f.host, 10) || args[3] != strconv.Itoa(os.Getpid()) {
			return false
		}
		id, err := hex.DecodeString(args[1])
		return err == nil && len(id) == 16 && hex.EncodeToString(id) == args[1]
	}
	if role == "sink" && slices.Equal(args, []string{"--nft-fixture", "listen", strconv.FormatUint(f.host, 10)}) {
		return true
	}
	if role == "source" && slices.Equal(args, []string{"--nft-fixture", "listen-source", strconv.FormatUint(f.host, 10)}) {
		return true
	}
	if (role == "source" || role == "sink") && len(args) == 5 && args[0] == "--nft-fixture" && (args[1] == "probe" || args[1] == "probe-source") && args[4] == strconv.FormatUint(f.host, 10) {
		port, err := strconv.Atoi(args[3])
		return err == nil && strconv.Itoa(port) == args[3] && validProbe(args[2], port)
	}
	return false
}

func sentinelArgs() []string { return []string{"-j", "list", "table", "inet", "andeiva_sentinel"} }

func (f *Fixture) readSentinel(ctx context.Context) ([]byte, error) {
	data, err := f.run(ctx, "gateway", nftPath, sentinelArgs(), "", "")
	if err != nil {
		return nil, err
	}
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	return json.Marshal(document)
}

// CheckSentinel detects changes to the separate inert table, including handles.
func (f *Fixture) CheckSentinel(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := f.readSentinel(ctx)
	if err != nil {
		return err
	}
	if len(f.sentinel) == 0 || !bytes.Equal(data, f.sentinel) {
		return errors.New("ANDEIVA_NFT_FIXTURE_SENTINEL_CHANGED")
	}
	return nil
}

func (f *Fixture) startListener(ctx context.Context) error {
	return f.startListenerRole(ctx, "sink", "listen")
}
func (f *Fixture) StartReverseListener(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startListenerRole(ctx, "source", "listen-source")
}
func (f *Fixture) startListenerRole(ctx context.Context, role, verb string) error {
	cmd, err := f.command(ctx, role, f.self, []string{"--nft-fixture", verb, strconv.FormatUint(f.host, 10)}, "", true, false)
	if err != nil {
		return err
	}
	input, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = input.Close()
		return err
	}
	f.children = append(f.children, child{cmd, input})
	ready := make(chan error, 1)
	go func() {
		expected := []byte("ANDEIVA_NFT_LISTEN_READY\n")
		got := make([]byte, len(expected))
		_, err := io.ReadFull(output, got)
		if err == nil && !bytes.Equal(got, expected) {
			err = errors.New("ANDEIVA_NFT_FIXTURE_READY_INVALID")
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(3 * time.Second):
		return errors.New("ANDEIVA_NFT_FIXTURE_READY_TIMEOUT")
	}
}

// StartGateway starts only the fixed guardian role of this executable, with its
// run identity bound to the retained host namespace and this supervisor PID.
func (f *Fixture) StartGateway(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (*exec.Cmd, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd, err := f.command(ctx, "gateway", f.self, args, "", true, true)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	f.children = append(f.children, child{cmd, nil})
	return cmd, nil
}

func (f *Fixture) probe(ctx context.Context, role, protocol string, port int) (bool, error) {
	return f.probeVerb(ctx, role, "probe", protocol, port)
}
func (f *Fixture) probeVerb(ctx context.Context, role, verb, protocol string, port int) (bool, error) {
	if !validProbe(protocol, port) {
		return false, errors.New("ANDEIVA_NFT_PROBE_INVALID")
	}
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd, err := f.command(deadline, role, f.self, []string{"--nft-fixture", verb, protocol, strconv.Itoa(port), strconv.FormatUint(f.host, 10)}, "", true, false)
	if err != nil {
		return false, err
	}
	var output boundedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 10 {
		return false, nil
	}
	return false, fmt.Errorf("ANDEIVA_NFT_PROBE_FAILED: %w: %s", err, output.String())
}
func (f *Fixture) Probe(ctx context.Context, protocol string, port int) (bool, error) {
	return f.probe(ctx, "source", protocol, port)
}
func (f *Fixture) ProbeLocal(ctx context.Context, protocol string, port int) (bool, error) {
	return f.probe(ctx, "sink", protocol, port)
}
func (f *Fixture) ProbeReverse(ctx context.Context, protocol string, port int) (bool, error) {
	return f.probeVerb(ctx, "sink", "probe-source", protocol, port)
}
func (f *Fixture) ProbeReverseLocal(ctx context.Context, protocol string, port int) (bool, error) {
	return f.probeVerb(ctx, "source", "probe-source", protocol, port)
}
func (f *Fixture) NamespaceIDs() map[string]uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]uint64{}
	for k, v := range f.namespaces {
		out[k] = v.inode
	}
	return out
}

func hostSnapshot(ctx context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, key := range []string{"rules", "routes", "routes6", "links"} {
		deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
		cmd, err := hostReadCommand(deadline, key)
		if err != nil {
			cancel()
			return nil, err
		}
		cmd.Env = fixedEnvironment()
		data, err := runBounded(deadline, cmd, "")
		cancel()
		if err != nil {
			return nil, err
		}
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, err
		}
		clean, err := json.Marshal(decoded)
		if err != nil {
			return nil, err
		}
		out[key] = clean
	}
	forward4, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/forwarding")
	if err != nil {
		return nil, err
	}
	forward6, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if err != nil {
		return nil, err
	}
	out["ipv4"], out["ipv6"] = forward4, forward6
	return out, nil
}

func hostReadCommand(ctx context.Context, key string) (*exec.Cmd, error) {
	switch key {
	case "rules":
		return exec.CommandContext(ctx, "/usr/sbin/nft", "-s", "-j", "list", "ruleset"), nil
	case "routes":
		return exec.CommandContext(ctx, "/usr/bin/ip", "-j", "route", "show", "table", "all"), nil
	case "routes6":
		return exec.CommandContext(ctx, "/usr/bin/ip", "-6", "-j", "route", "show", "table", "all"), nil
	case "links":
		return exec.CommandContext(ctx, "/usr/bin/ip", "-j", "link", "show"), nil
	default:
		return nil, errors.New("ANDEIVA_NFT_HOST_QUERY_INVALID")
	}
}
func (f *Fixture) CheckHost(ctx context.Context) error {
	now, err := hostSnapshot(ctx)
	if err != nil {
		return err
	}
	for key, want := range f.baseline {
		if !bytes.Equal(want, now[key]) {
			return fmt.Errorf("ANDEIVA_NFT_HOST_BASELINE_CHANGED: %s", key)
		}
	}
	return nil
}

// Close stops only subprocesses retained by this fixture, then drops its namespace
// references. It never searches for processes by a name or removes a global netns.
func (f *Fixture) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	var failures []error
	for i := len(f.children) - 1; i >= 0; i-- {
		c := f.children[i]
		if c.input != nil {
			_ = c.input.Close()
		}
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
			err := c.cmd.Wait()
			var exit *exec.ExitError
			if err != nil && !errors.As(err, &exit) && !strings.Contains(err.Error(), "Wait was already called") {
				failures = append(failures, err)
			}
		}
	}
	for _, role := range []string{"source", "sink", "gateway"} {
		ns := f.namespaces[role]
		if ns == nil {
			continue
		}
		if ns.input != nil {
			_ = ns.input.Close()
		}
		if ns.keeper != nil && ns.keeper.Process != nil {
			_ = ns.keeper.Process.Kill()
			err := ns.keeper.Wait()
			var exit *exec.ExitError
			if err != nil && !errors.As(err, &exit) {
				failures = append(failures, err)
			}
		}
		if ns.handle != nil {
			if err := ns.handle.Close(); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if err := f.verifyNoNamespaceReferences(); err != nil {
		failures = append(failures, err)
	}
	deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if f.baseline != nil {
		if err := f.CheckHost(deadline); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// The experiment creates no persistent namespace mount. After owned processes
// exit and handles close, any visible process or fd still holding one is a leak.
func (f *Fixture) verifyNoNamespaceReferences() error {
	wanted := map[uint64]bool{}
	for _, ns := range f.namespaces {
		if ns.inode != 0 {
			wanted[ns.inode] = true
		}
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		base := "/proc/" + entry.Name()
		if id, err := inode(base + "/ns/net"); err == nil && wanted[id] {
			return fmt.Errorf("ANDEIVA_NFT_FIXTURE_NAMESPACE_RETAINED: pid %s", entry.Name())
		}
		fds, err := os.ReadDir(base + "/fd")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		for _, fd := range fds {
			link, err := os.Readlink(base + "/fd/" + fd.Name())
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
			if !strings.HasPrefix(link, "net:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			id, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "net:["), "]"), 10, 64)
			if err == nil && wanted[id] {
				return fmt.Errorf("ANDEIVA_NFT_FIXTURE_NAMESPACE_FD_RETAINED: pid %s", entry.Name())
			}
		}
	}
	return nil
}
