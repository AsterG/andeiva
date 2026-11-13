//go:build linux

package networkexecutor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/AsterG/andeiva/internal/dhcpclient"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

// This private test protocol is deliberately not a runtime API or durable work
// format. Exclusive inherited pipe endpoints are its authentication boundary.
const dhcpLeaseFrameLimit = 8192

type dhcpLeaseBoot struct {
	PID, Parent int
	ParentStart uint64
	Identity    OwnedNamespaceIdentity
	Owner       LeaseOwner
	Desired     networkplan.Revision
}

type dhcpLeaseFrame struct {
	Kind      string            `json:"kind"`
	Boot      *dhcpLeaseBoot    `json:"boot,omitempty"`
	Lease     *dhcpclient.Lease `json:"lease,omitempty"`
	Fact      *LeaseFact        `json:"fact,omitempty"`
	PID       int               `json:"pid,omitempty"`
	Start     uint64            `json:"start,omitempty"`
	Outcome   LeaseOutcome      `json:"outcome,omitempty"`
	Mutations int               `json:"mutations,omitempty"`
	Error     string            `json:"error,omitempty"`
	Pdeath    int               `json:"pdeath,omitempty"`
}

type dhcpLeasePipe struct{ read, write *os.File }

func (p dhcpLeasePipe) send(message dhcpLeaseFrame) error {
	b, err := json.Marshal(message)
	if err != nil || len(b) == 0 || len(b) > dhcpLeaseFrameLimit {
		return ErrScope
	}
	if err := p.write.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	_, err = p.write.Write(append(header[:], b...))
	return err
}

func decodeDHCPLeaseFrame(b []byte) (dhcpLeaseFrame, error) {
	var m dhcpLeaseFrame
	if len(b) == 0 || len(b) > dhcpLeaseFrameLimit || !jsoncheck.UniqueFields(b) {
		return m, ErrScope
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF || len(m.Error) > 128 {
		return dhcpLeaseFrame{}, ErrScope
	}
	// Internal engine structs intentionally have no public JSON contract. Require
	// our exact encoder output, rejecting case aliases and omitted/default fields.
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(canonical, b) {
		return dhcpLeaseFrame{}, ErrScope
	}
	return m, nil
}

func (p dhcpLeasePipe) receive() (dhcpLeaseFrame, error) {
	return p.receiveWithin(15 * time.Second)
}

func (p dhcpLeasePipe) receiveWithin(timeout time.Duration) (dhcpLeaseFrame, error) {
	if err := p.read.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return dhcpLeaseFrame{}, err
	}
	var header [4]byte
	if _, err := io.ReadFull(p.read, header[:]); err != nil {
		return dhcpLeaseFrame{}, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > dhcpLeaseFrameLimit {
		return dhcpLeaseFrame{}, ErrScope
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(p.read, b); err != nil {
		return dhcpLeaseFrame{}, err
	}
	return decodeDHCPLeaseFrame(b)
}

func dhcpLeaseProcessStart(pid int) (uint64, error) {
	if pid <= 0 {
		return 0, ErrScope
	}
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(b) > 8192 {
		return 0, ErrScope
	}
	i := strings.LastIndex(string(b), ") ")
	if i < 0 {
		return 0, ErrScope
	}
	fields := strings.Fields(string(b)[i+2:])
	if len(fields) < 20 {
		return 0, ErrScope
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func dhcpLeasePipeIdentity(file *os.File, access int) error {
	var st unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFIFO || st.Mode&0777 != 0600 {
		return ErrScope
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != access {
		return ErrScope
	}
	return nil
}

func dhcpLeaseRootParent(pid int, start uint64) bool {
	if pid != os.Getppid() || start == 0 {
		return false
	}
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(b) > 65536 {
		return false
	}
	root := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			root = reflect.DeepEqual(strings.Fields(strings.TrimPrefix(line, "Uid:")), []string{"0", "0", "0", "0"})
		}
	}
	actual, err := dhcpLeaseProcessStart(pid)
	return root && err == nil && actual == start && pid == os.Getppid()
}

func dhcpLeaseParentDeathSignal() (int, error) {
	var signal int32
	_, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&signal)), 0, 0, 0, 0) // #nosec G103 -- Kernel ABI writes one local int32; no external pointer or buffer.
	if errno != 0 {
		return 0, errno
	}
	return int(signal), nil
}

func dhcpLeaseArmParentDeath(boot dhcpLeaseBoot) error {
	if !dhcpLeaseRootParent(boot.Parent, boot.ParentStart) {
		return ErrScope
	}
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	signal, err := dhcpLeaseParentDeathSignal()
	if err != nil || signal != int(unix.SIGKILL) || !dhcpLeaseRootParent(boot.Parent, boot.ParentStart) {
		return ErrScope
	}
	return nil
}

// Child roles have no public listener. Their only commands arrive through the
// supervisor-created, direction-checked anonymous pipes.
func TestNativeDHCPLeaseRole(t *testing.T) {
	role := os.Getenv("ANDEIVA_DHCP_LEASE_ROLE")
	if os.Getenv("ANDEIVA_DHCP_LEASE_NATIVE") != "1" || role == "" {
		t.Skip("native role only")
	}
	if os.Getenv("CI") != "" || (role != "owner" && role != "helper" && role != "broker") {
		t.Fatal("role denied")
	}
	for fd := 3; fd <= 7; fd++ {
		unix.CloseOnExec(fd)
	}
	// ExtraFiles are inherited in blocking mode; register only authenticated
	// anonymous pipe endpoints with Go's poller so deadlines remain effective.
	for fd, access := range map[int]int{5: unix.O_RDONLY, 6: unix.O_WRONLY} {
		var st unix.Stat_t
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFIFO || st.Mode&0777 != 0600 || err != nil || flags&unix.O_ACCMODE != access || unix.SetNonblock(fd, true) != nil {
			t.Fatal("inherited pipe identity")
		}
	}
	pipe := dhcpLeasePipe{os.NewFile(5, "supervisor-read"), os.NewFile(6, "supervisor-write")}
	if dhcpLeasePipeIdentity(pipe.read, unix.O_RDONLY) != nil || dhcpLeasePipeIdentity(pipe.write, unix.O_WRONLY) != nil {
		t.Fatal("pipe identity")
	}
	defer pipe.read.Close()
	defer pipe.write.Close()
	init, err := pipe.receive()
	if err != nil || init.Kind != "init" || init.Boot == nil || init.Boot.PID != os.Getpid() || !dhcpLeaseRootParent(init.Boot.Parent, init.Boot.ParentStart) {
		t.Fatalf("bootstrap identity: receive=%v kind=%q boot_present=%t", err, init.Kind, init.Boot != nil)
	}
	// setpriv clears the exec-time setting. Retain this thread after rearming.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := dhcpLeaseArmParentDeath(*init.Boot); err != nil {
		t.Fatal("parent-death binding", err)
	}
	if role == "owner" {
		runDHCPLeaseOwner(t, pipe)
		return
	}
	if role == "broker" {
		runDHCPLeaseRelay(t, pipe, *init.Boot)
		return
	}
	runDHCPLeaseHelper(t, pipe, *init.Boot)
}

func runDHCPLeaseOwner(t *testing.T, pipe dhcpLeasePipe) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("owner identity")
	}
	host, mount := os.NewFile(3, "host-network"), os.NewFile(7, "host-mount")
	defer host.Close()
	defer mount.Close()
	iface, err := net.InterfaceByName("wan0")
	if err != nil {
		t.Fatal(err)
	}
	c, err := dhcpclient.StartIsolated(context.Background(), dhcpclient.Scope{HostNetwork: host, HostMount: mount, Interface: iface.Name, Index: iface.Index, HardwareAddress: iface.HardwareAddr.String()})
	if err != nil {
		t.Fatal("DHCP owner start", err)
	}
	defer c.Stop()
	pid, err := strconv.Atoi(c.PID())
	if err != nil {
		t.Fatal(err)
	}
	start, err := dhcpLeaseProcessStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	if pipe.send(dhcpLeaseFrame{Kind: "owner_ready", PID: pid, Start: start}) != nil {
		t.Fatal("owner ready channel")
	}
	for {
		m, err := pipe.receiveWithin(4 * time.Minute)
		if err != nil {
			t.Fatal("owner channel", err)
		}
		out := dhcpLeaseFrame{Kind: "result"}
		switch m.Kind {
		case "current":
			lease, e := c.Current()
			if e != nil {
				out.Error = "unavailable"
			} else {
				out.Lease = &lease
			}
		case "renew":
			err = c.Renew()
		case "rebind":
			err = c.Rebind()
		case "close":
			c.Stop()
		default:
			t.Fatal("owner command denied")
		}
		if err != nil {
			out.Error = "unavailable"
		}
		if pipe.send(out) != nil {
			t.Fatal("owner result channel")
		}
		if m.Kind == "close" {
			return
		}
	}
}

func runDHCPLeaseHelper(t *testing.T, pipe dhcpLeasePipe, boot dhcpLeaseBoot) {
	if os.Getuid() != leaseNativeUID || os.Getgid() != leaseNativeUID {
		t.Fatal("helper identity")
	}
	host, target := os.NewFile(3, "host-network"), os.NewFile(4, "owned-network")
	defer host.Close()
	defer target.Close()
	current := func(context.Context) (LeaseFact, error) {
		if pipe.send(dhcpLeaseFrame{Kind: "current"}) != nil {
			return LeaseFact{}, ErrLeaseUnavailable
		}
		m, err := pipe.receive()
		if err != nil || m.Kind != "fact" || m.Error != "" || m.Fact == nil {
			return LeaseFact{}, ErrLeaseUnavailable
		}
		return *m.Fact, nil
	}
	l, err := NewLeaseInOwnedNamespace(context.Background(), target, host, boot.Identity, 0, LeaseOptions{Desired: boot.Desired, Owner: boot.Owner, Current: current})
	if err != nil {
		if pipe.send(dhcpLeaseFrame{Kind: "denied", Error: err.Error()}) != nil {
			t.Fatal("constructor refusal channel")
		}
		return
	}
	defer func() { _, _ = l.Withdraw(context.Background()); _ = l.Close() }()
	mutations := 0
	run := l.base.run
	l.base.run = func(ctx context.Context, op operation) ([]byte, error) {
		if strings.HasSuffix(op.kind, "-add") || strings.HasSuffix(op.kind, "-delete") {
			mutations++
		}
		return run(ctx, op)
	}
	signal, err := dhcpLeaseParentDeathSignal()
	if err != nil || signal != int(unix.SIGKILL) || !dhcpLeaseRootParent(boot.Parent, boot.ParentStart) {
		t.Fatal("helper parent-death readiness")
	}
	if pipe.send(dhcpLeaseFrame{Kind: "helper_ready", Pdeath: signal}) != nil {
		t.Fatal("helper ready channel")
	}
	for {
		m, err := pipe.receiveWithin(4 * time.Minute)
		if err != nil {
			t.Fatal("helper command channel", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		out := dhcpLeaseFrame{Kind: "result"}
		switch m.Kind {
		case "refresh":
			out.Outcome, err = l.Refresh(ctx)
		case "verify":
			err = l.Verify(ctx)
		case "withdraw":
			out.Outcome, err = l.Withdraw(ctx)
		case "close":
			err = l.Close()
		default:
			cancel()
			t.Fatal("helper command denied")
		}
		cancel()
		if err != nil {
			out.Error = err.Error()
		}
		out.Mutations = mutations
		if pipe.send(out) != nil {
			t.Fatal("helper result channel")
		}
		if m.Kind == "close" {
			if err != nil {
				t.Fatal("close active helper")
			}
			return
		}
	}
}

// Killing this actual root parent must SIGKILL its post-setpriv helper; an EOF
// exit from a child without parent-death binding cannot satisfy the native test.
func runDHCPLeaseRelay(t *testing.T, pipe dhcpLeasePipe, boot dhcpLeaseBoot) {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("broker identity")
	}
	host, target := os.NewFile(3, "host-network"), os.NewFile(4, "owned-network")
	defer host.Close()
	defer target.Close()
	helper := startDHCPLeaseChild(t, "helper", host, target, nil)
	boot.PID, boot.Parent = helper.cmd.Process.Pid, os.Getpid()
	var err error
	boot.ParentStart, err = dhcpLeaseProcessStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if helper.pipe.send(dhcpLeaseFrame{Kind: "init", Boot: &boot}) != nil {
		t.Fatal("relay helper bootstrap")
	}
	ready, err := helper.pipe.receive()
	if err != nil || ready.Kind != "helper_ready" || ready.Pdeath != int(unix.SIGKILL) {
		t.Fatal("relay helper readiness", ready.Kind, err)
	}
	start, err := dhcpLeaseProcessStart(helper.cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if pipe.send(dhcpLeaseFrame{Kind: "broker_ready", PID: helper.cmd.Process.Pid, Start: start, Pdeath: ready.Pdeath}) != nil {
		t.Fatal("relay readiness")
	}
	current := func() (LeaseFact, error) {
		if pipe.send(dhcpLeaseFrame{Kind: "current"}) != nil {
			return LeaseFact{}, ErrLeaseUnavailable
		}
		m, err := pipe.receive()
		if err != nil || m.Kind != "fact" || m.Error != "" || m.Fact == nil {
			return LeaseFact{}, ErrLeaseUnavailable
		}
		return *m.Fact, nil
	}
	for {
		m, err := pipe.receiveWithin(4 * time.Minute)
		if err != nil {
			t.Fatal("relay command", err)
		}
		if m.Kind != "refresh" && m.Kind != "verify" && m.Kind != "withdraw" && m.Kind != "close" {
			t.Fatal("relay command denied")
		}
		out, err := helper.exchange(m.Kind, current)
		if err != nil {
			t.Fatal("relay helper channel", err)
		}
		if pipe.send(out) != nil {
			t.Fatal("relay result")
		}
		if m.Kind == "close" {
			helper.wait(t, false)
			return
		}
	}
}

type dhcpLeaseChild struct {
	pipe   dhcpLeasePipe
	cmd    *exec.Cmd
	done   chan error
	output limitedBuffer
}

func startDHCPLeaseChild(t *testing.T, role string, host, target, mount *os.File) *dhcpLeaseChild {
	t.Helper()
	requestR, requestW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	replyR, replyW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestNativeDHCPLeaseRole$", "-test.v", "-test.timeout=5m"}
	if role == "helper" {
		args = append([]string{"--reuid=62006", "--regid=62006", "--clear-groups", "--no-new-privs", "--bounding-set=-all,+net_admin", "--inh-caps=-all,+net_admin", "--ambient-caps=-all,+net_admin", executable}, args...)
		executable = "/usr/bin/setpriv"
	}
	c := &dhcpLeaseChild{pipe: dhcpLeasePipe{replyR, requestW}, done: make(chan error, 1)}
	c.cmd = exec.Command(executable, args...) // #nosec G204 -- Root-owned self or fixed setpriv; closed test roles and arguments.
	c.cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "ANDEIVA_DHCP_LEASE_NATIVE=1", "ANDEIVA_DHCP_LEASE_ROLE=" + role}
	c.cmd.ExtraFiles = []*os.File{host, target, requestR, replyW}
	if role == "owner" {
		c.cmd.ExtraFiles = append(c.cmd.ExtraFiles, mount)
	}
	c.cmd.Stdout, c.cmd.Stderr = &c.output, &c.output
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := c.cmd.Start()
		started <- err
		if err == nil {
			c.done <- c.cmd.Wait()
		}
	}()
	if err := <-started; err != nil {
		t.Fatal("child start", err)
	}
	_ = requestR.Close()
	_ = replyW.Close()
	t.Cleanup(func() { _ = c.cmd.Process.Kill(); _ = c.pipe.read.Close(); _ = c.pipe.write.Close() })
	return c
}

func (c *dhcpLeaseChild) exchange(command string, current func() (LeaseFact, error)) (dhcpLeaseFrame, error) {
	if err := c.pipe.send(dhcpLeaseFrame{Kind: command}); err != nil {
		return dhcpLeaseFrame{}, err
	}
	for {
		m, err := c.pipe.receive()
		if err != nil {
			return m, err
		}
		if m.Kind != "current" {
			if m.Kind != "result" {
				return m, ErrScope
			}
			return m, nil
		}
		if current == nil {
			return m, ErrScope
		}
		fact, err := current()
		reply := dhcpLeaseFrame{Kind: "fact", Fact: &fact}
		if err != nil {
			reply.Fact = nil
			reply.Error = "unavailable"
		}
		if err := c.pipe.send(reply); err != nil {
			return dhcpLeaseFrame{}, err
		}
	}
}

func (c *dhcpLeaseChild) wait(t *testing.T, killed bool) {
	t.Helper()
	select {
	case err := <-c.done:
		if killed {
			if err == nil {
				t.Fatal("killed child exited successfully")
			}
			return
		}
		b := c.output.data
		if err != nil || c.output.exceeded || !bytes.Contains(b, []byte("--- PASS: TestNativeDHCPLeaseRole")) || bytes.Contains(b, []byte("--- SKIP:")) {
			t.Fatalf("role did not execute: %v %.4096s", err, b)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("child did not exit")
	}
}

type dhcpLeaseBroker struct {
	owner    *dhcpLeaseChild
	identity LeaseOwner
	desired  networkplan.Revision
	last     LeaseFact
	grant    dhcpclient.Lease
	forced   bool
}

func (b *dhcpLeaseBroker) revoke() LeaseFact {
	if b.last.Sequence == 0 || !b.last.Revoked {
		b.last = LeaseFact{Owner: b.identity, Sequence: b.last.Sequence + 1, DesiredHash: b.desired.Hash, WAN: b.desired.Config.Interfaces[1].Binding, Revoked: true}
	}
	return b.last
}

func (b *dhcpLeaseBroker) current() (LeaseFact, error) {
	if b.forced {
		return b.revoke(), nil
	}
	m, err := b.owner.exchange("current", nil)
	if err != nil {
		b.forced = true
		return b.revoke(), nil
	}
	if m.Error != "" || m.Lease == nil {
		return b.revoke(), nil
	}
	l := *m.Lease
	if l.Event.PID != int(b.identity.PID) || l.Event.Interface != "wan0" || l.Epoch == 0 || l.Epoch < b.grant.Epoch || l.DeadlineBootNS <= 0 || l.DeadlineBootNS > l.Event.BootNS+int64(l.Event.Seconds)*int64(time.Second) {
		return LeaseFact{}, ErrScope
	}
	if l.Epoch == b.grant.Epoch {
		if !reflect.DeepEqual(l, b.grant) || b.last.Revoked {
			return b.revoke(), nil
		}
		return b.last, nil
	}
	b.grant = l
	b.last = LeaseFact{Owner: b.identity, Sequence: b.last.Sequence + 1, DesiredHash: b.desired.Hash, WAN: b.desired.Config.Interfaces[1].Binding, Address: l.Event.Address, Gateway: l.Event.Gateway, DeadlineBootNS: l.DeadlineBootNS}
	return b.last, nil
}

func nativeDHCPLeaseObserve(t *testing.T) observation {
	t.Helper()
	e := &Executor{lifetime: context.Background(), run: func(ctx context.Context, op operation) ([]byte, error) {
		// This supervisor observer has no mutation entry point.
		if op.kind != "links" && op.kind != "addresses" && op.kind != "routes" {
			return nil, ErrScope
		}
		cmd, err := ownedNamespaceCommand(ctx, op)
		if err != nil {
			return nil, err
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var output limitedBuffer
		cmd.Stdout = &output
		err = cmd.Run()
		if output.exceeded {
			return nil, ErrObservation
		}
		return output.data, err
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := e.observe(ctx)
	if err != nil {
		t.Fatal("physical observer", err)
	}
	return o
}

func nativeDHCPLeaseStopServer(t *testing.T, targetID, hostID uint64) {
	t.Helper()
	pid, err := strconv.Atoi(os.Getenv("ANDEIVA_DHCP_LEASE_SERVER_PID"))
	if err != nil || pid <= 1 {
		t.Fatal("server identity")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal("server pidfd", err)
	}
	defer unix.Close(fd)
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ns, err := namespaceID(int(f.Fd()))
	if err != nil || ns == targetID || ns == hostID {
		t.Fatal("server namespace scope")
	}
	pin, err := os.Open("/run/netns/dhcp-server")
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	expected, err := namespaceID(int(pin.Fd()))
	if err != nil || ns != expected {
		t.Fatal("server namespace mismatch")
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		t.Fatal("stop isolated server", err)
	}
	if err := dhcpLeaseWaitPidfd(fd, 5*time.Second); err != nil {
		t.Fatal("server death not observed", err)
	}
	t.Log("server death: pidfd readable")
}

func dhcpLeaseWaitPidfd(fd int, timeout time.Duration) error {
	if fd < 0 || fd > 65535 || timeout <= 0 {
		return ErrScope
	}
	until := time.Now().Add(timeout)
	for time.Now().Before(until) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			return nil
		}
		if fds[0].Revents != 0 {
			return ErrScope
		}
	}
	return ErrLeaseUnavailable
}

// A late ACK can replace the grant after server termination was requested.
// Expiry must be measured against the most recent valid fact, never the first.
func dhcpLeaseCheckExpiry(previous, current LeaseFact, now int64) (LeaseFact, bool, error) {
	if previous.Revoked || previous.Sequence == 0 || previous.DeadlineBootNS <= 0 || current.Owner != previous.Owner || current.DesiredHash != previous.DesiredHash || current.WAN != previous.WAN || current.Sequence < previous.Sequence || now <= 0 {
		return previous, false, ErrScope
	}
	if current.Revoked {
		if current.Sequence <= previous.Sequence || current.Address != "" || current.Gateway != "" || current.DeadlineBootNS != 0 || now < previous.DeadlineBootNS {
			return previous, false, ErrScope
		}
		return previous, true, nil
	}
	if current.DeadlineBootNS <= 0 || current.Sequence == previous.Sequence && current != previous {
		return previous, false, ErrScope
	}
	return current, false, nil
}

func TestNativeDHCPLeaseIntegration(t *testing.T) {
	if os.Getenv("ANDEIVA_DHCP_LEASE_NATIVE") != "1" || os.Getenv("ANDEIVA_DHCP_LEASE_ROLE") != "" {
		t.Skip("requires authorized native integration harness")
	}
	mode := os.Getenv("ANDEIVA_DHCP_LEASE_MODE")
	if os.Getenv("CI") != "" || os.Getuid() != 0 || (mode != "lifecycle" && mode != "owner-death" && mode != "manager-death" && mode != "broker-death") {
		t.Fatal("integration scope")
	}
	if mode == "broker-death" {
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			t.Fatal("subreaper", err)
		}
		defer unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)
	}
	for fd := 3; fd <= 5; fd++ {
		unix.CloseOnExec(fd)
	}
	host, mount, target := os.NewFile(3, "host-network"), os.NewFile(4, "host-mount"), os.NewFile(5, "target-network")
	defer host.Close()
	defer mount.Close()
	defer target.Close()
	hostID, err := namespaceID(int(host.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	targetID, err := namespaceID(int(target.Fd()))
	if err != nil || hostID == targetID {
		t.Fatal("host target isolation")
	}
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	selfID, err := namespaceID(int(self.Fd()))
	_ = self.Close()
	if err != nil || selfID != targetID {
		t.Fatal("target namespace mismatch")
	}
	bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	parentStart, err := dhcpLeaseProcessStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	desired := fixturePlan()
	desired.Config.Interfaces[1].IPv4 = networkplan.IPv4{Mode: "dhcp"}
	desired, err = networkplan.Canonical(desired.Config)
	if err != nil {
		t.Fatal(err)
	}
	baseline := nativeDHCPLeaseObserve(t)
	assertBaseline := func(stage string) {
		t.Helper()
		if !reflect.DeepEqual(nativeDHCPLeaseObserve(t), baseline) {
			t.Fatal(stage, "LAN/empty-WAN baseline differs")
		}
		t.Log(stage + ": exact LAN/empty-WAN physical baseline")
	}
	var owner, helper *dhcpLeaseChild
	var relayedHelperPID int
	var relayedHelperStart uint64
	var broker *dhcpLeaseBroker
	var identity OwnedNamespaceIdentity
	startOwner := func() {
		t.Helper()
		owner = startDHCPLeaseChild(t, "owner", host, target, mount)
		b := dhcpLeaseBoot{PID: owner.cmd.Process.Pid, Parent: os.Getpid(), ParentStart: parentStart}
		if owner.pipe.send(dhcpLeaseFrame{Kind: "init", Boot: &b}) != nil {
			t.Fatal("owner init")
		}
		m, err := owner.pipe.receive()
		if err != nil {
			_ = owner.cmd.Process.Kill()
			owner.wait(t, false)
			t.Fatal("owner readiness channel", err)
		}
		if m.Kind != "owner_ready" || m.PID <= 1 || m.Start == 0 {
			t.Fatal("owner readiness", m.Kind, err)
		}
		actual, err := dhcpLeaseProcessStart(m.PID)
		if err != nil || actual != m.Start {
			t.Fatal("engine start identity")
		}
		pid, err := strconv.ParseUint(strconv.Itoa(m.PID), 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		identity = OwnedNamespaceIdentity{UID: leaseNativeUID, GID: leaseNativeUID, Host: hostID, Namespace: targetID, BootID: strings.TrimSpace(string(bootID)), RunID: nativeLeaseNonce(t)}
		broker = &dhcpLeaseBroker{owner: owner, desired: desired, identity: LeaseOwner{Namespace: targetID, BootID: identity.BootID, RunID: identity.RunID, Incarnation: nativeLeaseNonce(t), PID: uint32(pid), StartTicks: m.Start}}
		t.Logf("DHCP owner started: process=%d engine=%d incarnation=%s", owner.cmd.Process.Pid, m.PID, broker.identity.Incarnation)
	}
	startHelper := func(denied bool) {
		t.Helper()
		role := "helper"
		if mode == "broker-death" && !denied {
			role = "broker"
		}
		helper = startDHCPLeaseChild(t, role, host, target, nil)
		b := dhcpLeaseBoot{PID: helper.cmd.Process.Pid, Parent: os.Getpid(), ParentStart: parentStart, Identity: identity, Owner: broker.identity, Desired: desired}
		if helper.pipe.send(dhcpLeaseFrame{Kind: "init", Boot: &b}) != nil {
			t.Fatal("helper init")
		}
		m, err := helper.pipe.receive()
		if err != nil {
			_ = helper.cmd.Process.Kill()
			helper.wait(t, false)
			t.Fatal("helper readiness", err)
		}
		if denied {
			if m.Kind != "denied" || m.Error != ErrUnsupported.Error() {
				t.Fatal("occupied-WAN reopen accepted", m.Kind, m.Error)
			}
			helper.wait(t, false)
			return
		}
		if role == "broker" {
			if m.Kind != "broker_ready" || m.PID <= 1 || m.Start == 0 || m.Pdeath != int(unix.SIGKILL) {
				t.Fatal("broker helper readiness", m.Kind, m.Error)
			}
			relayedHelperPID, relayedHelperStart = m.PID, m.Start
			return
		}
		if m.Kind != "helper_ready" || m.Pdeath != int(unix.SIGKILL) {
			t.Fatal("helper constructor", m.Kind, m.Error)
		}
	}
	callHelper := func(command string) dhcpLeaseFrame {
		t.Helper()
		m, err := helper.exchange(command, broker.current)
		if err != nil {
			t.Fatal("helper channel", command, err)
		}
		return m
	}
	callOwner := func(command string) {
		t.Helper()
		m, err := owner.exchange(command, nil)
		if err != nil || m.Error != "" {
			t.Fatal("owner operation", command, m.Error, err)
		}
	}
	awaitGrant := func(after uint64, reason string) {
		t.Helper()
		until := time.Now().Add(35 * time.Second)
		for time.Now().Before(until) {
			f, err := broker.current()
			if err != nil {
				t.Fatal("lease scope", err)
			}
			if !f.Revoked && broker.grant.Epoch > after {
				if reason != "" && broker.grant.Event.Reason != reason {
					t.Fatal("expected real ACK", reason, broker.grant.Event.Reason)
				}
				t.Logf("DHCP grant: epoch=%d reason=%s deadline=%d", broker.grant.Epoch, broker.grant.Event.Reason, f.DeadlineBootNS)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("real DHCP grant timed out")
	}
	apply := func(stage string) dhcpLeaseFrame {
		t.Helper()
		m := callHelper("refresh")
		if m.Error != "" || m.Outcome != LeaseApplied {
			t.Fatal(stage, m.Outcome, m.Error)
		}
		if v := callHelper("verify"); v.Error != "" {
			t.Fatal(stage, "physical verification", v.Error)
		}
		t.Log(stage + ": real lease realized by LeaseExecutor")
		return m
	}
	revoke := func(stage string) {
		t.Helper()
		broker.forced = true
		m := callHelper("refresh")
		if m.Outcome != LeaseWANWithdrawn || m.Error != ErrLeaseUnavailable.Error() {
			t.Fatal(stage, m.Outcome, m.Error)
		}
		assertBaseline(stage)
	}
	closePair := func() {
		t.Helper()
		if m := callHelper("close"); m.Error != "" {
			t.Fatal("helper close", m.Error)
		}
		helper.wait(t, false)
		callOwner("close")
		owner.wait(t, false)
	}
	startOwner()
	startHelper(false)
	assertBaseline("constructor read-only")
	awaitGrant(0, "")
	initial := apply("BOUND")
	if mode == "broker-death" {
		applied := nativeDHCPLeaseObserve(t)
		fd, err := unix.PidfdOpen(relayedHelperPID, 0)
		if err != nil {
			t.Fatal("helper pidfd", err)
		}
		defer unix.Close(fd)
		start, err := dhcpLeaseProcessStart(relayedHelperPID)
		if err != nil || start != relayedHelperStart {
			t.Fatal("relayed helper start identity")
		}
		if fd > 65535 {
			t.Fatal("helper pidfd outside bounded profile")
		}
		alive := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if n, err := unix.Poll(alive, 0); err != nil || n != 0 {
			t.Fatal("helper was not alive before broker kill", err)
		}
		if err := helper.cmd.Process.Kill(); err != nil {
			t.Fatal("kill broker", err)
		}
		helper.wait(t, true)
		if err := dhcpLeaseWaitPidfd(fd, 5*time.Second); err != nil {
			t.Fatal("helper survived broker death", err)
		}
		var status unix.WaitStatus
		pid, err := unix.Wait4(relayedHelperPID, &status, unix.WNOHANG, nil)
		if err != nil || pid != relayedHelperPID || !status.Signaled() || status.Signal() != unix.SIGKILL {
			t.Fatal("broker death did not SIGKILL helper", pid, status, err)
		}
		if !reflect.DeepEqual(nativeDHCPLeaseObserve(t), applied) {
			t.Fatal("broker death changed retained L3")
		}
		identity.RunID = nativeLeaseNonce(t)
		broker.identity.RunID = identity.RunID
		startHelper(true)
		callOwner("close")
		owner.wait(t, false)
		if !reflect.DeepEqual(nativeDHCPLeaseObserve(t), applied) {
			t.Fatal("broker-death teardown changed retained L3")
		}
		t.Log("broker death: helper SIGKILL verified by pidfd/Wait4, WAN retained, occupied-WAN reopening denied; no restoration claim")
		return
	}
	if mode == "manager-death" {
		applied := nativeDHCPLeaseObserve(t)
		if err := helper.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		helper.wait(t, true)
		if !reflect.DeepEqual(nativeDHCPLeaseObserve(t), applied) {
			t.Fatal("manager death changed physical state")
		}
		identity.RunID = nativeLeaseNonce(t)
		broker.identity.RunID = identity.RunID
		startHelper(true)
		if !reflect.DeepEqual(nativeDHCPLeaseObserve(t), applied) {
			t.Fatal("reopen refusal changed physical state")
		}
		callOwner("close")
		owner.wait(t, false)
		t.Log("manager death: WAN retained, occupied-WAN reopen denied; no restoration claim; namespace teardown required")
		if !reflect.DeepEqual(nativeDHCPLeaseObserve(t), applied) {
			t.Fatal("DHCP stop changed retained WAN after manager death")
		}
		return
	}
	if mode == "owner-death" {
		if err := owner.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		owner.wait(t, true)
		m := callHelper("refresh")
		if m.Outcome != LeaseWANWithdrawn || m.Error != ErrLeaseUnavailable.Error() {
			t.Fatal("owner death withdrawal", m.Outcome, m.Error)
		}
		assertBaseline("owner channel death")
		if m := callHelper("close"); m.Error != "" {
			t.Fatal(m.Error)
		}
		helper.wait(t, false)
		return
	}
	oldEpoch := broker.grant.Epoch
	callOwner("renew")
	awaitGrant(oldEpoch, "RENEW")
	renewed := callHelper("refresh")
	if renewed.Error != "" || renewed.Outcome != LeaseEvidenceRefreshed || renewed.Mutations != initial.Mutations {
		t.Fatal("renewal L3 effects", renewed)
	}
	if m := callHelper("verify"); m.Error != "" {
		t.Fatal("renewal verification", m.Error)
	}
	t.Log("RENEW ACK: exact source deadline retained, zero new L3 mutations")
	oldEpoch = broker.grant.Epoch
	revoke("pre-rebind authority withdrawal")
	callOwner("rebind")
	broker.forced = false
	awaitGrant(oldEpoch, "")
	apply("rebind grant")
	oldOwner, oldIncarnation := broker.identity.PID, broker.identity.Incarnation
	revoke("pre-restart withdrawal")
	closePair()
	startOwner()
	startHelper(false)
	if broker.identity.PID == oldOwner || broker.identity.Incarnation == oldIncarnation {
		t.Fatal("owner incarnation reused")
	}
	awaitGrant(0, "")
	apply("fresh owner/helper restart")
	lastLive := broker.last
	nativeDHCPLeaseStopServer(t, targetID, hostID)
	until := time.Now().Add(130 * time.Second)
	for {
		f, err := broker.current()
		if err != nil {
			t.Fatal(err)
		}
		var expired bool
		lastLive, expired, err = dhcpLeaseCheckExpiry(lastLive, f, nativeLeaseNow(t))
		if err != nil {
			t.Fatal("authority unavailable before latest grant deadline; not expiry evidence", err)
		}
		if expired {
			break
		}
		if time.Now().After(until) {
			t.Fatal("server death did not expire lease")
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("expiry witnessed against latest valid sequence=%d deadline=%d", lastLive.Sequence, lastLive.DeadlineBootNS)
	m := callHelper("refresh")
	if m.Outcome != LeaseWANWithdrawn || m.Error != ErrLeaseUnavailable.Error() {
		t.Fatal("expiry withdrawal", m)
	}
	assertBaseline("server death/lease expiry")
	closePair()
	startOwner()
	startHelper(false)
	until = time.Now().Add(12 * time.Second)
	for time.Now().Before(until) {
		f, err := broker.current()
		if err != nil || !f.Revoked {
			t.Fatal("offline restart revived lease", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	m = callHelper("refresh")
	if m.Outcome != LeaseWANWithdrawn || m.Error != ErrLeaseUnavailable.Error() {
		t.Fatal("offline denial", m)
	}
	assertBaseline("offline cached lease rejected")
	closePair()
}

func TestDHCPLeasePrivateFramesBounded(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{"kind":"current","kind":"close"}`), []byte(`{"Kind":"current"}`), []byte(`{"kind":"current","unknown":1}`), bytes.Repeat([]byte("x"), dhcpLeaseFrameLimit+1)} {
		if _, err := decodeDHCPLeaseFrame(b); err == nil {
			t.Fatal("invalid private frame accepted")
		}
	}
	if _, err := decodeDHCPLeaseFrame([]byte(`{"kind":"current"}`)); err != nil {
		t.Fatal(err)
	}
	for _, m := range []dhcpLeaseFrame{
		{Kind: "init", Boot: &dhcpLeaseBoot{PID: 123, Parent: 45, ParentStart: 678, Identity: recoveryIdentityFixture(), Owner: LeaseOwner{PID: 99}, Desired: fixturePlan()}},
		{Kind: "fact", Fact: &LeaseFact{Owner: LeaseOwner{PID: 99}, Sequence: 1, Revoked: true}},
	} {
		encoded, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeDHCPLeaseFrame(encoded)
		if err != nil || !reflect.DeepEqual(decoded, m) {
			t.Fatal("nested frame roundtrip", err)
		}
	}
}

func TestDHCPLeaseExpiryTracksLatestGrant(t *testing.T) {
	a := LeaseFact{Sequence: 1, DeadlineBootNS: 100, Address: "198.19.0.10/24", Gateway: "198.19.0.2"}
	b := a
	b.Sequence = 2
	b.DeadlineBootNS = 200
	last, expired, err := dhcpLeaseCheckExpiry(a, b, 90)
	if err != nil || expired || last != b {
		t.Fatal("late grant not retained", last, expired, err)
	}
	unavailable := b
	unavailable.Sequence = 3
	unavailable.Revoked = true
	unavailable.Address = ""
	unavailable.Gateway = ""
	unavailable.DeadlineBootNS = 0
	if _, expired, err := dhcpLeaseCheckExpiry(last, unavailable, 150); err == nil || expired {
		t.Fatal("unavailable between A and B deadlines credited as expiry")
	}
	if latest, expired, err := dhcpLeaseCheckExpiry(last, unavailable, 200); err != nil || !expired || latest != b {
		t.Fatal("latest deadline expiry rejected", expired, err)
	}
	changed := b
	changed.DeadlineBootNS++
	if _, _, err := dhcpLeaseCheckExpiry(b, changed, 100); err == nil {
		t.Fatal("same sequence changed deadline")
	}
}

func TestDHCPLeaseParentDeathRejectsUnknownParent(t *testing.T) {
	before, err := dhcpLeaseParentDeathSignal()
	if err != nil {
		t.Fatal(err)
	}
	if err := dhcpLeaseArmParentDeath(dhcpLeaseBoot{Parent: 0, ParentStart: 1}); err == nil {
		t.Fatal("unverified parent accepted")
	}
	after, err := dhcpLeaseParentDeathSignal()
	if err != nil || after != before {
		t.Fatal("rejected parent changed signal", after, err)
	}
}

func TestDHCPLeaseBrokerDoesNotExtendOrReplayGrants(t *testing.T) {
	rqR, rqW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rpR, rpW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer rqR.Close()
	defer rqW.Close()
	defer rpR.Close()
	defer rpW.Close()
	peer := dhcpLeasePipe{read: rqR, write: rpW}
	responses := make(chan dhcpLeaseFrame)
	done := make(chan error, 1)
	go func() {
		for response := range responses {
			m, err := peer.receive()
			if err != nil {
				done <- err
				return
			}
			if m.Kind != "current" {
				done <- ErrScope
				return
			}
			if err := peer.send(response); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	b := &dhcpLeaseBroker{owner: &dhcpLeaseChild{pipe: dhcpLeasePipe{read: rpR, write: rqW}}, identity: LeaseOwner{PID: 123}, desired: fixturePlan()}
	lease := dhcpclient.Lease{Epoch: 1, DeadlineBootNS: int64(100 * time.Second), Event: dhcpclient.Event{PID: 123, Interface: "wan0", BootNS: int64(time.Second), Seconds: 120, Address: "198.19.0.10/24", Gateway: "198.19.0.2"}}
	query := func(m dhcpLeaseFrame) (LeaseFact, error) {
		if m.Lease != nil {
			copy := *m.Lease
			m.Lease = &copy
		}
		responses <- m
		return b.current()
	}
	first, err := query(dhcpLeaseFrame{Kind: "result", Lease: &lease})
	if err != nil || first.DeadlineBootNS != lease.DeadlineBootNS || first.Sequence != 1 {
		t.Fatal(first, err)
	}
	repeated, err := query(dhcpLeaseFrame{Kind: "result", Lease: &lease})
	if err != nil || repeated != first {
		t.Fatal("reading extended evidence", repeated, err)
	}
	extended := lease
	extended.DeadlineBootNS++
	if f, err := query(dhcpLeaseFrame{Kind: "result", Lease: &extended}); err != nil || !f.Revoked || f.DeadlineBootNS != 0 {
		t.Fatal("same epoch changed deadline accepted", f, err)
	}
	revoked, err := query(dhcpLeaseFrame{Kind: "result", Error: "unavailable"})
	if err != nil || !revoked.Revoked || revoked.Sequence != 2 {
		t.Fatal(revoked, err)
	}
	replayed, err := query(dhcpLeaseFrame{Kind: "result", Lease: &lease})
	if err != nil || replayed != revoked {
		t.Fatal("old grant revived revoked authority", replayed, err)
	}
	lease.Epoch++
	lease.DeadlineBootNS = int64(90 * time.Second)
	next, err := query(dhcpLeaseFrame{Kind: "result", Lease: &lease})
	if err != nil || next.Revoked || next.Sequence != 3 || next.DeadlineBootNS != lease.DeadlineBootNS {
		t.Fatal("new grant not exact", next, err)
	}
	close(responses)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
