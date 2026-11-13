package networkexecutor

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

var leaseGateOwners = struct {
	sync.Mutex
	ids map[uint64]bool
}{ids: map[uint64]bool{}}

// NewLeaseGateInOwnedNamespace only reads and pins trusted supervisor resources.
// It coexists with LeaseExecutor; neither constructor authorizes a host target.
// The caller must own the namespace exclusively and provide the continuous-awake
// experimental profile. Suspend/VM pause/snapshot recovery is not supported.
func NewLeaseGateInOwnedNamespace(lifetime context.Context, target, host *os.File, id OwnedNamespaceIdentity, readerGID uint32, options LeaseGateOptions) (*LeaseGate, error) {
	if lifetime == nil || lifetime.Err() != nil || target == nil || host == nil || !validOwnedIdentity(id) {
		return nil, ErrScope
	}
	desired, err := networkplan.Canonical(options.Desired.Config)
	if err != nil || desired.Hash != options.Desired.Hash {
		return nil, ErrScope
	}
	options.Desired = desired
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pin, _, err := pinNamespace(target)
	if err != nil {
		return nil, err
	}
	hostPin, _, err := pinNamespace(host)
	if err != nil {
		_ = pin.Close()
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = pin.Close()
			_ = hostPin.Close()
		}
	}()
	if verifyOwnedNamespaceWithReader(pin, hostPin, id, readerGID) != nil || !trustedExecutable("/usr/sbin/nft") {
		return nil, ErrScope
	}
	type linkIdentity struct {
		name, mac string
		index     int
	}
	var links []linkIdentity
	for _, i := range options.Desired.Config.Interfaces {
		if !linkName.MatchString(i.Binding.Name) {
			return nil, ErrScope
		}
		actual, err := net.InterfaceByName(i.Binding.Name)
		if err != nil || actual.Index <= 0 || actual.HardwareAddr.String() != i.Binding.HardwareAddress {
			return nil, ErrScope
		}
		links = append(links, linkIdentity{i.Binding.Name, i.Binding.HardwareAddress, actual.Index})
	}
	guard := func() error {
		if verifyOwnedNamespaceWithReader(pin, hostPin, id, readerGID) != nil || !trustedExecutable("/usr/sbin/nft") {
			return ErrScope
		}
		for _, want := range links {
			actual, err := net.InterfaceByName(want.name)
			if err != nil || actual.Index != want.index || actual.HardwareAddr.String() != want.mac {
				return ErrScope
			}
		}
		return nil
	}
	closed := func() error {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if guard() != nil {
			return ErrScope
		}
		return leaseForwardingClosed(LeaseOptions{Desired: options.Desired})
	}
	kernel := &leaseGateLinux{lifetime: lifetime, guard: guard}
	now := func() (int64, error) {
		var ts unix.Timespec
		err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
		return ts.Nano(), err
	}
	g, err := newLeaseGate(lifetime, id, options, kernel, now, closed)
	if err != nil {
		return nil, err
	}
	leaseGateOwners.Lock()
	if leaseGateOwners.ids[id.Namespace] {
		leaseGateOwners.Unlock()
		return nil, ErrBusy
	}
	leaseGateOwners.ids[id.Namespace] = true
	leaseGateOwners.Unlock()
	g.release = func() error {
		err := errors.Join(pin.Close(), hostPin.Close())
		leaseGateOwners.Lock()
		delete(leaseGateOwners.ids, id.Namespace)
		leaseGateOwners.Unlock()
		return err
	}
	ok = true
	return g, nil
}

type leaseGateLinux struct {
	lifetime context.Context
	guard    func() error
}

type leaseGateOperation uint8

const (
	leaseGateCheck leaseGateOperation = iota + 1
	leaseGateApply
	leaseGateObserve
)

func leaseGateCommand(ctx context.Context, op leaseGateOperation) (*exec.Cmd, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrCommand
	}
	var cmd *exec.Cmd
	switch op {
	case leaseGateCheck:
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "--check", "-j", "-f", "-")
	case leaseGateApply:
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-f", "-")
	case leaseGateObserve:
		cmd = exec.CommandContext(ctx, "/usr/sbin/nft", "-j", "-n", "-y", "list", "table", "inet", leaseGateTable)
	default:
		return nil, ErrCommand
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.WaitDelay = 200 * time.Millisecond
	return cmd, nil
}

func (k *leaseGateLinux) execute(parent context.Context, op leaseGateOperation, input []byte) ([]byte, error) {
	if parent == nil || parent.Err() != nil || k.lifetime.Err() != nil || len(input) > leaseGateMaxJSON || (op == leaseGateObserve && len(input) != 0) || (op != leaseGateObserve && len(input) == 0) {
		return nil, ErrCommand
	}
	// Linux parent-death signals bind to the creator thread. Keep it alive through
	// Wait as well as namespace validation; do not only pin around cmd.Start.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if k.guard() != nil {
		return nil, ErrScope
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	stop := context.AfterFunc(k.lifetime, cancel)
	defer stop()
	cmd, err := leaseGateCommand(ctx, op)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = bytes.NewReader(input)
	stdout, stderr := &limitedBuffer{}, &limitedBuffer{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if cmd.Run() != nil || stdout.exceeded || stderr.exceeded || len(stdout.data) > leaseGateMaxJSON || k.guard() != nil || ctx.Err() != nil {
		return nil, ErrCommand
	}
	return stdout.data, nil
}

func (k *leaseGateLinux) Check(ctx context.Context, b []byte) error {
	_, err := k.execute(ctx, leaseGateCheck, b)
	return err
}
func (k *leaseGateLinux) Apply(ctx context.Context, b []byte) error {
	_, err := k.execute(ctx, leaseGateApply, b)
	return err
}
func (k *leaseGateLinux) Observe(ctx context.Context) ([]byte, error) {
	return k.execute(ctx, leaseGateObserve, nil)
}
