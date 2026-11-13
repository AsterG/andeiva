//go:build linux

package networkexecutor

import (
	"context"
	"io"
	"os"
	"runtime"

	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

// NewLeaseInOwnedNamespace performs only readback and ownership checks. The
// reader group has the same restrictions as the existing owned constructor.
func NewLeaseInOwnedNamespace(ctx context.Context, target, host *os.File, identity OwnedNamespaceIdentity, readerGID uint32, options LeaseOptions) (*LeaseExecutor, error) {
	// Detach caller-owned slices before retaining the forwarding guard.
	desired, err := networkplan.Canonical(options.Desired.Config)
	if err != nil || desired.Hash != options.Desired.Hash {
		return nil, ErrScope
	}
	options.Desired = desired
	var base *Executor
	if readerGID == 0 {
		base, err = NewInOwnedNamespace(ctx, target, host, identity)
	} else {
		base, err = NewInOwnedNamespaceWithReader(ctx, target, host, identity, readerGID)
	}
	if err != nil {
		return nil, err
	}
	run := base.run
	base.run = func(ctx context.Context, op operation) ([]byte, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := leaseForwardingClosed(options); err != nil {
			return nil, err
		}
		return run(ctx, op)
	}
	now := func() (int64, error) {
		var t unix.Timespec
		err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t)
		return t.Nano(), err
	}
	l, err := newLeaseExecutor(ctx, base, options, now)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	return l, nil
}

func leaseForwardingClosed(options LeaseOptions) error {
	names := []string{"all", "default"}
	if len(options.Desired.Config.Interfaces) != 2 {
		return ErrScope
	}
	for _, i := range options.Desired.Config.Interfaces {
		if !linkName.MatchString(i.Binding.Name) {
			return ErrScope
		}
		names = append(names, i.Binding.Name)
	}
	paths := []string{"/proc/sys/net/ipv4/ip_forward"}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, name := range names {
			paths = append(paths, "/proc/sys/net/"+family+"/conf/"+name+"/forwarding")
		}
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return ErrScope
		}
		b, rerr := io.ReadAll(io.LimitReader(f, 4))
		cerr := f.Close()
		if rerr != nil || cerr != nil || string(b) != "0\n" {
			return ErrScope
		}
	}
	return nil
}
