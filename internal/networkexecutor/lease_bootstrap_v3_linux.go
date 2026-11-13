package networkexecutor

import (
	"context"
	"os"
	"runtime"

	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

// NewLANBootstrapInOwnedNamespaceV3 retains the same non-host, identity, caps
// and reader-group checks as the static executor. It configures no interface.
func NewLANBootstrapInOwnedNamespaceV3(ctx context.Context, target, host *os.File, id OwnedNamespaceIdentity, readerGID uint32, desired networkplan.Revision) (*LANBootstrapV3, error) {
	r, err := CanonicalLANBootstrapPlanV3(desired)
	if err != nil {
		return nil, err
	}
	var base *Executor
	if readerGID == 0 {
		base, err = NewInOwnedNamespace(ctx, target, host, id)
	} else {
		base, err = NewInOwnedNamespaceWithReader(ctx, target, host, id, readerGID)
	}
	if err != nil {
		return nil, err
	}
	closed := func() error { return leaseForwardingClosed(LeaseOptions{Desired: r}) }
	run := base.run
	base.run = func(ctx context.Context, op operation) ([]byte, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		switch op.kind {
		case "links", "addresses", "routes", "rules":
		default:
			if err := closed(); err != nil {
				return nil, err
			}
		}
		return run(ctx, op)
	}
	now := func() (int64, error) {
		var t unix.Timespec
		err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t)
		return t.Nano(), err
	}
	b, err := newLANBootstrapV3(base, r, now, closed)
	if err != nil {
		_ = base.Close()
		return nil, err
	}
	return b, nil
}
