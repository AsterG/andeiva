package networkexecutor

import (
	"context"
	"os"
	"runtime"

	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

// NewLeaseFromSelectedInOwnedNamespace only reconstructs authenticated selected
// ownership, with closed forwarding. The trusted caller must resolve the exact
// snapshot from current selected work and R2 reserves first; decoded request
// bodies or matching hashes are insufficient. It never applies a saved token.
func NewLeaseFromSelectedInOwnedNamespace(ctx context.Context, target, host *os.File, id OwnedNamespaceIdentity, readerGID uint32, options LeaseOptions, snapshot LeaseSelectedSnapshotV3) (*LeaseExecutor, LeaseSelectedStateV3, error) {
	s, err := CanonicalLeaseSelectedSnapshotV3(snapshot)
	if err != nil || s.Identity != id || options.Desired.Hash != s.Desired.Hash {
		return nil, "", ErrScope
	}
	desired, err := networkplan.Canonical(options.Desired.Config)
	if err != nil || desired.Hash != s.Desired.Hash {
		return nil, "", ErrScope
	}
	options.Desired = desired
	var base *Executor
	if readerGID == 0 {
		base, err = NewInOwnedNamespace(ctx, target, host, id)
	} else {
		base, err = NewInOwnedNamespaceWithReader(ctx, target, host, id, readerGID)
	}
	if err != nil {
		return nil, "", err
	}
	run := base.run
	base.run = func(call context.Context, op operation) ([]byte, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := leaseForwardingClosed(options); err != nil {
			return nil, err
		}
		return run(call, op)
	}
	now := func() (int64, error) {
		var ts unix.Timespec
		err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
		return ts.Nano(), err
	}
	l, state, err := recoverLeaseSelectedV3(ctx, base, options, s, now)
	if err != nil {
		_ = base.Close()
		return nil, "", err
	}
	return l, state, nil
}
