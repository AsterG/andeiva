package previewruntime

import (
	"context"
	"errors"
	"os"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

// Resources belong to root's verified launch. Current must read the inherited,
// single-writer owner channel and check fixed PID/start/incarnation, sequence
// and original BOOTTIME deadline. Nothing here is a request-decoded option.
type RoutedDHCPRuntimeOptionsV3 struct {
	LAN          *networkexecutor.LANBootstrapV3
	Target, Host *os.File
	Desired      networkplan.Revision
	Owner        networkexecutor.LeaseOwner
	Current      func(context.Context) (RoutedDHCPOwnerFactV3, error)
}

func assembleRoutedDHCPRuntimeV3(ctx context.Context, o RoutedDHCPRuntimeOptionsV3, id networkexecutor.OwnedNamespaceIdentity, readerGID uint32, reader *configpoc.RoutedSelectionReaderV2, authority configpoc.RoutedAuthorityV1, integrity *routedIntegrityGateV3) (*RoutedDHCPRuntimeV3, func() error, error) {
	if ctx == nil || ctx.Err() != nil || o.LAN == nil || o.Current == nil || reader == nil || authority == nil || integrity == nil || authority.Identity() != id || o.Owner.Namespace != id.Namespace || o.Owner.BootID != id.BootID || o.Owner.RunID != id.RunID || o.Owner.PID <= 1 || o.Owner.StartTicks == 0 || !ValidRun(o.Owner.Incarnation) {
		return nil, nil, ErrIdentity
	}
	desired, err := networkexecutor.CanonicalLANBootstrapPlanV3(o.Desired)
	if err != nil {
		return nil, nil, err
	}
	f, err := networkexecutor.NewLeaseForwardingInOwnedNamespaceV3(o.Target, o.Host, id, readerGID, desired)
	if err != nil {
		return nil, nil, err
	}
	r := &RoutedDHCPRuntimeV3{identity: id, owner: o.Owner, current: o.Current, reader: routedDHCPSelectedReaderV3{reader}, forward: f}
	r.ready = func() error {
		integrity.mu.Lock()
		defer integrity.mu.Unlock()
		if integrity.blockedLocked() || integrity.phase != routedIntegrityReadyV3 {
			return configpoc.ErrRecovery
		}
		return nil
	}
	r.fenced = func() bool { integrity.mu.Lock(); defer integrity.mu.Unlock(); return integrity.blockedLocked() }
	r.policy = func(call context.Context, p routedDHCPWorkV3) error {
		if r.ready() != nil {
			return configpoc.ErrRecovery
		}
		receipt, hash, e := authority.Observe(call)
		if e != nil || !integrityPhysicalIdleV3(receipt, hash) || hash != p.Running() {
			return configpoc.ErrRecovery
		}
		return nil
	}
	current := func(call context.Context) (networkexecutor.LeaseFact, error) {
		x, e := o.Current(call)
		if e != nil || x.Epoch == 0 || x.Fact.Owner != o.Owner {
			return networkexecutor.LeaseFact{}, configpoc.ErrRecovery
		}
		return x.Fact, nil
	}
	opts := networkexecutor.LeaseOptions{Desired: desired, Owner: o.Owner, Current: current}
	r.openLease = func(call context.Context) (routedDHCPLeaseV3, error) { return o.LAN.OpenLease(call, opts) }
	r.recoverLease = func(call context.Context, s networkexecutor.LeaseSelectedSnapshotV3) (routedDHCPLeaseV3, error) {
		return o.LAN.RecoverSelectedLeaseV3(call, opts, s)
	}
	r.releaseLease = o.LAN.ReleaseLease
	r.buildGate = func(call context.Context, a networkexecutor.LeaseGateAuthority) (routedDHCPGateV3, error) {
		if call.Err() != nil {
			return nil, call.Err()
		}
		return networkexecutor.NewLeaseGateInOwnedNamespace(ctx, o.Target, o.Host, id, readerGID, networkexecutor.LeaseGateOptions{Desired: desired, Owner: o.Owner, Authority: a})
	}
	closeResources := func() error {
		// Cancellation stops watchdog only. Kernel expiry remains independent;
		// resources are drained by the owning supervisor, never a client request.
		r.mu.Lock()
		defer r.mu.Unlock()
		var gateErr error
		if g, ok := r.gate.(*networkexecutor.LeaseGate); ok {
			gateErr = g.Dispose()
		}
		return errors.Join(gateErr, f.Close())
	}
	return r, closeResources, nil
}
