package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedactivation"
)

// Root assembly authenticates a single owner stream. No field below is accepted
// from HTTP or the API/helper request channel. A new owner needs a new assembly.
type RoutedDHCPOwnerFactV3 struct {
	Epoch        uint64
	Fact         networkexecutor.LeaseFact
	hookBootNS   int64 // Authenticated V4 event metadata; never stored as a new lease bound.
	leaseSeconds uint32
}

type routedDHCPLeaseV3 interface {
	PrepareSelectedSnapshotV3(context.Context) (networkexecutor.LeaseSelectedSnapshotV3, error)
	Refresh(context.Context) (networkexecutor.LeaseOutcome, error)
	VerifySelectedStateV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedStateV3) error
	WithdrawSelectedV3(context.Context) (networkexecutor.LeaseOutcome, error)
}
type routedDHCPGateV3 interface {
	Initialize(context.Context) error
	RecoverClosedSelectedV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3) error
	RecoverWithdrawnSelectedV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3) error
	VerifyClosedSelectedV3(context.Context) error
	DisposeWithdrawnSelectedV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3) error
	Close(context.Context) error
	Stage(context.Context) error
	Open(context.Context) error
	Verify(context.Context) error
	VerifyRetainedV4(context.Context, networkexecutor.LeaseGateGrant) error
}
type routedDHCPForwardingV3 interface {
	Disable(context.Context) error
	VerifyClosed(context.Context) error
	VerifyOpen(context.Context) error
	Enable(context.Context, func(context.Context) error) error
}
type routedDHCPReaderV3 interface {
	Resolve(context.Context, string) (routedDHCPWorkV3, error)
	VerifyDHCPReleasedV3(context.Context) error
	LastWithdrawnDHCPV3(context.Context) (*networkexecutor.LeaseSelectedSnapshotV3, error)
}
type routedDHCPWorkV3 interface {
	Reference() configpoc.SelectionReferenceV2
	Snapshot() networkexecutor.LeaseSelectedSnapshotV3
	Epoch() uint64
	Phase() string
	Running() string
}
type routedDHCPSelectedReaderV3 struct {
	*configpoc.RoutedSelectionReaderV2
	acceptContinuation bool
}

func (r routedDHCPSelectedReaderV3) Resolve(ctx context.Context, work string) (routedDHCPWorkV3, error) {
	if r.acceptContinuation {
		return r.ResolveDHCPLeaseAuthorityV4(ctx, work)
	}
	return r.ResolveDHCPCurrentV3(ctx, work)
}

// RoutedDHCPRuntimeV3 serializes the retained helper's lease, policy and gate.
// Its watchdog can only close/withdraw. Only selected R2 and a current owner may
// permit an opening. The independent kernel timeout survives helper/API death.
type RoutedDHCPRuntimeV3 struct {
	mu                        sync.Mutex
	identity                  networkexecutor.OwnedNamespaceIdentity
	owner                     networkexecutor.LeaseOwner
	current                   func(context.Context) (RoutedDHCPOwnerFactV3, error)
	reader                    routedDHCPReaderV3
	policy                    func(context.Context, routedDHCPWorkV3) error
	selectAdmissionBaseline   func(context.Context, configpoc.RoutedDHCPSelectedV3) error
	baselineAdmissionSelected bool
	ready                     func() error
	refreshReady              func() bool
	baseline                  func(context.Context) error
	fenced                    func() bool
	forward                   routedDHCPForwardingV3
	buildGate                 func(context.Context, networkexecutor.LeaseGateAuthority) (routedDHCPGateV3, error)
	openLease                 func(context.Context) (routedDHCPLeaseV3, error)
	recoverLease              func(context.Context, networkexecutor.LeaseSelectedSnapshotV3) (routedDHCPLeaseV3, error)
	releaseLease              func(context.Context) error
	gate                      routedDHCPGateV3
	lease                     routedDHCPLeaseV3
	grant                     configpoc.RoutedDHCPGrantV3
	work                      string
	opened, withdrawn, failed bool
	renewalProfile            RoutedDHCPRenewalProfileV4
	renewalWaiting            bool
	retired                   bool // A V4 retired owner instance never acquires again.
	adoptionClock             func() (int64, error)
	hookEpoch                 uint64
	hookBootNS                int64
	budgetRejectedEpoch       uint64
	lastOverrunEpoch          uint64
	adoptionOverruns          uint64
	marginClosures            uint64
	lastMarginEpoch           uint64
	noticeV4                  string
}

// Gate callbacks run only while runtime.mu is held. They do not reenter Gate,
// the API writer or its publication barrier.
type routedDHCPGateAuthorityV3 struct{ runtime *RoutedDHCPRuntimeV3 }

// This private cause records a coherent authenticated observation, not a later
// successful reread after an unrelated failure. It authorizes closure only.
var errRoutedDHCPOwnerAdvancedV4 = errors.New("ANDEIVA_DHCP_OWNER_ADVANCED_V4")

func (a routedDHCPGateAuthorityV3) Current(ctx context.Context) (networkexecutor.LeaseGateGrant, error) {
	r := a.runtime
	if r.work == "" {
		return networkexecutor.LeaseGateGrant{}, ErrUnavailable
	}
	if ownerErr := r.sameOwner(ctx, r.grant); ownerErr != nil {
		if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 {
			if _, margin := routedDHCPMarginV4(ownerErr); margin {
				return networkexecutor.LeaseGateGrant{}, errors.Join(networkexecutor.ErrLeaseGateMarginClosed, ErrUnavailable)
			}
		}
		if ownerErr == errRoutedDHCPOwnerAdvancedV4 {
			selected, err := r.selected(ctx, r.work)
			if err == nil && selected.Phase() == "applied" && r.sameEffectiveRenewalPendingV4(ctx, selected) {
				return networkexecutor.LeaseGateGrant{}, errors.Join(networkexecutor.ErrLeaseGateRenewal, ErrUnavailable)
			}
		}
		return networkexecutor.LeaseGateGrant{}, ErrUnavailable
	}
	return networkexecutor.LeaseGateGrant{Fact: r.grant.Snapshot.Fact(), WorkHash: r.work}, nil
}
func (a routedDHCPGateAuthorityV3) Verify(ctx context.Context, g networkexecutor.LeaseGateGrant) error {
	r := a.runtime
	p, err := r.selected(ctx, g.WorkHash)
	if err != nil || p.Phase() != "applied" || !r.selectedGrantV4(p, r.grant) || g.Fact != r.grant.Snapshot.Fact() {
		firewallipc.RecordRoutedDHCPFailureV1("authority_selected", configpoc.ErrRecovery, ctx)
		return configpoc.ErrRecovery
	}
	return r.verifySelectedGrantV4(ctx, p)
}

func (r *RoutedDHCPRuntimeV3) verifySelectedGrantV4(ctx context.Context, p routedDHCPWorkV3) error {
	if err := r.sameOwner(ctx, r.grant); err != nil {
		if _, margin := routedDHCPMarginV4(err); margin && r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 {
			return errors.Join(networkexecutor.ErrLeaseGateMarginClosed, configpoc.ErrRecovery)
		}
		if err == errRoutedDHCPOwnerAdvancedV4 && r.sameEffectiveRenewalPendingV4(ctx, p) {
			return errors.Join(networkexecutor.ErrLeaseGateRenewal, configpoc.ErrRecovery)
		}
		firewallipc.RecordRoutedDHCPFailureV1("authority_owner", err, ctx)
		return configpoc.ErrRecovery
	}
	verifySelected := r.lease.VerifySelectedStateV3
	if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 {
		if observer, ok := r.lease.(interface {
			VerifySelectedObservationV4(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedStateV3) error
		}); ok {
			verifySelected = observer.VerifySelectedObservationV4
		}
	}
	if err := verifySelected(ctx, r.grant.Snapshot, networkexecutor.LeaseSelectedTargetV3); err != nil {
		if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 && networkexecutor.MatchesLeaseObservationPendingV4(err, r.grant.Snapshot.Fact()) {
			// The source marker is minted only after target readback. Policy must
			// independently prove every other predicate before closure is expected.
			policyErr := r.policy(ctx, p)
			if routedactivation.MatchesClosedLeaseObservationV4(policyErr, r.grant.Snapshot.Fact(), p.Running()) {
				if _, margin := routedDHCPMarginV4(r.sameOwner(ctx, r.grant)); margin {
					return errors.Join(networkexecutor.ErrLeaseGateMarginClosed, configpoc.ErrRecovery)
				}
				if r.sameEffectiveRenewalPendingV4(ctx, p) {
					return errors.Join(networkexecutor.ErrLeaseGateRenewal, configpoc.ErrRecovery)
				}
			}
		}
		firewallipc.RecordRoutedDHCPFailureV1("authority_lease", err, ctx)
		return configpoc.ErrRecovery
	}
	if err := r.policy(ctx, p); err != nil {
		// A concurrent hook alone must not hide a policy/listener/table failure.
		// Only the engine's complete, closure-only observation can classify this.
		if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 && routedactivation.MatchesClosedLeaseObservationV4(err, r.grant.Snapshot.Fact(), p.Running()) {
			if ownerErr := r.sameOwner(ctx, r.grant); ownerErr != nil {
				if _, margin := routedDHCPMarginV4(ownerErr); margin {
					return errors.Join(networkexecutor.ErrLeaseGateMarginClosed, configpoc.ErrRecovery)
				}
			}
			if r.sameEffectiveRenewalPendingV4(ctx, p) {
				return errors.Join(networkexecutor.ErrLeaseGateRenewal, configpoc.ErrRecovery)
			}
		}
		firewallipc.RecordRoutedDHCPFailureV1("authority_policy", err, ctx)
		return configpoc.ErrRecovery
	}
	err := r.sameOwner(ctx, r.grant)
	if _, margin := routedDHCPMarginV4(err); margin && r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 {
		return errors.Join(networkexecutor.ErrLeaseGateMarginClosed, configpoc.ErrRecovery)
	}
	if err == errRoutedDHCPOwnerAdvancedV4 && r.sameEffectiveRenewalPendingV4(ctx, p) {
		return errors.Join(networkexecutor.ErrLeaseGateRenewal, configpoc.ErrRecovery)
	}
	firewallipc.RecordRoutedDHCPFailureV1("authority_owner_after", err, ctx)
	if err == errRoutedDHCPOwnerAdvancedV4 {
		return configpoc.ErrRecovery
	}
	return err
}

// sameEffectiveRenewalPendingV4 classifies only an authenticated owner epoch
// advance whose selected provenance, effective tuple and owner identity remain
// valid. The caller uses the result only to close the expiring
// gate and hand the fresh grant to the serialized renewal path.
func (r *RoutedDHCPRuntimeV3) sameEffectiveRenewalPendingV4(ctx context.Context, selected routedDHCPWorkV3) bool {
	if r.renewalProfile != RoutedDHCPSameEffectiveRenewalV4 || r.failed || selected == nil || r.lease == nil {
		return false
	}
	next, err := r.currentUnder(ctx)
	if err != nil || !sameRenewalGrantV4(r.grant, next) || !r.selectedGrantV4(selected, r.grant) || !r.selectedGrantV4(selected, next) {
		return false
	}
	// The old snapshot intentionally no longer matches Current. This result
	// authorizes closure only; RefreshSameEffectiveSelectedV4 independently
	// verifies retained L3 and the fresh owner before any new token is staged.
	return r.sameOwner(ctx, next) == nil
}

func (r *RoutedDHCPRuntimeV3) sameOwner(ctx context.Context, g configpoc.RoutedDHCPGrantV3) error {
	if done := networkexecutor.StartNativeLeaseSpanV4("verify_owner"); done != nil {
		defer done()
	}
	x, err := r.current(ctx)
	r.observeHookV4(x, err)
	if _, margin := routedDHCPMarginV4(err); margin && r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 {
		return errors.Join(configpoc.ErrRecovery, err)
	}
	if err != nil || x.Epoch == 0 || x.Epoch != g.Epoch || x.Fact.Owner != r.owner || x.Fact.Revoked || x.Fact != g.Snapshot.Fact() || ctx.Err() != nil {
		previous := g.Snapshot.Fact()
		if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 && err == nil && ctx.Err() == nil && x.Epoch > g.Epoch && x.Fact.Owner == r.owner && !x.Fact.Revoked && x.Fact.Sequence > previous.Sequence && x.Fact.DesiredHash == previous.DesiredHash && x.Fact.WAN == previous.WAN && x.Fact.Address == previous.Address && x.Fact.Gateway == previous.Gateway && x.Fact.DeadlineBootNS > 0 {
			return errRoutedDHCPOwnerAdvancedV4
		}
		return configpoc.ErrRecovery
	}
	return nil
}

func (r *RoutedDHCPRuntimeV3) selected(ctx context.Context, work string) (routedDHCPWorkV3, error) {
	if done := networkexecutor.StartNativeLeaseSpanV4("selected_authority"); done != nil {
		defer done()
	}
	p, err := r.reader.Resolve(ctx, work)
	if err != nil || p == nil || p.Reference().WorkHash != work || p.Snapshot().Identity != r.identity || p.Snapshot().Fact().Owner != r.owner || p.Epoch() == 0 {
		return nil, configpoc.ErrRecovery
	}
	return p, nil
}

// Caller holds runtime ownership. This proof can only preserve an existing
// permit during store unavailability. It grants no readiness or effect authority.
func (r *RoutedDHCPRuntimeV3) verifyRetainedPermitV4(ctx context.Context) error {
	if r.renewalProfile != RoutedDHCPSameEffectiveRenewalV4 || !r.opened || r.failed || r.withdrawn || r.retired || r.gate == nil || r.lease == nil || r.work == "" || r.fenced() {
		return configpoc.ErrRecovery
	}
	grant := r.grant
	fact := grant.Snapshot.Fact()
	if r.lease.VerifySelectedStateV3(ctx, grant.Snapshot, networkexecutor.LeaseSelectedTargetV3) != nil || r.forward.VerifyOpen(ctx) != nil || r.gate.VerifyRetainedV4(ctx, networkexecutor.LeaseGateGrant{Fact: fact, WorkHash: r.work}) != nil {
		return configpoc.ErrRecovery
	}
	actual, err := r.current(ctx)
	if err != nil || actual.Epoch != grant.Epoch || actual.Fact != fact || r.fenced() || ctx.Err() != nil {
		return configpoc.ErrRecovery
	}
	return nil
}

func (r *RoutedDHCPRuntimeV3) closeUnder(ctx context.Context) error {
	if done := networkexecutor.StartNativeLeaseSpanV4("runtime_close"); done != nil {
		defer done()
	}
	r.opened = false
	var gateErr error
	if r.gate != nil {
		gateErr = r.gate.Close(ctx)
	}
	forwardErr := r.forward.Disable(ctx)
	if gateErr != nil || forwardErr != nil {
		firewallipc.RecordRoutedDHCPFailureV1("close_gate", gateErr, ctx)
		firewallipc.RecordRoutedDHCPFailureV1("close_forward", forwardErr, ctx)
		r.failed = true
		return errors.Join(configpoc.ErrRecovery, gateErr, forwardErr)
	}
	return nil
}

func (r *RoutedDHCPRuntimeV3) currentUnder(ctx context.Context) (configpoc.RoutedDHCPGrantV3, error) {
	if done := networkexecutor.StartNativeLeaseSpanV4("current_evidence"); done != nil {
		defer done()
	}
	// Current is a bounded, read-only owner observation. Integrity inspection
	// may temporarily pause effects, but must not make the selected lease look
	// absent and trigger a destructive controller withdrawal.
	if r.failed || r.lease == nil {
		firewallipc.RecordRoutedDHCPFailureV1("current_state", configpoc.ErrRecovery, ctx)
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	x, err := r.current(ctx)
	r.observeHookV4(x, err)
	if err != nil || x.Epoch == 0 || x.Fact.Owner != r.owner || x.Fact.Revoked {
		firewallipc.RecordRoutedDHCPFailureV1("current_owner", errors.Join(err, configpoc.ErrRecovery), ctx)
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	s, err := r.lease.PrepareSelectedSnapshotV3(ctx)
	g := configpoc.RoutedDHCPGrantV3{Epoch: x.Epoch, Snapshot: s}
	if err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("current_prepare", err, ctx)
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if s.Identity != r.identity || s.Fact() != x.Fact || r.sameOwner(ctx, g) != nil {
		firewallipc.RecordRoutedDHCPFailureV1("current_recheck", configpoc.ErrRecovery, ctx)
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	return g, nil
}

func (r *RoutedDHCPRuntimeV3) begin(ctx context.Context) (configpoc.RoutedDHCPGrantV3, error) {
	if r.retired || r.failed || r.ready() != nil || r.work != "" && !r.withdrawn {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if r.reader.VerifyDHCPReleasedV3(ctx) != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	// Probe before any gate/forwarding/lease mutation. Only typed acquisition
	// states are effect-free; generic unavailability remains recovery.
	x, currentErr := r.current(ctx)
	if epoch, noLease := routedDHCPNoLeaseEpochV1(currentErr); noLease {
		if x != (RoutedDHCPOwnerFactV3{}) || r.lease != nil || r.work != "" || r.opened || r.withdrawn || r.baseline == nil || r.forward.VerifyClosed(ctx) != nil || (r.gate != nil && r.gate.VerifyClosedSelectedV3(ctx) != nil) || r.baseline(ctx) != nil || r.reader.VerifyDHCPReleasedV3(ctx) != nil || r.ready() != nil || ctx.Err() != nil {
			return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
		}
		// A second atomic observation can already contain BOUND. Continue with
		// that grant instead of mixing its phase with an earlier empty lease.
		x, currentErr = r.current(ctx)
		if after, stillNoLease := routedDHCPNoLeaseEpochV1(currentErr); stillNoLease {
			if after < epoch || x != (RoutedDHCPOwnerFactV3{}) || r.ready() != nil || ctx.Err() != nil {
				return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
			}
			return configpoc.RoutedDHCPGrantV3{}, currentErr
		}
		if currentErr != nil {
			return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
		}
	}
	if currentErr != nil {
		if state, margin := routedDHCPMarginV4(currentErr); margin && r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 && r.lease == nil && r.work == "" && !r.opened && !r.withdrawn && r.forward.VerifyClosed(ctx) == nil && (r.gate == nil || r.gate.VerifyClosedSelectedV3(ctx) == nil) && r.reader.VerifyDHCPReleasedV3(ctx) == nil && r.ready() == nil && ctx.Err() == nil {
			r.noteMarginClosedV4(state.epoch)
			return configpoc.RoutedDHCPGrantV3{}, currentErr
		}
		if currentErr == errRoutedDHCPInitialWaitingV1 && x == (RoutedDHCPOwnerFactV3{}) && r.lease == nil && r.work == "" && !r.opened && !r.withdrawn && r.forward.VerifyClosed(ctx) == nil && (r.gate == nil || r.gate.VerifyClosedSelectedV3(ctx) == nil) && r.reader.VerifyDHCPReleasedV3(ctx) == nil && r.ready() == nil && ctx.Err() == nil {
			return configpoc.RoutedDHCPGrantV3{}, errRoutedDHCPInitialWaitingV1
		}
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if ctx.Err() != nil || x.Epoch == 0 || x.Fact.Owner != r.owner || x.Fact.Revoked {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if r.gate == nil {
		if r.forward.VerifyClosed(ctx) != nil {
			return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
		}
		last, err := r.reader.LastWithdrawnDHCPV3(ctx)
		if err != nil {
			return configpoc.RoutedDHCPGrantV3{}, err
		}
		g, err := r.buildGate(ctx, routedDHCPGateAuthorityV3{r})
		if err != nil {
			return configpoc.RoutedDHCPGrantV3{}, err
		}
		r.gate = g
		if last == nil {
			err = g.Initialize(ctx)
		} else {
			err = g.RecoverWithdrawnSelectedV3(ctx, *last)
		}
		if err != nil {
			r.failed = true
			return configpoc.RoutedDHCPGrantV3{}, err
		}
	}
	if r.closeUnder(ctx) != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if r.lease == nil {
		l, err := r.openLease(ctx)
		if err != nil {
			return configpoc.RoutedDHCPGrantV3{}, err
		}
		r.lease = l
	}
	g, err := r.currentUnder(ctx)
	if err != nil || r.lease.VerifySelectedStateV3(ctx, g.Snapshot, networkexecutor.LeaseSelectedBaselineV3) != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	r.grant, r.work, r.withdrawn = g, "", false
	return g, nil
}

func (r *RoutedDHCPRuntimeV3) verifyClosed(ctx context.Context, hash string, state networkexecutor.LeaseSelectedStateV3) error {
	if r.grant.Snapshot.Hash != hash || r.gate == nil || r.lease == nil || r.gate.VerifyClosedSelectedV3(ctx) != nil || r.forward.VerifyClosed(ctx) != nil {
		return configpoc.ErrRecovery
	}
	return r.lease.VerifySelectedStateV3(ctx, r.grant.Snapshot, state)
}

func (r *RoutedDHCPRuntimeV3) apply(ctx context.Context, work string) error {
	if r.failed || r.ready() != nil || r.closeUnder(ctx) != nil {
		return configpoc.ErrRecovery
	}
	p, err := r.selected(ctx, work)
	if err != nil || p.Phase() != "prepared" || r.lease == nil || !reflect.DeepEqual(p.Snapshot(), r.grant.Snapshot) || p.Epoch() != r.grant.Epoch || r.sameOwner(ctx, r.grant) != nil || r.verifyClosed(ctx, r.grant.Snapshot.Hash, networkexecutor.LeaseSelectedBaselineV3) != nil {
		return configpoc.ErrRecovery
	}
	r.work = work
	if _, err = r.lease.Refresh(ctx); err != nil {
		return errors.Join(err, r.withdraw(ctx, work))
	}
	after, err := r.selected(ctx, work)
	if err != nil || after.Reference() != p.Reference() || r.verifyClosed(ctx, r.grant.Snapshot.Hash, networkexecutor.LeaseSelectedTargetV3) != nil || r.sameOwner(ctx, r.grant) != nil {
		return errors.Join(configpoc.ErrRecovery, r.withdraw(ctx, work))
	}
	return nil
}

func (r *RoutedDHCPRuntimeV3) retire(ctx context.Context) error {
	if r.failed || !r.withdrawn || r.lease == nil || r.gate == nil {
		return configpoc.ErrRecovery
	}
	last, err := r.reader.LastWithdrawnDHCPV3(ctx)
	if err != nil || last == nil || !reflect.DeepEqual(*last, r.grant.Snapshot) || r.verifyClosed(ctx, r.grant.Snapshot.Hash, networkexecutor.LeaseSelectedBaselineV3) != nil {
		return configpoc.ErrRecovery
	}
	if err := r.releaseLease(ctx); err != nil {
		r.failed = true
		return err
	}
	if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 {
		// Immutable undo carries the original sequence. The same closed gate
		// retains newer consumed sequences until the helper releases resources.
		r.retired = true
		gateErr, forwardErr := r.gate.VerifyClosedSelectedV3(ctx), r.forward.VerifyClosed(ctx)
		if gateErr != nil || forwardErr != nil {
			r.failed = true
			return errors.Join(configpoc.ErrRecovery, gateErr, forwardErr)
		}
	} else {
		if err := r.gate.DisposeWithdrawnSelectedV3(ctx, *last); err != nil {
			r.failed = true
			return err
		}
		r.gate = nil
	}
	r.lease, r.work, r.grant, r.withdrawn = nil, "", configpoc.RoutedDHCPGrantV3{}, false
	return nil
}

func (r *RoutedDHCPRuntimeV3) open(ctx context.Context, work string) error {
	if done := networkexecutor.StartNativeLeaseSpanV4("runtime_open"); done != nil {
		defer done()
	}
	if r.failed || r.ready() != nil || r.opened || r.work != work || r.gate == nil || r.lease == nil {
		firewallipc.RecordRoutedDHCPFailureV1("open_state", configpoc.ErrRecovery, ctx)
		return configpoc.ErrRecovery
	}
	if err := r.checkAdoptionBudgetV4(ctx); err != nil {
		return err
	}
	p, err := r.selected(ctx, work)
	if err != nil || p.Phase() != "applied" || !r.selectedGrantV4(p, r.grant) {
		firewallipc.RecordRoutedDHCPFailureV1("open_selected", configpoc.ErrRecovery, ctx)
		return configpoc.ErrRecovery
	}
	if r.selectAdmissionBaseline != nil && !r.baselineAdmissionSelected {
		baseline, ok := p.(configpoc.RoutedDHCPSelectedV3)
		if !ok || r.verifyClosed(ctx, r.grant.Snapshot.Hash, networkexecutor.LeaseSelectedTargetV3) != nil ||
			r.selectAdmissionBaseline(ctx, baseline) != nil {
			return configpoc.ErrRecovery
		}
		r.baselineAdmissionSelected = true
	}
	if err := r.sameOwner(ctx, r.grant); err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("open_owner", err, ctx)
		return configpoc.ErrRecovery
	}
	if err := r.checkAdoptionBudgetV4(ctx); err != nil {
		return err
	}
	if err := r.gate.Stage(ctx); err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("open_gate_stage", err, ctx)
		return r.closeRenewalErrorV4(ctx, err)
	}
	if err := r.checkAdoptionBudgetV4(ctx); err != nil {
		return err
	}
	if err := r.gate.Open(ctx); err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("open_gate_open", err, ctx)
		return r.closeRenewalErrorV4(ctx, err)
	}
	if err := r.checkAdoptionBudgetV4(ctx); err != nil {
		return err
	}
	if err := r.forward.Enable(ctx, r.gate.Verify); err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("open_forward", err, ctx)
		return r.closeRenewalErrorV4(ctx, err)
	}
	if err := r.checkAdoptionBudgetV4(ctx); err != nil {
		return err
	}
	r.opened = true
	r.noticeV4 = ""
	return nil
}

func (r *RoutedDHCPRuntimeV3) closeRenewalErrorV4(ctx context.Context, cause error) error {
	closed := r.closeUnder(ctx)
	if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 && closed == nil && (errors.Is(cause, networkexecutor.ErrLeaseGateRenewal) || errors.Is(cause, networkexecutor.ErrLeaseGateExpired) || errors.Is(cause, networkexecutor.ErrLeaseGateMarginClosed)) {
		r.renewalWaiting = true
	}
	return errors.Join(cause, closed)
}

func (r *RoutedDHCPRuntimeV3) withdraw(ctx context.Context, work string) error {
	// Retained gate closure precedes even a failed selected-store read. A fresh
	// helper has no token authority and requires supervisor-contained forwarding.
	if r.closeUnder(ctx) != nil {
		firewallipc.RecordRoutedDHCPFailureV1("withdraw_close", configpoc.ErrRecovery, ctx)
		return configpoc.ErrRecovery
	}
	p, err := r.selected(ctx, work)
	if err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("withdraw_selected", err, ctx)
		return err
	}
	s := p.Snapshot()
	if r.gate == nil {
		g, e := r.buildGate(ctx, routedDHCPGateAuthorityV3{r})
		if e != nil {
			firewallipc.RecordRoutedDHCPFailureV1("withdraw_build_gate", e, ctx)
			return e
		}
		r.gate = g
		if e = g.RecoverClosedSelectedV3(ctx, s); e != nil {
			firewallipc.RecordRoutedDHCPFailureV1("withdraw_recover_gate", e, ctx)
			r.failed = true
			return e
		}
	}
	if r.lease == nil {
		l, e := r.recoverLease(ctx, s)
		if e != nil {
			firewallipc.RecordRoutedDHCPFailureV1("withdraw_recover_lease", e, ctx)
			return e
		}
		r.lease = l
	}
	r.grant, r.work = configpoc.RoutedDHCPGrantV3{Epoch: p.Epoch(), Snapshot: s}, work
	if _, err = r.lease.WithdrawSelectedV3(ctx); err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("withdraw_lease", err, ctx)
		r.failed = true
		return err
	}
	if err = r.verifyClosed(ctx, s.Hash, networkexecutor.LeaseSelectedBaselineV3); err != nil {
		firewallipc.RecordRoutedDHCPFailureV1("withdraw_verify", err, ctx)
		r.failed = true
		return err
	}
	r.withdrawn = true
	r.renewalWaiting = false
	return nil
}

func (r *RoutedDHCPRuntimeV3) dispatch(ctx context.Context, c firewallipc.RoutedCommandV3) (any, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	finishWait := networkexecutor.StartNativeLeaseSpanV4("rpc_wait")
	r.mu.Lock()
	if finishWait != nil {
		finishWait()
	}
	defer r.mu.Unlock()
	var g configpoc.RoutedDHCPGrantV3
	var err error
	switch c.Verb {
	case "dhcp_begin":
		g, err = r.begin(ctx)
	case "dhcp_current":
		g, err = r.currentUnder(ctx)
	case "dhcp_verify":
		err = r.verifyClosed(ctx, c.DHCP.Snapshot, c.DHCP.State)
	case "dhcp_apply":
		err = r.apply(ctx, c.DHCP.Work)
	case "dhcp_renew":
		g, err = r.renewSameEffectiveModeV4(ctx, c.DHCP.Work, c.DHCP.Snapshot, c.DHCP.RefreshOnly)
	case "dhcp_open":
		err = r.open(ctx, c.DHCP.Work)
	case "dhcp_withdraw":
		err = r.withdraw(ctx, c.DHCP.Work)
	case "dhcp_retire":
		err = r.retire(ctx)
	case "dhcp_live":
		if r.failed || r.ready() != nil || !r.opened || r.work != c.DHCP.Work {
			err = configpoc.ErrRecovery
		} else {
			err = r.gate.Verify(ctx)
			if errors.Is(err, networkexecutor.ErrLeaseGateRenewal) || errors.Is(err, networkexecutor.ErrLeaseGateExpired) {
				err = r.closeRenewalErrorV4(ctx, err)
			}
		}
	default:
		err = ErrIdentity
	}
	if c.Verb == "dhcp_current" || c.Verb == "dhcp_begin" || c.Verb == "dhcp_renew" {
		return firewallipc.RoutedDHCPGrantV3{Epoch: g.Epoch, Snapshot: g.Snapshot}, err
	}
	return struct{}{}, err
}

// Run watches the authenticated owner while the API is absent. It never grants
// access or publishes selected state. API recovery must still archive withdrawal.
func (r *RoutedDHCPRuntimeV3) Run(ctx context.Context) {
	if r == nil || ctx == nil {
		return
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			if r.opened || r.renewalWaiting {
				call, cancel := context.WithTimeout(ctx, 3*time.Second)
				r.watchLeaseV4(call)
				cancel()
			}
			r.mu.Unlock()
		}
	}
}
