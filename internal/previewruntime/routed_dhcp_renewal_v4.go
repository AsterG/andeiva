package previewruntime

import (
	"context"
	"errors"
	"reflect"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// RoutedDHCPRenewalProfileV4 is selected by trusted assembly after matching IPC
// capabilities. It is not a configuration field or request-controlled option.
type RoutedDHCPRenewalProfileV4 uint8

const (
	RoutedDHCPLegacyRenewalV4 RoutedDHCPRenewalProfileV4 = iota
	RoutedDHCPSameEffectiveRenewalV4
)

func (r *RoutedDHCPRuntimeV3) SetRenewalProfileV4(profile RoutedDHCPRenewalProfileV4) error {
	if r == nil {
		return ErrIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if profile > RoutedDHCPSameEffectiveRenewalV4 || r.work != "" || r.lease != nil || r.gate != nil || r.failed || r.withdrawn || r.opened || r.renewalWaiting || r.retired {
		return ErrIdentity
	}
	r.renewalProfile = profile
	return nil
}

func (r *RoutedDHCPRuntimeV3) SameEffectiveRenewalV4() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4
}

// selectedGrantV4 preserves the immutable selected snapshot as provenance and
// undo. Operational renewals may differ only in source sequence/deadline/epoch.
func (r *RoutedDHCPRuntimeV3) selectedGrantV4(p routedDHCPWorkV3, g configpoc.RoutedDHCPGrantV3) bool {
	if p == nil {
		return false
	}
	if p.Epoch() == g.Epoch && reflect.DeepEqual(p.Snapshot(), g.Snapshot) {
		return true
	}
	return r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 && g.Epoch > p.Epoch() && networkexecutor.ValidateSameEffectiveLeaseV4(p.Snapshot(), g.Snapshot) == nil
}

func sameRenewalGrantV4(previous, next configpoc.RoutedDHCPGrantV3) bool {
	return next.Epoch > previous.Epoch && networkexecutor.ValidateSameEffectiveLeaseV4(previous.Snapshot, next.Snapshot) == nil
}

type routedDHCPLeaseRenewalV4 interface {
	RefreshSameEffectiveSelectedV4(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error
}

// Caller holds runtime.mu. Correlation fields are not grants: Current supplies
// the complete new evidence. No store write, claim or selected-plan rewrite.
func (r *RoutedDHCPRuntimeV3) renewSameEffectiveV4(ctx context.Context, work, snapshot string) (out configpoc.RoutedDHCPGrantV3, result error) {
	return r.renewSameEffectiveModeV4(ctx, work, snapshot, false)
}

func (r *RoutedDHCPRuntimeV3) renewSameEffectiveModeV4(ctx context.Context, work, snapshot string, refreshOnly bool) (out configpoc.RoutedDHCPGrantV3, result error) {
	reject := func(stage string, cause error) (configpoc.RoutedDHCPGrantV3, error) {
		firewallipc.RecordRoutedDHCPFailureV1(stage, cause, ctx)
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if r.renewalProfile != RoutedDHCPSameEffectiveRenewalV4 || work == "" || work != r.work || r.lease == nil || r.gate == nil || r.forward == nil {
		return reject("renew_binding", configpoc.ErrRecovery)
	}
	if refreshOnly {
		// Revocation needs the retained private Work binding, not fresh owner
		// evidence or readiness. Any later failure must leave this permit closed.
		if err := r.closeUnder(ctx); err != nil {
			return out, err
		}
		forwardErr, gateErr := r.forward.VerifyClosed(ctx), r.gate.VerifyClosedSelectedV3(ctx)
		if forwardErr != nil || gateErr != nil {
			r.failed = true
			return out, errors.Join(configpoc.ErrRecovery, forwardErr, gateErr)
		}
		r.renewalWaiting = true
	}
	eligible := r.ready() == nil
	if r.refreshReady != nil {
		eligible = r.refreshReady()
	}
	if r.failed || r.fenced() || !eligible || r.withdrawn {
		return reject("renew_state", configpoc.ErrRecovery)
	}
	next, err := r.currentUnder(ctx)
	if err != nil {
		return reject("renew_current", err)
	}
	if snapshot != next.Snapshot.Hash {
		return reject("renew_snapshot", configpoc.ErrRecovery)
	}
	if reflect.DeepEqual(next, r.grant) {
		if refreshOnly {
			return out, configpoc.ErrRecovery // Never open in the recovery-only lane.
		}
		if r.ready() != nil || r.fenced() || ctx.Err() != nil {
			return reject("renew_state", configpoc.ErrRecovery)
		}
		p, err := r.selected(ctx, work)
		if err != nil || p.Phase() != "applied" || !r.selectedGrantV4(p, r.grant) {
			return out, configpoc.ErrRecovery
		}
		if r.sameOwner(ctx, next) != nil {
			return out, configpoc.ErrRecovery
		}
		if r.opened {
			if err := r.gate.Verify(ctx); err != nil {
				return out, r.closeRenewalErrorV4(ctx, err)
			}
			return next, nil // Retry after a lost reply; existing token is already current.
		}
		if !r.renewalWaiting || r.forward.VerifyClosed(ctx) != nil || r.gate.VerifyClosedSelectedV3(ctx) != nil {
			return out, configpoc.ErrRecovery
		}
		if err = r.open(ctx, work); err != nil {
			return out, err
		}
		r.renewalWaiting = false
		return next, nil
	}
	// Revoke the prior permit as soon as the authenticated owner reports a new
	// grant. Validation and lease-proof refresh happen only after readback of
	// both closed gates, so an unexpected tuple cannot leave old forwarding open.
	if err = r.closeUnder(ctx); err != nil {
		return out, err
	}
	r.renewalWaiting = true
	defer func() {
		if result != nil {
			result = errors.Join(result, r.closeUnder(ctx))
		}
	}()
	if !sameRenewalGrantV4(r.grant, next) {
		return reject("renew_effective_tuple", configpoc.ErrRecovery)
	}
	lease, ok := r.lease.(routedDHCPLeaseRenewalV4)
	if !ok {
		return reject("renew_lease_capability", configpoc.ErrRecovery)
	}
	p, err := r.selected(ctx, work)
	if err != nil || p.Phase() != "applied" || !r.selectedGrantV4(p, r.grant) || !r.selectedGrantV4(p, next) {
		return reject("renew_selected", err)
	}
	if r.forward.VerifyClosed(ctx) != nil || r.gate.VerifyClosedSelectedV3(ctx) != nil || r.sameOwner(ctx, next) != nil {
		return reject("renew_closed_authority", configpoc.ErrRecovery)
	}
	if err = lease.RefreshSameEffectiveSelectedV4(ctx, r.grant.Snapshot, next.Snapshot); err != nil {
		return reject("renew_selected_proof", err)
	}
	r.grant = next
	if refreshOnly || ctx.Err() != nil || r.fenced() || r.ready() != nil {
		// Refresh changes only retained evidence under a verified closed gate.
		// Full inspection, not this operational lane, must restore readiness.
		return reject("renew_wait_integrity", configpoc.ErrRecovery)
	}
	if err = r.open(ctx, work); err != nil {
		return reject("renew_reopen", err)
	}
	r.renewalWaiting = false
	return next, nil
}

// The watchdog never opens a token. A fresh same-effective renewal closes the
// old permit without deleting L3. Even while closed it keeps checking freshness;
// expiry/revocation/death or a changed tuple takes the original withdrawal path.
func (r *RoutedDHCPRuntimeV3) watchLeaseV4(ctx context.Context) {
	if !r.opened && !r.renewalWaiting {
		return
	}
	if r.fenced() {
		_ = r.withdraw(ctx, r.work)
		return
	}
	if r.sameOwner(ctx, r.grant) == nil {
		return
	}
	if r.renewalProfile == RoutedDHCPSameEffectiveRenewalV4 && !r.withdrawn && !r.failed {
		next, err := r.currentUnder(ctx)
		if err == nil && sameRenewalGrantV4(r.grant, next) {
			if r.closeUnder(ctx) == nil {
				r.renewalWaiting = true
			}
			return
		}
	}
	_ = r.withdraw(ctx, r.work)
}
