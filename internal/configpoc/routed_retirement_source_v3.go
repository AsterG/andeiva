package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// Only a full selected reader issues this correlation. It does not establish
// process drainage or authorize namespace teardown without Root's retained
// publication barrier and independently authenticated operational anchors.
type RoutedRetirementSourceV3 struct {
	identity networkexecutor.OwnedNamespaceIdentity
	ref      SelectionReferenceV2
	verified bool
}

func (s RoutedRetirementSourceV3) Identity() networkexecutor.OwnedNamespaceIdentity {
	return s.identity
}
func (s RoutedRetirementSourceV3) Reference() SelectionReferenceV2 { return s.ref }
func (s RoutedRetirementSourceV3) Valid() bool {
	return s.verified && validRoutedIdentityV1(s.identity) && validHash(s.ref.Selection) && validHash(s.ref.State) && validHash(s.ref.WorkHash) && s.ref.Lineage != ""
}

// ObserveRetirementSourceV3 verifies CURRENT selected work, never arbitrary
// historical work. Old comes from Root's authenticated retained scope. The
// callback is readonly; callers must wait for the final successful return before
// transmitting a result. Root retains the SAME store writer lock through effects.
func (r *RoutedSelectionReaderV2) ObserveRetirementSourceV3(ctx context.Context, old networkexecutor.OwnedNamespaceIdentity, observe func(RoutedRetirementSourceV3) error) (out RoutedRetirementSourceV3, result error) {
	if r == nil || ctx == nil || ctx.Err() != nil || r.options.Policy != SelectionFullHistoryV2 || !validRoutedIdentityV1(old) || r.options.Identity != old || observe == nil {
		return out, ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return out, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out, result = RoutedRetirementSourceV3{}, ErrRecovery
		}
	}()
	s := v.store
	cfg := s.state.Configuration
	if cfg == nil || cfg.RecoveryRequired {
		return out, ErrRecovery
	}
	work := ""
	var identity networkexecutor.OwnedNamespaceIdentity
	switch {
	case s.state.RoutedDHCP != nil:
		d := s.state.RoutedDHCP
		if validateRoutedDHCPSelectedV3(s.state, s.readObject) != nil {
			return out, ErrRecovery
		}
		selected, e := loadRoutedDHCPWorkV3(d.Work, s.state.Lineage, s.readObject)
		if e != nil {
			return out, e
		}
		work, identity = d.Work, selected.Snapshot.Identity
	case cfg.Intent != nil:
		in := cfg.Intent
		if in.Kind != v2BootKind || in.Domain != "routed" {
			return out, ErrRecovery
		}
		work = in.RoutedWork
	case cfg.Pending != nil:
		pending := cfg.Pending
		if pending.Domain != "routed" {
			return out, ErrRecovery
		}
		op, e := s.lookupRetained(pending.Owner, pending.OriginCommit)
		if e != nil || !op.Pinned || op.Reserve == nil || op.Reserve.PlanIntent == nil {
			return out, ErrRecovery
		}
		work = op.Reserve.PlanIntent.RoutedWork
	case s.state.RoutedActive != nil:
		work = s.state.RoutedActive.Work
	default:
		return out, ErrRecovery
	}
	if !validHash(work) {
		return out, ErrRecovery
	}
	if s.state.RoutedDHCP == nil {
		selected, e := loadRoutedWorkV2(work, s.state.Lineage, s.readObject)
		if e != nil {
			return out, e
		}
		identity = selected.Scope().Identity
	}
	if identity != old {
		return out, ErrRecovery
	}
	ref := v.ref
	ref.WorkHash = work
	candidate := RoutedRetirementSourceV3{identity: identity, ref: ref, verified: true}
	if !candidate.Valid() {
		return out, ErrRecovery
	}
	if err = r.revalidate(ctx, v); err != nil {
		return out, err
	}
	if err = observe(candidate); err != nil {
		return out, err
	}
	if err = r.revalidate(ctx, v); err != nil {
		return out, err
	}
	return candidate, nil
}
