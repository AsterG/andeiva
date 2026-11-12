package previewruntime

import (
	"context"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/routedactivation"
)

// RoutedAuthority joins the selected coordinator plan to the physical adapter.
// Its lifetime belongs to the helper, never to an HTTP server or catalogue.
type RoutedAuthority struct {
	mu       sync.Mutex
	engine   *routedactivation.Engine
	group    *nftguardian.Group
	selected configpoc.RoutedSelectedPlanV1
	identity networkexecutor.OwnedNamespaceIdentity
	baseline *configpoc.RoutedBaselineV1
}

func NewRoutedAuthority(kernel routedactivation.Kernel, network routedactivation.Network, listeners localengine.Listeners, options routedactivation.Options, identity networkexecutor.OwnedNamespaceIdentity) (*RoutedAuthority, error) {
	if identity.UID == 0 || identity.GID == 0 || identity.Namespace == 0 || identity.Host == 0 || identity.Namespace == identity.Host || !bootPattern.MatchString(identity.BootID) || !validHex(identity.RunID, 16) {
		return nil, ErrIdentity
	}
	a := &RoutedAuthority{identity: identity}
	options.ResolvePlan = a.resolveSelected
	options.ResolveBaseline = a.resolveBaseline
	options.ResolveRecoveredIdle = a.resolveRecoveredIdle
	engine, err := routedactivation.New(kernel, network, listeners, options)
	if err != nil {
		return nil, err
	}
	group, err := nftguardian.NewGroup(engine)
	if err != nil {
		return nil, err
	}
	a.engine, a.group = engine, group
	return a, nil
}

func (a *RoutedAuthority) Identity() networkexecutor.OwnedNamespaceIdentity { return a.identity }

func (a *RoutedAuthority) resolveBaseline(ctx context.Context, target configpoc.RoutedActivationBundleV1) (routedactivation.BaselineV1, error) {
	a.mu.Lock()
	baseline := a.baseline
	a.mu.Unlock()
	if ctx.Err() != nil || baseline == nil || baseline.Saved.Composite.Hash != target.Composite.Hash {
		return routedactivation.BaselineV1{}, configpoc.ErrRecovery
	}
	return routedactivation.BaselineV1{Saved: baseline.Saved, Owned: baseline.Owned, Dependencies: baseline.Dependencies}, nil
}

func (a *RoutedAuthority) resolveRecoveredIdle(ctx context.Context, transition configpoc.RoutedTransitionV1, deadline time.Time) (nftguardian.RecoveredIdleV1, error) {
	a.mu.Lock()
	p := a.selected
	a.mu.Unlock()
	if ctx.Err() != nil || !p.Valid() || p.Scope().Identity != a.identity || p.Transition() != transition || !p.Deadline().Equal(deadline) {
		return nftguardian.RecoveredIdleV1{}, configpoc.ErrRecovery
	}
	previous, target := p.Bundles()
	witness := nftguardian.RecoveredIdleV1{Plan: transition, Deadline: deadline, Scope: a.identity}
	switch p.Resolution() {
	case "before":
		witness.Bundle = previous
		witness.OwnedRef = transition.BeforeOwned
		witness.Finality = nftguardian.BeforeRestored
	case "target":
		witness.Bundle = &target
		witness.OwnedRef = transition.TargetOwned
		witness.Finality = nftguardian.TargetConfirmed
	default:
		return nftguardian.RecoveredIdleV1{}, configpoc.ErrRecovery
	}
	return witness, nil
}

func (a *RoutedAuthority) Resume(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	if p.Resolution() != "before" && p.Resolution() != "target" {
		return configpoc.ErrRecovery
	}
	if err := a.install(p); err != nil {
		return err
	}
	state, _, err := a.group.SnapshotObserved()
	_, selectedTarget := p.Bundles()
	confirmedReceipt := p.Resolution() == "target" && state.ID == p.Lease() && state.Target == selectedTarget.Composite.Hash && state.Deadline.Equal(p.Deadline())
	if err == nil && state.Phase == "idle" && (state.ID == "" || confirmedReceipt) && a.Match(ctx, p, p.Resolution()) == nil {
		return nil
	}
	// A selected recovery intent may already have reconstructed and restored
	// this engine. Final publication now supplies the missing idle witness.
	if err = a.group.RecoverIdle(ctx, p.Transition()); err == nil {
		return nil
	}
	previous, target := p.Bundles()
	if err = a.engine.RecoverPlan(ctx, p.Transition(), previous, target, p.Deadline(), p.Scope().Identity); err != nil {
		return err
	}
	return a.group.RecoverIdle(ctx, p.Transition())
}

func (a *RoutedAuthority) resolveSelected(ctx context.Context, transition configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, deadline time.Time) (routedactivation.PreparationV1, error) {
	a.mu.Lock()
	p := a.selected
	a.mu.Unlock()
	if ctx.Err() != nil || !p.Valid() || transition != p.Transition() || !deadline.Equal(p.Deadline()) || (previous == nil) != p.Cold() {
		return routedactivation.PreparationV1{}, configpoc.ErrRecovery
	}
	wantPrevious, wantTarget := p.Bundles()
	if target.Composite.Hash != wantTarget.Composite.Hash || (previous != nil && previous.Composite.Hash != wantPrevious.Composite.Hash) {
		return routedactivation.PreparationV1{}, configpoc.ErrRecovery
	}
	artifacts := p.Artifacts()
	return routedactivation.PreparationV1{Before: artifacts.Before, Target: artifacts.Target, Dependencies: artifacts.Dependencies}, nil
}

func (a *RoutedAuthority) install(p configpoc.RoutedSelectedPlanV1) error {
	if a == nil || a.group == nil || !p.Valid() || p.Scope().Identity != a.identity {
		return configpoc.ErrRecovery
	}
	a.mu.Lock()
	a.selected = p
	a.baseline = p.Baseline()
	a.mu.Unlock()
	return nil
}

func (a *RoutedAuthority) Prepare(ctx context.Context, target configpoc.RoutedActivationBundleV1, baseline *configpoc.RoutedBaselineV1) (configpoc.RoutedPreparationV1, error) {
	if a == nil || a.engine == nil {
		return configpoc.RoutedPreparationV1{}, configpoc.ErrRecovery
	}
	a.mu.Lock()
	a.baseline = baseline
	a.mu.Unlock()
	value, err := a.engine.Prepare(ctx, target)
	return configpoc.RoutedPreparationV1{Before: value.Before, Target: value.Target, Dependencies: value.Dependencies}, err
}

func (a *RoutedAuthority) PrepareBoot(ctx context.Context, target, saved configpoc.RoutedActivationBundleV1) (configpoc.RoutedPreparationV1, error) {
	engine, ok := any(a.engine).(interface {
		PrepareColdBoot(context.Context, configpoc.RoutedActivationBundleV1, configpoc.RoutedActivationBundleV1) (routedactivation.PreparationV1, error)
	})
	if !ok {
		return configpoc.RoutedPreparationV1{}, configpoc.ErrRecovery
	}
	value, err := engine.PrepareColdBoot(ctx, target, saved)
	return configpoc.RoutedPreparationV1{Before: value.Before, Target: value.Target, Dependencies: value.Dependencies}, err
}

func (a *RoutedAuthority) Observe(ctx context.Context) (configpoc.RoutedReceiptV1, string, error) {
	if ctx == nil || ctx.Err() != nil || a == nil || a.group == nil {
		return configpoc.RoutedReceiptV1{}, "", configpoc.ErrRecovery
	}
	state, current, err := a.group.SnapshotObserved()
	if ctx.Err() != nil {
		return configpoc.RoutedReceiptV1{}, "", configpoc.ErrRecovery
	}
	return configpoc.RoutedReceiptV1{Phase: state.Phase, ID: state.ID, Previous: state.Previous, Target: state.Target, Deadline: state.Deadline}, current, err
}

func (a *RoutedAuthority) Match(ctx context.Context, p configpoc.RoutedSelectedPlanV1, side string) error {
	if err := a.install(p); err != nil {
		return err
	}
	reference := p.Transition().BeforeOwned
	if side == "target" {
		reference = p.Transition().TargetOwned
	} else if side != "before" {
		return configpoc.ErrRecovery
	}
	return a.engine.MatchOwned(ctx, reference)
}

func (a *RoutedAuthority) Arm(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	if err := a.install(p); err != nil {
		return err
	}
	previous, target := p.Bundles()
	if p.Cold() {
		return a.group.ArmBootstrapUntilLease(ctx, p.Transition(), p.Lease(), target, p.Deadline())
	}
	return a.group.ArmUntilLease(ctx, p.Transition(), p.Lease(), *previous, target, p.Deadline())
}

func (a *RoutedAuthority) receipt(ctx context.Context, p configpoc.RoutedSelectedPlanV1) (nftguardian.State, error) {
	if err := a.install(p); err != nil {
		return nftguardian.State{}, err
	}
	state, _, err := a.group.SnapshotObserved()
	_, target := p.Bundles()
	if ctx.Err() != nil || err != nil || state.ID != p.Lease() || state.Target != target.Composite.Hash || !state.Deadline.Equal(p.Deadline()) {
		return nftguardian.State{}, configpoc.ErrRecovery
	}
	return state, nil
}

func (a *RoutedAuthority) Apply(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	state, err := a.receipt(ctx, p)
	if err != nil {
		return err
	}
	_, target := p.Bundles()
	return a.group.ApplyLease(ctx, p.Transition(), target, state)
}
func (a *RoutedAuthority) Confirm(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	state, err := a.receipt(ctx, p)
	if err != nil {
		return err
	}
	return a.group.ConfirmLease(ctx, p.Transition(), state)
}
func (a *RoutedAuthority) Recover(ctx context.Context, p configpoc.RoutedSelectedPlanV1) error {
	state, err := a.receipt(ctx, p)
	if err != nil {
		if p.Resolution() != "recovery-before" {
			return err
		}
		previous, target := p.Bundles()
		if err = a.engine.RecoverPlan(ctx, p.Transition(), previous, target, p.Deadline(), p.Scope().Identity); err != nil {
			return err
		}
		// Recovery is already selected but not final. Restore its exact before
		// image; do not manufacture an idle/finality witness before publication.
		return a.engine.RestoreOwned(ctx, p.Transition().BeforeOwned)
	}
	return a.group.RecoverLease(p.Transition(), state)
}
func (a *RoutedAuthority) Bootstrap(ctx context.Context, p configpoc.RoutedSelectedPlanV1, started time.Time) error {
	if err := a.install(p); err != nil {
		return err
	}
	if !p.Cold() || !p.Deadline().Equal(started.Add(10*time.Second)) || p.Lease() != p.Transition().Operation {
		return configpoc.ErrRecovery
	}
	_, target := p.Bundles()
	state, current, err := a.group.SnapshotObserved()
	if err == nil && state.ID == p.Lease() && state.Target == target.Composite.Hash && state.Previous == "" && state.Deadline.Equal(p.Deadline()) {
		switch state.Phase {
		case "pending", "idle":
			if current == target.Composite.Hash && a.engine.MatchOwned(ctx, p.Transition().TargetOwned) == nil {
				return nil
			}
		case "armed":
			return a.group.ApplyLease(ctx, p.Transition(), target, state)
		}
		return configpoc.ErrRecovery
	}
	return a.group.BootstrapStartup(ctx, p.Transition(), target, started)
}
