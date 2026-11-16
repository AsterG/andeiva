package nftguardian

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// GroupEngine is supplied by trusted assembly, never by an administrative body.
// ValidatePlan MUST verify the selected durable intent, original deadline,
// lineage, artifact context and owned reservations. ValidShape is not authority.
// A nil previous denotes cold physical BeforeOwned, NOT effective PreviousRunning.
// Current and ObserveOwned must perform bounded semantic readback, not cached
// success. RestoreOwned accepts only this validated plan's exact owned artifact.
type GroupEngine interface {
	ValidatePlan(context.Context, configpoc.RoutedTransitionV1, *configpoc.RoutedActivationBundleV1, configpoc.RoutedActivationBundleV1, time.Time) error
	Apply(context.Context, configpoc.RoutedActivationBundleV1) error
	Current() string
	ObserveOwned(context.Context) (string, error)
	RestoreOwned(context.Context, string) error
}

type RecoveredFinality string

const (
	BeforeRestored  RecoveredFinality = "before-restored"
	TargetConfirmed RecoveredFinality = "confirmed-target"
)

// RecoveredIdleV1 is an internal trusted-engine witness, never a caller/wire DTO.
// The engine must authenticate original Work scope and durable selected finality;
// field shape or a supplied enum does not confer that authority.
type RecoveredIdleV1 struct {
	Plan     configpoc.RoutedTransitionV1
	Bundle   *configpoc.RoutedActivationBundleV1
	OwnedRef string
	Deadline time.Time
	Scope    networkexecutor.OwnedNamespaceIdentity
	Finality RecoveredFinality
}

// Group uses the same receipt/timer/CAS core as Guardian for one complete bundle.
// It owns no journal or storage. Assembly must not enable it without a real
// selected-plan validator and exclusive component writers under this authority.
type Group struct {
	leaseCore
	engine           GroupEngine
	plan             configpoc.RoutedTransitionV1
	previous, target configpoc.RoutedActivationBundleV1
	cold             bool
	recoveredOwned   string
}

func NewGroup(engine GroupEngine) (*Group, error) {
	if engine == nil {
		return nil, ErrLease
	}
	return &Group{engine: engine, leaseCore: leaseCore{state: State{Phase: "bootstrap"}, restricted: true, maxTTL: 120 * time.Second}}, nil
}

func ownedDigest(hash string) bool {
	if len(hash) != 64 || hash != strings.ToLower(hash) {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

func (g *Group) ownedMatches(ctx context.Context, want string) bool {
	// Contextual store refs may differ for equal physical payloads. A concrete
	// engine can verify the exact selected ref without inventing one digest for
	// both roles. Existing engines retain their literal digest comparison.
	if matcher, ok := g.engine.(interface {
		MatchOwned(context.Context, string) error
	}); ok {
		return ownedDigest(want) && matcher.MatchOwned(ctx, want) == nil
	}
	actual, err := g.engine.ObserveOwned(ctx)
	return err == nil && ownedDigest(want) && actual == want
}

// BootstrapStartup arms BEFORE applying a cold target. The original Started is
// obtained from the durable boot record by ValidatePlan; it is never reset here.
// Its signature intentionally does not satisfy the legacy relative bootstrap API.
func (g *Group) BootstrapStartup(ctx context.Context, plan configpoc.RoutedTransitionV1, target configpoc.RoutedActivationBundleV1, started time.Time) error {
	if g == nil || ctx == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.engine == nil || g.state.Phase != "bootstrap" || !plan.ValidShape() || started.IsZero() || started.Location() != time.UTC || time.Now().Before(started) {
		return ErrLease
	}
	target, err := configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil {
		return ErrLease
	}
	deadline := started.Add(10 * time.Second)
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if bounded.Err() != nil || g.engine.Current() != "" || g.engine.ValidatePlan(bounded, plan, nil, target, deadline) != nil || !g.ownedMatches(bounded, plan.BeforeOwned) || bounded.Err() != nil {
		return ErrLease
	}
	if err := g.armUntilLocked(plan.Operation, "", target.Composite.Hash, deadline, func() {
		g.plan, g.target, g.cold = plan, target, true
		g.recoveredOwned = ""
	}, g.expire); err != nil {
		return err
	}
	return g.applyBundleLocked(ctx, target)
}

// ArmUntil binds a complete before/target pair to one exact absolute receipt.
func (g *Group) ArmUntil(ctx context.Context, plan configpoc.RoutedTransitionV1, previous, target configpoc.RoutedActivationBundleV1, deadline time.Time) error {
	return g.ArmUntilLease(ctx, plan, plan.Operation, previous, target, deadline)
}

// ArmUntilLease keeps the coordinator's lease ID distinct from its operation ID.
func (g *Group) ArmUntilLease(ctx context.Context, plan configpoc.RoutedTransitionV1, leaseID string, previous, target configpoc.RoutedActivationBundleV1, deadline time.Time) error {
	if g == nil || ctx == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.engine == nil || g.state.Phase != "idle" || !plan.ValidShape() || len(leaseID) < 1 || len(leaseID) > 64 || deadline.IsZero() || deadline.Location() != time.UTC || deadline.Sub(time.Now()) > g.maxTTL {
		return ErrLease
	}
	previous, err := configpoc.CanonicalRoutedActivationBundleV1(previous)
	if err != nil {
		return ErrLease
	}
	target, err = configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil {
		return ErrLease
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if bounded.Err() != nil || g.engine.Current() != previous.Composite.Hash || g.engine.ValidatePlan(bounded, plan, &previous, target, deadline) != nil || !g.ownedMatches(bounded, plan.BeforeOwned) || bounded.Err() != nil {
		return ErrLease
	}
	return g.armUntilLocked(leaseID, previous.Composite.Hash, target.Composite.Hash, deadline, func() {
		g.plan, g.previous, g.target, g.cold = plan, previous, target, false
		g.recoveredOwned = ""
	}, g.expire)
}

// ArmBootstrapUntilLease arms a first confirmed activation without inventing an
// effective previous bundle. ValidatePlan must prove the selected Pending's
// original confirmed deadline/window; this method neither resets it nor applies
// the ten-second boot window. ApplyLease remains a separate, exact-CAS operation.
func (g *Group) ArmBootstrapUntilLease(ctx context.Context, plan configpoc.RoutedTransitionV1, leaseID string, target configpoc.RoutedActivationBundleV1, deadline time.Time) error {
	if g == nil || ctx == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	newCold := g.state.Phase == "bootstrap" || (g.state.Phase == "idle" && g.state.ID == "" && plan.Operation != g.plan.Operation)
	if g.closed || g.engine == nil || !newCold || !plan.ValidShape() || len(leaseID) < 1 || len(leaseID) > 64 || deadline.IsZero() || deadline.Location() != time.UTC || deadline.Sub(time.Now()) > g.maxTTL {
		return ErrLease
	}
	target, err := configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil {
		return ErrLease
	}
	bounded, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if bounded.Err() != nil || g.engine.Current() != "" || g.engine.ValidatePlan(bounded, plan, nil, target, deadline) != nil || !g.ownedMatches(bounded, plan.BeforeOwned) || bounded.Err() != nil {
		return ErrLease
	}
	return g.armUntilLocked(leaseID, "", target.Composite.Hash, deadline, func() {
		g.plan, g.previous, g.target, g.cold = plan, configpoc.RoutedActivationBundleV1{}, target, true
		g.recoveredOwned = ""
	}, g.expire)
}

// RecoverIdle initializes only a fresh helper's finalized idle state. It never
// recreates a pending receipt or starts a replacement confirmation window.
func (g *Group) RecoverIdle(ctx context.Context, plan configpoc.RoutedTransitionV1) error {
	if g == nil || ctx == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.engine == nil || g.state.Phase != "bootstrap" || g.state.ID != "" || g.timer != nil || !plan.ValidShape() || ctx.Err() != nil {
		return ErrLease
	}
	provider, ok := g.engine.(interface {
		RecoveredIdle(context.Context, configpoc.RoutedTransitionV1) (RecoveredIdleV1, error)
	})
	if !ok {
		return ErrLease
	}
	witness, err := provider.RecoveredIdle(ctx, plan)
	if err != nil || witness.Plan != plan || witness.Deadline.IsZero() || witness.Deadline.Location() != time.UTC || !ownedDigest(witness.OwnedRef) {
		return ErrLease
	}
	switch witness.Finality {
	case BeforeRestored:
		if witness.OwnedRef != plan.BeforeOwned {
			return ErrLease
		}
	case TargetConfirmed:
		if witness.OwnedRef != plan.TargetOwned || witness.Bundle == nil {
			return ErrLease
		}
	default:
		return ErrLease
	}
	var bundle configpoc.RoutedActivationBundleV1
	if witness.Bundle != nil {
		bundle, err = configpoc.CanonicalRoutedActivationBundleV1(*witness.Bundle)
		if err != nil {
			return ErrLease
		}
	}
	if g.engine.Current() != bundle.Composite.Hash || !g.ownedMatches(ctx, witness.OwnedRef) || ctx.Err() != nil {
		return ErrLease
	}
	g.plan, g.previous, g.target = plan, bundle, bundle
	g.cold, g.recoveredOwned, g.state = witness.Bundle == nil, witness.OwnedRef, State{Phase: "idle"}
	return nil
}

func (g *Group) previousHash() string {
	if g.cold {
		return ""
	}
	return g.previous.Composite.Hash
}

func (g *Group) applyBundleLocked(ctx context.Context, target configpoc.RoutedActivationBundleV1) error {
	return g.leaseCore.applyLocked(ctx, target.Composite.Hash, g.previousHash(), g.target.Composite.Hash, g.engine.Current, func(call context.Context) error {
		if err := g.engine.Apply(call, target); err != nil {
			return err
		}
		if !g.ownedMatches(call, g.plan.TargetOwned) || g.engine.Current() != target.Composite.Hash {
			return ErrLease
		}
		return nil
	}, g.expire, g.restore)
}

func (g *Group) ApplyLease(ctx context.Context, plan configpoc.RoutedTransitionV1, target configpoc.RoutedActivationBundleV1, expected State) error {
	if g == nil || ctx == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.engine == nil || g.plan != plan || !g.exactLeaseLocked(expected) || g.state.Phase != "armed" {
		return ErrLease
	}
	target, err := configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil || target.Composite.Hash != expected.Target {
		return ErrLease
	}
	// Same-content requests still require a receipt and complete target readback.
	if g.previousHash() == target.Composite.Hash && !g.ownedMatches(ctx, g.plan.TargetOwned) {
		_ = g.restore()
		return ErrLease
	}
	err = g.applyBundleLocked(ctx, target)
	if err == nil && !time.Now().Before(g.deadline) {
		g.expire()
		return ErrLease
	}
	return err
}

func (g *Group) ConfirmLease(ctx context.Context, plan configpoc.RoutedTransitionV1, expected State) error {
	if g == nil || ctx == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.engine == nil || ctx.Err() != nil || g.plan != plan || !g.exactLeaseLocked(expected) || !g.ownedMatches(ctx, g.plan.TargetOwned) {
		return ErrLease
	}
	return g.leaseCore.confirmLocked(expected.ID, expected.Target, g.target.Composite.Hash, func() string {
		hash := g.engine.Current()
		if ctx.Err() != nil {
			return ""
		}
		return hash
	}, g.expire)
}

// Recovery compares the artifact scope as well as the exact original receipt.
// Compensation uses an independent bounded context even after caller loss.
func (g *Group) RecoverLease(plan configpoc.RoutedTransitionV1, expected State) error {
	if g == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.engine == nil || g.plan != plan || g.previousHash() != expected.Previous || g.target.Composite.Hash != expected.Target || !g.recoveryLeaseLocked(expected) {
		return ErrLease
	}
	return g.leaseCore.recoverPreviousLocked(g.restore)
}

func (g *Group) restore() error {
	if g.state.Phase == "bootstrap" && g.plan.Version == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if g.engine.RestoreOwned(ctx, g.plan.BeforeOwned) != nil || !g.ownedMatches(ctx, g.plan.BeforeOwned) || g.engine.Current() != g.previousHash() {
		g.state.Phase = "blocked"
		return ErrLease
	}
	g.state.Phase = "expired"
	return nil
}
func (g *Group) expire() { g.expireLocked(g.restore) }

func (g *Group) observedLocked() (State, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return g.observedContextLocked(ctx, false)
}

type pairedGroupObserver interface {
	ObserveCurrentOwned(context.Context) (GroupObservationV1, error)
}

// GroupObservationV1 is trusted in-process evidence, never a request/wire DTO.
// MatchingOwned contains at most two exact contextual references proved by the
// SAME physical observation and immutable selected plan; no later matching I/O.
type GroupObservationV1 struct {
	Plan           configpoc.RoutedTransitionV1
	Current, Owned string
	MatchingOwned  [2]string
}

func (g *Group) observedContextLocked(ctx context.Context, requirePair bool) (State, string, error) {
	if ctx.Err() != nil || g.closed || g.engine == nil {
		return State{}, "", ErrLease
	}
	pair, paired := g.engine.(pairedGroupObserver)
	if requirePair && !paired {
		return State{}, "", ErrLease
	}
	var hash, owned string
	var observation GroupObservationV1
	if paired {
		var err error
		observation, err = pair.ObserveCurrentOwned(ctx)
		hash, owned = observation.Current, observation.Owned
		if err != nil || ctx.Err() != nil || !ownedDigest(owned) || hash != "" && !ownedDigest(hash) || observation.Plan != g.plan || observation.MatchingOwned[0] != owned {
			return State{}, "", ErrLease
		}
		for i, ref := range observation.MatchingOwned {
			if i == 1 && ref == "" {
				continue
			}
			if !ownedDigest(ref) || i == 1 && ref == owned {
				return State{}, "", ErrLease
			}
			if ref != g.plan.BeforeOwned && ref != g.plan.TargetOwned {
				// Unselected bootstrap can observe its exact physical baseline,
				// but cannot turn that reference into selected authority.
				if g.state.Phase != "bootstrap" || g.plan != (configpoc.RoutedTransitionV1{}) || i != 0 {
					return State{}, "", ErrLease
				}
			}
		}
	} else {
		hash = g.engine.Current()
	}
	match := func(want string) bool {
		if !paired {
			return g.ownedMatches(ctx, want)
		}
		if !ownedDigest(want) || ctx.Err() != nil {
			return false
		}
		return want == observation.MatchingOwned[0] || want == observation.MatchingOwned[1]
	}
	if g.state.Phase == "idle" && g.state.ID == "" && g.recoveredOwned != "" {
		if !match(g.recoveredOwned) || ctx.Err() != nil {
			return State{}, "", ErrLease
		}
		return g.snapshotLocked(hash, g.cold && hash == "")
	}
	before := g.cold && g.state.Phase != "pending" && hash == "" && match(g.plan.BeforeOwned)
	if g.state.Phase == "bootstrap" {
		if !paired {
			observed, err := g.engine.ObserveOwned(ctx)
			if err != nil || !ownedDigest(observed) {
				return State{}, "", ErrLease
			}
		}
	} else if hash != "" {
		want := ""
		if (g.state.Phase == "armed" || g.state.Phase == "expired" || (g.state.Phase == "idle" && g.state.ID == "")) && hash == g.previousHash() {
			want = g.plan.BeforeOwned
		} else if hash == g.target.Composite.Hash {
			want = g.plan.TargetOwned
		} else if hash == g.previousHash() {
			want = g.plan.BeforeOwned
		}
		if !match(want) {
			return State{}, "", ErrLease
		}
	}
	if ctx.Err() != nil {
		return State{}, "", ErrLease
	}
	return g.snapshotLocked(hash, before)
}

// SnapshotObservedContext requires a fresh paired observer; legacy Current has
// no cancellation contract. The caller's remaining budget includes lock wait.
func (g *Group) SnapshotObservedContext(ctx context.Context) (State, string, error) {
	if g == nil || ctx == nil {
		return State{}, "", ErrLease
	}
	for !g.mu.TryLock() {
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return State{}, "", ctx.Err()
		case <-timer.C:
		}
	}
	defer g.mu.Unlock()
	return g.observedContextLocked(ctx, true)
}

func (g *Group) SnapshotObserved() (State, string, error) {
	if g == nil {
		return State{}, "", ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.observedLocked()
}
func (g *Group) MatchObserved(plan configpoc.RoutedTransitionV1, expected State, hash string) error {
	if g == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	actual, current, err := g.observedLocked()
	if err != nil || g.plan != plan || actual.Phase != expected.Phase || actual.ID != expected.ID || actual.Previous != expected.Previous || actual.Target != expected.Target || !actual.Deadline.Equal(expected.Deadline) || current != hash {
		return ErrLease
	}
	return nil
}
func (g *Group) Close() error {
	if g == nil || g.engine == nil {
		return ErrLease
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closeLocked(g.restore)
}
