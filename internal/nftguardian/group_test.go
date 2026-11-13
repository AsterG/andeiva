package nftguardian

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/routednft"
)

func groupBundle(t testing.TB, deny bool) configpoc.RoutedActivationBundleV1 {
	t.Helper()
	policy := routednft.LabPolicy()
	if deny {
		policy.Rules[0].Action = "deny"
	}
	firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		t.Fatal(err)
	}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := configpoc.NewRoutedActivationBundleV1(firewall, local)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}
func groupPlan(id, before, target string) configpoc.RoutedTransitionV1 {
	return configpoc.RoutedTransitionV1{Version: 1, Operation: id, Previous: strings.Repeat("1", 64), Target: strings.Repeat("2", 64), BeforeOwned: before, TargetOwned: target, Dependencies: strings.Repeat("3", 64)}
}

type groupTestEngine struct {
	cancel                                              context.CancelFunc
	mu                                                  sync.Mutex
	hash, owned                                         string
	plan                                                configpoc.RoutedTransitionV1
	previous, target                                    string
	deadline                                            time.Time
	selected, cold, failApply, failRestore, badReadback bool
	delay                                               time.Duration
	applyCount, restoreCount                            int
	appliedDeadline                                     time.Time
	restoreContextErr                                   error
}

func (e *groupTestEngine) selectPlan(p configpoc.RoutedTransitionV1, previous, target string, d time.Time, cold bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.plan, e.previous, e.target, e.deadline, e.cold, e.selected = p, previous, target, d, cold, true
}
func (e *groupTestEngine) ValidatePlan(ctx context.Context, p configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, d time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || !e.selected || p != e.plan || !d.Equal(e.deadline) || target.Composite.Hash != e.target || (previous == nil) != e.cold {
		return ErrLease
	}
	if previous != nil && previous.Composite.Hash != e.previous {
		return ErrLease
	}
	return nil
}
func (e *groupTestEngine) Apply(ctx context.Context, target configpoc.RoutedActivationBundleV1) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.applyCount++
	e.appliedDeadline, _ = ctx.Deadline()
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	e.hash, e.owned = target.Composite.Hash, e.plan.TargetOwned
	if e.cancel != nil {
		e.cancel()
	}
	if e.badReadback {
		e.owned = strings.Repeat("f", 64)
	}
	if e.failApply {
		return ErrLease
	}
	return ctx.Err()
}
func (e *groupTestEngine) Current() string { e.mu.Lock(); defer e.mu.Unlock(); return e.hash }
func (e *groupTestEngine) ObserveOwned(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return e.owned, nil
}
func (e *groupTestEngine) RestoreOwned(ctx context.Context, digest string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.restoreCount++
	e.restoreContextErr = ctx.Err()
	if ctx.Err() != nil || e.failRestore || !e.selected || digest != e.plan.BeforeOwned {
		return ErrLease
	}
	e.hash, e.owned = e.previous, digest
	return nil
}
func coldGroup(t testing.TB) (*Group, *groupTestEngine, configpoc.RoutedActivationBundleV1, configpoc.RoutedTransitionV1, time.Time) {
	t.Helper()
	target := groupBundle(t, false)
	started := time.Now().UTC()
	p := groupPlan("boot", strings.Repeat("a", 64), strings.Repeat("b", 64))
	e := &groupTestEngine{owned: p.BeforeOwned}
	e.selectPlan(p, "", target.Composite.Hash, started.Add(10*time.Second), true)
	g, err := NewGroup(e)
	if err != nil {
		t.Fatal(err)
	}
	return g, e, target, p, started
}

func TestGroupColdBootstrapUsesActualOwnedBaselineAndOneAbsoluteLease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, e, target, p, started := coldGroup(t)
		defer g.Close()
		if target.Composite.Hash == target.Firewall.Hash {
			t.Fatal("component impersonates composite")
		}
		if err := g.BootstrapStartup(context.Background(), p, target, started); err != nil {
			t.Fatal(err)
		}
		s, h, err := g.SnapshotObserved()
		if err != nil || s.Phase != "pending" || s.Previous != "" || s.Target != target.Composite.Hash || h != target.Composite.Hash || !s.Deadline.Equal(started.Add(10*time.Second)) || !e.appliedDeadline.Equal(s.Deadline) || e.applyCount != 1 {
			t.Fatal("unscoped/false before-state bootstrap", s, h, err)
		}
		target.Firewall.Config.Routed.Rules[0].Action = "deny"
		if _, err := configpoc.CanonicalRoutedActivationBundleV1(g.target); err != nil {
			t.Fatal("bundle aliases caller", err)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		s, h, err = g.SnapshotObserved()
		if err != nil || s.Phase != "expired" || h != "" || e.owned != p.BeforeOwned || e.restoreCount != 1 || e.restoreContextErr != nil {
			t.Fatal("cold expiry did not restore actual baseline", s, h, err)
		}
		if g.ConfirmLease(context.Background(), p, s) == nil {
			t.Fatal("expired bootstrap confirmed")
		}
	})
}

func TestLegacyGuardianStillRejectsRoutedBundleMasqueradingAsRevision(t *testing.T) {
	bundle := groupBundle(t, false)
	engine := configpoc.NewSimEngine("legacy-boundary")
	g := NewRestricted(engine)
	defer g.Close()
	for _, hash := range []string{bundle.Firewall.Hash, bundle.Composite.Hash} {
		if g.Bootstrap(context.Background(), configpoc.Revision{Hash: hash, Config: bundle.Firewall.Config}) == nil || engine.Current() != "" {
			t.Fatal("legacy type boundary widened")
		}
	}
}

func TestGroupBootstrapRefusesUnselectedForeignOrExpiredPlansWithoutEffects(t *testing.T) {
	for _, kind := range []string{"unselected", "foreign-owned", "future-start", "expired-start", "reset-start", "forged-bundle", "forged-plan"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g, e, target, p, started := coldGroup(t)
				defer g.Close()
				switch kind {
				case "unselected":
					e.selected = false
				case "foreign-owned":
					e.owned = strings.Repeat("c", 64)
				case "future-start":
					started = started.Add(time.Second)
				case "expired-start":
					started = started.Add(-11 * time.Second)
				case "reset-start":
					time.Sleep(time.Second)
					started = time.Now().UTC()
				case "forged-bundle":
					target.Composite.Hash = target.Firewall.Hash
				case "forged-plan":
					p.Dependencies = strings.Repeat("d", 64)
				}
				if g.BootstrapStartup(context.Background(), p, target, started) == nil || e.applyCount != 0 || e.restoreCount != 0 || g.timer != nil || g.state.Phase != "bootstrap" {
					t.Fatal("untrusted bootstrap acquired authority")
				}
			})
		})
	}
}

func TestGroupFailedApplyOrReadbackCompensatesBeforeReturning(t *testing.T) {
	for _, kind := range []string{"apply-error", "readback", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				g, e, target, p, started := coldGroup(t)
				defer g.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				switch kind {
				case "apply-error":
					e.failApply = true
				case "readback":
					e.badReadback = true
				case "canceled":
					e.cancel = cancel
				}
				if g.BootstrapStartup(ctx, p, target, started) == nil || e.hash != "" || e.owned != p.BeforeOwned || g.state.Phase != "expired" || e.restoreContextErr != nil {
					t.Fatal("partial group result escaped compensation", g.state)
				}
			})
		})
	}
}

func TestGroupRestoreUncertaintyFences(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, e, target, p, started := coldGroup(t)
		defer g.Close()
		e.failApply, e.failRestore = true, true
		if g.BootstrapStartup(context.Background(), p, target, started) == nil || g.state.Phase != "blocked" {
			t.Fatal("uncertainty not fenced")
		}
		if _, _, err := g.SnapshotObserved(); err == nil {
			t.Fatal("blocked state certified")
		}
		if g.BootstrapStartup(context.Background(), p, target, started) == nil {
			t.Fatal("blocked bootstrap retried")
		}
	})
}

func TestGroupApplyCannotOutliveOriginalStartupDeadline(t *testing.T) {
	g, e, target, p, _ := coldGroup(t)
	defer g.Close()
	started := time.Now().UTC().Add(-8 * time.Second)
	e.selectPlan(p, "", target.Composite.Hash, started.Add(10*time.Second), true)
	e.delay = 2100 * time.Millisecond
	if g.BootstrapStartup(context.Background(), p, target, started) == nil || e.applyCount != 1 || e.hash != "" || e.owned != p.BeforeOwned || g.state.Phase != "expired" || e.restoreContextErr != nil {
		t.Fatal("late target escaped startup deadline", g.state)
	}
}

func confirmedGroup(t testing.TB) (*Group, *groupTestEngine, configpoc.RoutedActivationBundleV1) {
	g, e, target, p, started := coldGroup(t)
	if err := g.BootstrapStartup(context.Background(), p, target, started); err != nil {
		t.Fatal(err)
	}
	s, _, err := g.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ConfirmLease(context.Background(), p, s); err != nil {
		t.Fatal(err)
	}
	return g, e, target
}

func TestGroupWholeScopeCASAndLostConfirm(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, e, previous := confirmedGroup(t)
		defer g.Close()
		target := groupBundle(t, true)
		p := groupPlan("change", e.owned, strings.Repeat("c", 64))
		deadline := time.Now().UTC().Add(30 * time.Second)
		e.selectPlan(p, previous.Composite.Hash, target.Composite.Hash, deadline, false)
		if err := g.ArmUntil(context.Background(), p, previous, target, deadline); err != nil {
			t.Fatal(err)
		}
		s, h, err := g.SnapshotObserved()
		if err != nil || h != previous.Composite.Hash {
			t.Fatal(s, h, err)
		}
		for _, kind := range []string{"id", "previous", "target", "deadline", "artifact"} {
			bad, badPlan := s, p
			switch kind {
			case "id":
				bad.ID = "foreign"
			case "previous":
				bad.Previous = target.Composite.Hash
			case "target":
				bad.Target = previous.Composite.Hash
			case "deadline":
				bad.Deadline = bad.Deadline.Add(time.Nanosecond)
			case "artifact":
				badPlan.BeforeOwned = strings.Repeat("d", 64)
			}
			before := e.applyCount
			if g.ApplyLease(context.Background(), badPlan, target, bad) == nil || e.applyCount != before || g.RecoverLease(badPlan, bad) == nil {
				t.Fatal("foreign CAS changed group", kind)
			}
		}
		if err := g.ApplyLease(context.Background(), p, target, s); err != nil {
			t.Fatal(err)
		}
		pending, _, err := g.SnapshotObserved()
		if err != nil {
			t.Fatal(err)
		}
		if g.ConfirmLease(context.Background(), p, pending) != nil || g.ConfirmLease(context.Background(), p, pending) != nil {
			t.Fatal("exact lost confirm did not reconcile")
		}
		if g.RecoverLease(p, pending) == nil {
			t.Fatal("confirmed group blindly rolled back")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if e.hash != target.Composite.Hash || g.state.Phase != "idle" {
			t.Fatal("confirmed timer changed components")
		}
	})
}

func TestGroupZeroAndNilCloseReject(t *testing.T) {
	var absent *Group
	if !errors.Is(absent.Close(), ErrLease) || !errors.Is((&Group{}).Close(), ErrLease) {
		t.Fatal("invalid group accepted")
	}
}

func TestGroupColdConfirmedLeaseUsesOriginalPendingDeadlineAndDistinctID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, e, target, plan, _ := coldGroup(t)
		defer g.Close()
		deadline := time.Now().UTC().Add(90 * time.Second)
		e.selectPlan(plan, "", target.Composite.Hash, deadline, true)
		time.Sleep(25 * time.Second)
		if err := g.ArmBootstrapUntilLease(context.Background(), plan, "confirmed-lease", target, deadline); err != nil {
			t.Fatal(err)
		}
		state, hash, err := g.SnapshotObserved()
		if err != nil || hash != "" || state.ID != "confirmed-lease" || state.ID == plan.Operation || state.Previous != "" || !state.Deadline.Equal(deadline) || e.applyCount != 0 {
			t.Fatal("cold confirmed arm invented previous or applied", state, hash, err)
		}
		bad := state
		bad.ID = plan.Operation
		if g.ApplyLease(context.Background(), plan, target, bad) == nil || e.applyCount != 0 {
			t.Fatal("operation ID substituted for lease")
		}
		if g.ApplyLease(context.Background(), plan, target, state) != nil {
			t.Fatal("apply")
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		observed, current, err := g.SnapshotObserved()
		if err != nil || observed.Phase != "pending" || current != target.Composite.Hash {
			t.Fatal("boot ten-second timer replaced confirmed deadline")
		}
		time.Sleep(55 * time.Second)
		synctest.Wait()
		observed, current, err = g.SnapshotObserved()
		owned, ownedErr := e.ObserveOwned(context.Background())
		if err != nil || ownedErr != nil || observed.Phase != "expired" || current != "" || owned != plan.BeforeOwned {
			t.Fatal("original confirmed expiry did not restore physical before")
		}
	})
}

func TestGroupColdConfirmedRejectsChangedScopeDeadlineAndExistingCurrent(t *testing.T) {
	for _, kind := range []string{"deadline", "before", "current", "lease", "nonutc", "too-long"} {
		synctest.Test(t, func(t *testing.T) {
			g, e, target, plan, _ := coldGroup(t)
			defer g.Close()
			deadline := time.Now().UTC().Add(time.Minute)
			e.selectPlan(plan, "", target.Composite.Hash, deadline, true)
			lease := "lease"
			switch kind {
			case "deadline":
				deadline = deadline.Add(time.Nanosecond)
			case "before":
				e.owned = strings.Repeat("f", 64)
			case "current":
				e.hash = target.Composite.Hash
			case "lease":
				lease = ""
			case "nonutc":
				deadline = deadline.In(time.FixedZone("offset", 3600))
			case "too-long":
				deadline = time.Now().UTC().Add(121 * time.Second)
			}
			if g.ArmBootstrapUntilLease(context.Background(), plan, lease, target, deadline) == nil || e.applyCount != 0 || g.state.Phase != "bootstrap" {
				t.Fatal("invalid cold confirmed scope armed", kind)
			}
		})
	}
}

func TestGroupSameHashStillOwnsOneReceipt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g, e, previous := confirmedGroup(t)
		defer g.Close()
		p := groupPlan("same", e.owned, e.owned)
		deadline := time.Now().UTC().Add(time.Second)
		e.selectPlan(p, previous.Composite.Hash, previous.Composite.Hash, deadline, false)
		if g.ArmUntil(context.Background(), p, previous, previous, deadline) != nil {
			t.Fatal("arm")
		}
		s, _, err := g.SnapshotObserved()
		if err != nil {
			t.Fatal(err)
		}
		before := e.applyCount
		if g.ApplyLease(context.Background(), p, previous, s) != nil || e.applyCount != before || g.state.Phase != "pending" {
			t.Fatal("same hash lost receipt")
		}
		if g.ConfirmLease(context.Background(), p, s) != nil {
			t.Fatal("confirm same hash")
		}
	})
}

func TestGroupConfirmAndRecoverSerializeAsOneAuthority(t *testing.T) {
	g, e, previous := confirmedGroup(t)
	defer g.Close()
	target := groupBundle(t, true)
	p := groupPlan("concurrent", e.owned, strings.Repeat("c", 64))
	deadline := time.Now().UTC().Add(30 * time.Second)
	e.selectPlan(p, previous.Composite.Hash, target.Composite.Hash, deadline, false)
	if err := g.ArmUntil(context.Background(), p, previous, target, deadline); err != nil {
		t.Fatal(err)
	}
	s, _, err := g.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	if err := g.ApplyLease(context.Background(), p, target, s); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() { <-start; results <- g.ConfirmLease(context.Background(), p, s) }()
	go func() { <-start; results <- g.RecoverLease(p, s) }()
	close(start)
	a, b := <-results, <-results
	if (a == nil) == (b == nil) {
		t.Fatal("two authorities won or neither succeeded", a, b)
	}
	if a != nil && !errors.Is(a, ErrLease) || b != nil && !errors.Is(b, ErrLease) {
		t.Fatal(a, b)
	}
	if _, _, err := g.SnapshotObserved(); err != nil {
		t.Fatal("winning outcome not verified", err)
	}
}
