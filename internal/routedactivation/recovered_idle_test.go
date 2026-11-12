package routedactivation

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func recoveredIdleFixture(t testing.TB, target bool) (assembledFixture, *Engine, *nftguardian.Group) {
	t.Helper()
	f := assembleFixture(t)
	t.Cleanup(func() { _ = f.group.Close() })
	ctx := context.Background()
	deadline := f.started.Add(10 * time.Second)
	if target && (f.engine.ValidatePlan(ctx, f.plan, nil, f.target, deadline) != nil || f.engine.Apply(ctx, f.target) != nil) {
		t.Fatal("establish retained kernel target without surviving controller memory")
	}
	identity := networkexecutor.OwnedNamespaceIdentity{UID: 1001, GID: 1002, Namespace: 200, Host: 100, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}
	network := &networkFixture{snapshot: f.network.snapshot, active: f.network.active, identity: identity, before: f.network.before}
	options := f.engine.options
	options.ResolveRecoveredIdle = func(ctx context.Context, plan configpoc.RoutedTransitionV1, original time.Time) (nftguardian.RecoveredIdleV1, error) {
		if ctx.Err() != nil || plan != f.plan || !original.Equal(deadline) {
			return nftguardian.RecoveredIdleV1{}, ErrState
		}
		witness := nftguardian.RecoveredIdleV1{Plan: plan, OwnedRef: plan.BeforeOwned, Deadline: deadline, Scope: identity, Finality: nftguardian.BeforeRestored}
		if target {
			witness.Bundle, witness.OwnedRef, witness.Finality = &f.target, plan.TargetOwned, nftguardian.TargetConfirmed
		}
		return witness, nil
	}
	restarted, err := New(f.kernel, network, f.listeners, options)
	if err != nil || restarted.RecoverPlan(ctx, f.plan, nil, f.target, deadline, identity) != nil {
		t.Fatal("authenticate original selected Work", err)
	}
	group, err := nftguardian.NewGroup(restarted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Close() })
	return f, restarted, group
}

func TestRecoveredConfirmedIdleHasNoPendingReceiptOrReplacementTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, engine, group := recoveredIdleFixture(t, true)
		before := len(f.kernel.batches)
		if group.RecoverIdle(context.Background(), f.plan) != nil || len(f.kernel.batches) != before {
			t.Fatal("finalized idle reconstruction made effects")
		}
		state, hash, err := group.SnapshotObserved()
		if err != nil || state.Phase != "idle" || state.ID != "" || !state.Deadline.IsZero() || hash != f.target.Composite.Hash {
			t.Fatal("confirmed state invented a pending lease", state, hash, err)
		}
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		state, hash, err = group.SnapshotObserved()
		if err != nil || hash != f.target.Composite.Hash || state.Phase != "idle" || engine.Current() != hash || len(f.kernel.batches) != before {
			t.Fatal("a replacement timer changed confirmed kernel state")
		}
		if group.RecoverIdle(context.Background(), f.plan) == nil {
			t.Fatal("nonfresh group adopted finality again")
		}
	})
}

func TestRecoveredColdBeforeAllowsNewOperationButRejectsOldRearm(t *testing.T) {
	f, engine, group := recoveredIdleFixture(t, false)
	ctx := context.Background()
	if group.RecoverIdle(ctx, f.plan) != nil {
		t.Fatal("restore finalized physical before")
	}
	state, hash, err := group.SnapshotObserved()
	if err != nil || state.Phase != "idle" || hash != "" {
		t.Fatal("cold before promoted a saved but ineffective bundle", err)
	}
	if group.ArmBootstrapUntilLease(ctx, f.plan, "new-lease-old-operation", f.target, time.Now().UTC().Add(time.Minute)) == nil {
		t.Fatal("old pending operation was rearmed")
	}
	plan := f.plan
	plan.Operation = "new-cold-operation"
	plan.BeforeOwned, plan.TargetOwned = strings.Repeat("a", 64), strings.Repeat("b", 64)
	prepared, err := engine.Prepare(ctx, f.target)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(30 * time.Second)
	engine.options.ResolvePlan = func(ctx context.Context, actual configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, actualDeadline time.Time) (PreparationV1, error) {
		if ctx.Err() != nil || actual != plan || previous != nil || target.Composite.Hash != f.target.Composite.Hash || !actualDeadline.Equal(deadline) {
			return PreparationV1{}, ErrState
		}
		return prepared, nil
	}
	if group.ArmBootstrapUntilLease(ctx, plan, "distinct-new-lease", f.target, deadline) != nil {
		t.Fatal("new selected Work could not arm on verified cold before")
	}
	state, _, err = group.SnapshotObserved()
	if err != nil || group.ApplyLease(ctx, plan, f.target, state) != nil || group.ConfirmLease(ctx, plan, state) != nil {
		t.Fatal("new cold commit failed", err)
	}
}

func TestRecoveredIdleRejectsForgedFinalityScopeDeadlineAndUnknownKernel(t *testing.T) {
	for _, fault := range []string{"pending-target", "before-for-target", "scope", "deadline", "refs", "bundle", "kernel"} {
		f, engine, group := recoveredIdleFixture(t, true)
		resolve := engine.options.ResolveRecoveredIdle
		engine.options.ResolveRecoveredIdle = func(ctx context.Context, plan configpoc.RoutedTransitionV1, deadline time.Time) (nftguardian.RecoveredIdleV1, error) {
			witness, err := resolve(ctx, plan, deadline)
			switch fault {
			case "pending-target":
				witness.Finality = "pending-target"
			case "before-for-target":
				witness.Finality, witness.OwnedRef, witness.Bundle = nftguardian.BeforeRestored, plan.BeforeOwned, nil
			case "scope":
				witness.Scope.Namespace++
			case "deadline":
				witness.Deadline = deadline.Add(time.Nanosecond)
			case "refs":
				witness.OwnedRef = strings.Repeat("f", 64)
			case "bundle":
				witness.Bundle = nil
			}
			return witness, err
		}
		if fault == "kernel" {
			delete(f.kernel.objects, RoutedTable)
		}
		before := len(f.kernel.batches)
		if group.RecoverIdle(context.Background(), f.plan) == nil || len(f.kernel.batches) != before {
			t.Fatal("untrusted recovered finality was adopted", fault)
		}
		state, _, _ := group.SnapshotObserved()
		if state.Phase != "" && state.Phase != "bootstrap" {
			t.Fatal("rejected witness created idle/pending state", fault)
		}
		if fault == "kernel" && !engine.fenced {
			t.Fatal("unknown kernel readback did not fence")
		}
	}
}
