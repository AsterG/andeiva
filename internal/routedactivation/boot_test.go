package routedactivation

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func coldBootFixture(t testing.TB) (assembledFixture, configpoc.RoutedActivationBundleV1) {
	t.Helper()
	f := assembleFixture(t)
	t.Cleanup(func() { _ = f.group.Close() })
	delete(f.kernel.objects, LegacyTable)
	legacy := knownLegacyRules(t)
	empty := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{}, Services: []localpolicy.Service{}}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &empty})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := configpoc.NewRoutedActivationBundleV1(legacy, local)
	if err != nil {
		t.Fatal(err)
	}
	var prepared PreparationV1
	engine, err := New(f.kernel, f.network, f.listeners, Options{Legacy: legacy, ResolvePlan: func(ctx context.Context, plan configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, deadline time.Time) (PreparationV1, error) {
		if ctx.Err() != nil || plan != f.plan || previous != nil || target.Composite.Hash != f.target.Composite.Hash || !deadline.Equal(f.started.Add(10*time.Second)) {
			return PreparationV1{}, ErrState
		}
		// Represents the selected Boot/SystemBundle token; no effect precedes it.
		return prepared, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = engine.PrepareColdBoot(context.Background(), f.target, saved)
	if err != nil || len(f.kernel.batches) != 0 || f.network.calls != 0 || prepared.Before.LegacyFirewall.Presence != Absent || prepared.Before.RoutedFirewall.Presence != Absent || prepared.Before.LocalServices.Presence != Absent {
		t.Fatal("cold Boot fabricated its before or made effects", err)
	}
	prospective := prepared.Before
	prospective.LegacyFirewall = TableStateV1{Presence: Present, Revision: &legacy}
	baseline := BaselineV1{Saved: saved, Owned: prospective, Dependencies: prepared.Dependencies}
	engine.options.ResolveBaseline = func(ctx context.Context, target configpoc.RoutedActivationBundleV1) (BaselineV1, error) {
		if ctx.Err() != nil || target.Composite.Hash != saved.Composite.Hash {
			return BaselineV1{}, ErrState
		}
		return baseline, nil
	}
	group, err := nftguardian.NewGroup(engine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Close() })
	f.engine, f.group, f.prepared = engine, group, prepared
	return f, saved
}

func TestColdBootActualAbsenceExpiresToAbsenceNotProspectiveSavedFour(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, _ := coldBootFixture(t)
		if f.group.BootstrapStartup(context.Background(), f.plan, f.target, f.started) != nil {
			t.Fatal("selected cold Boot")
		}
		f.engine.mu.Lock()
		_, exists := f.kernel.objects[LegacyTable]
		f.engine.mu.Unlock()
		if exists {
			t.Fatal("prospective legacy was silently realized")
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		state, hash, err := f.group.SnapshotObserved()
		if err != nil || state.Phase != "expired" || hash != "" || f.engine.MatchOwned(context.Background(), f.plan.BeforeOwned) != nil {
			t.Fatal("Boot did not restore actual absent before", state, hash, err)
		}
		f.engine.mu.Lock()
		tables, active, listeners := len(f.kernel.objects), f.network.active, len(f.listeners.actual)
		f.engine.mu.Unlock()
		if tables != 0 || active || listeners != 0 {
			t.Fatal("automatic Boot recovery realized saved4 or left resources")
		}
	})
}

func TestColdBootProspectiveBaselineOnlyRealizesOnExplicitSavedFourCommit(t *testing.T) {
	f, saved := coldBootFixture(t)
	confirmFixture(t, f)
	if _, exists := f.kernel.objects[LegacyTable]; exists {
		t.Fatal("saved4 was applied before explicit operation")
	}
	plan, receipt := armFixtureOperation(t, f, "explicit-saved-four", f.target, saved)
	if f.group.ConfirmLease(context.Background(), plan, receipt) != nil || f.engine.Current() != saved.Composite.Hash || f.engine.MatchOwned(context.Background(), plan.TargetOwned) != nil {
		t.Fatal("explicit saved4 did not restore its authorized prospective target")
	}
}

func TestColdBootReadOnlyPreparationRejectsExistingTablesAndWrongHistory(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	saved := installOriginalBaseline(t, f)
	engine, err := New(f.kernel, f.network, f.listeners, f.engine.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.PrepareColdBoot(context.Background(), f.target, saved); err == nil || len(f.kernel.batches) != 0 || f.network.calls != 0 {
		t.Fatal("existing table was adopted as a new absent namespace")
	}
	delete(f.kernel.objects, LegacyTable)
	wrong := saved
	wrong.Firewall = knownLegacyRules(t)
	wrong, err = configpoc.NewRoutedActivationBundleV1(wrong.Firewall, wrong.LocalServices)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.PrepareColdBoot(context.Background(), f.target, wrong); err == nil || len(f.kernel.batches) != 0 || f.network.calls != 0 {
		t.Fatal("unselected saved4 history accepted")
	}
}
