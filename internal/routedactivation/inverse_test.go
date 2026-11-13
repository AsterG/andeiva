package routedactivation

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/routednft"
)

func confirmFixture(t testing.TB, f assembledFixture) {
	t.Helper()
	if f.group.BootstrapStartup(context.Background(), f.plan, f.target, f.started) != nil {
		t.Fatal("bootstrap")
	}
	state, _, err := f.group.SnapshotObserved()
	if err != nil || f.group.ConfirmLease(context.Background(), f.plan, state) != nil {
		t.Fatal("confirm", err)
	}
}

func installOriginalBaseline(t testing.TB, f assembledFixture) configpoc.RoutedActivationBundleV1 {
	t.Helper()
	empty := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{}, Services: []localpolicy.Service{}}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", Rules: []configpoc.Rule{}, LocalServices: &empty})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := configpoc.NewRoutedActivationBundleV1(*f.prepared.Before.LegacyFirewall.Revision, local)
	if err != nil {
		t.Fatal(err)
	}
	baseline := BaselineV1{Saved: saved, Owned: f.prepared.Before, Dependencies: f.prepared.Dependencies}
	f.engine.options.ResolveBaseline = func(ctx context.Context, target configpoc.RoutedActivationBundleV1) (BaselineV1, error) {
		if ctx.Err() != nil || target.Composite.Hash != saved.Composite.Hash {
			return BaselineV1{}, ErrState
		}
		return baseline, nil
	}
	return saved
}

func armFixtureOperation(t testing.TB, f assembledFixture, id string, previous, target configpoc.RoutedActivationBundleV1) (configpoc.RoutedTransitionV1, nftguardian.State) {
	t.Helper()
	prepared, err := f.engine.Prepare(context.Background(), target)
	if err != nil {
		t.Fatal("prepare", err)
	}
	deadline := time.Now().UTC().Add(30 * time.Second)
	plan := configpoc.RoutedTransitionV1{Version: 1, Operation: id, Previous: strings.Repeat("1", 64), Target: strings.Repeat("2", 64), BeforeOwned: strings.Repeat("8", 64), TargetOwned: strings.Repeat("9", 64), Dependencies: strings.Repeat("7", 64)}
	f.engine.options.ResolvePlan = func(ctx context.Context, actual configpoc.RoutedTransitionV1, actualPrevious *configpoc.RoutedActivationBundleV1, actualTarget configpoc.RoutedActivationBundleV1, actualDeadline time.Time) (PreparationV1, error) {
		if ctx.Err() != nil || actual != plan || actualPrevious == nil || actualPrevious.Composite.Hash != previous.Composite.Hash || actualTarget.Composite.Hash != target.Composite.Hash || !actualDeadline.Equal(deadline) {
			return PreparationV1{}, ErrState
		}
		return prepared, nil
	}
	if err := f.group.ArmUntilLease(context.Background(), plan, "lease-"+id, previous, target, deadline); err != nil {
		t.Fatal("arm", err)
	}
	state, _, err := f.group.SnapshotObserved()
	if err != nil || f.group.ApplyLease(context.Background(), plan, target, state) != nil {
		t.Fatal("apply", err)
	}
	return plan, state
}

func TestInverseSavedFourExpiryRestoresSixAndNextOperationUsesActualSide(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := assembleFixture(t)
		defer f.group.Close()
		confirmFixture(t, f)
		saved := installOriginalBaseline(t, f)
		plan, receipt := armFixtureOperation(t, f, "inverse", f.target, saved)
		_, current, err := f.group.SnapshotObserved()
		f.engine.mu.Lock()
		active, listeners := f.network.active, len(f.listeners.actual)
		exactBaseline := f.engine.matches(context.Background(), f.prepared.Before, f.prepared.Dependencies)
		f.engine.mu.Unlock()
		if err != nil || current != saved.Composite.Hash || active || listeners != 0 || !exactBaseline {
			t.Fatal("saved4 was faked as configured6 or baseline was not restored", err)
		}
		time.Sleep(31 * time.Second)
		synctest.Wait()
		observed, current, err := f.group.SnapshotObserved()
		if err != nil || observed.Phase != "expired" || current != f.target.Composite.Hash || f.group.RecoverLease(plan, receipt) != nil {
			t.Fatal("inverse expiry failed to restore real6", observed, current, err)
		}
		// A recovered before-side is the actual source of the next operation;
		// the expired target4 must not remain an optimistic active selector.
		policy := *f.target.Firewall.Config.Routed
		policy.Rules = append([]routednft.Rule{}, policy.Rules...)
		policy.Rules[0].Action = "deny"
		firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
		if err != nil {
			t.Fatal(err)
		}
		target, err := configpoc.NewRoutedActivationBundleV1(firewall, f.target.LocalServices)
		if err != nil {
			t.Fatal(err)
		}
		next, receipt := armFixtureOperation(t, f, "after-recovery", f.target, target)
		if f.group.ConfirmLease(context.Background(), next, receipt) != nil || f.engine.Current() != target.Composite.Hash {
			t.Fatal("new operation could not use recovered6")
		}
	})
}

func TestConfirmedSavedFourCanForwardAgainToSameOwnedSix(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	confirmFixture(t, f)
	saved := installOriginalBaseline(t, f)
	plan, receipt := armFixtureOperation(t, f, "saved-four", f.target, saved)
	if f.group.ConfirmLease(context.Background(), plan, receipt) != nil || f.engine.Current() != saved.Composite.Hash {
		t.Fatal("confirm actual4")
	}
	plan, receipt = armFixtureOperation(t, f, "forward-six", saved, f.target)
	if f.group.ConfirmLease(context.Background(), plan, receipt) != nil || f.engine.Current() != f.target.Composite.Hash || !f.network.active || len(f.listeners.actual) != 1 {
		t.Fatal("4 to6 did not reconstruct target under deny")
	}
}

func TestInverseRejectsMissingForeignOrInconsistentOriginalBaseline(t *testing.T) {
	for _, fault := range []string{"missing", "saved", "snapshot", "local-enabled"} {
		f := assembleFixture(t)
		defer f.group.Close()
		confirmFixture(t, f)
		saved := installOriginalBaseline(t, f)
		original := f.engine.options.ResolveBaseline
		f.engine.options.ResolveBaseline = func(ctx context.Context, target configpoc.RoutedActivationBundleV1) (BaselineV1, error) {
			if fault == "local-enabled" {
				return BaselineV1{Saved: target, Owned: f.prepared.Before, Dependencies: f.prepared.Dependencies}, nil
			}
			baseline, err := original(ctx, target)
			switch fault {
			case "missing":
				return BaselineV1{}, ErrState
			case "saved":
				baseline.Saved = f.target
			case "snapshot":
				baseline.Owned.Network.Links[0].Index++
			case "local-enabled":
				baseline.Saved, err = configpoc.NewRoutedActivationBundleV1(saved.Firewall, f.target.LocalServices)
			}
			return baseline, err
		}
		if fault == "local-enabled" {
			var err error
			saved, err = configpoc.NewRoutedActivationBundleV1(saved.Firewall, f.target.LocalServices)
			if err != nil {
				t.Fatal(err)
			}
		}
		before := len(f.kernel.batches)
		if _, err := f.engine.Prepare(context.Background(), saved); err == nil || len(f.kernel.batches) != before || !f.network.active || len(f.listeners.actual) != 1 {
			t.Fatal("original baseline authority bypassed", fault)
		}
	}
}

func TestInverseHelperRecoveryBindsOriginalBaselineAndCanRestoreSix(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	confirmFixture(t, f)
	saved := installOriginalBaseline(t, f)
	prepared, err := f.engine.Prepare(context.Background(), saved)
	if err != nil {
		t.Fatal(err)
	}
	plan := f.plan
	plan.Operation, plan.BeforeOwned, plan.TargetOwned = "inverse-restart", strings.Repeat("8", 64), strings.Repeat("9", 64)
	deadline := time.Now().UTC().Add(30 * time.Second)
	f.engine.options.ResolvePlan = func(ctx context.Context, actual configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, actualDeadline time.Time) (PreparationV1, error) {
		if ctx.Err() != nil || actual != plan || previous == nil || previous.Composite.Hash != f.target.Composite.Hash || target.Composite.Hash != saved.Composite.Hash || !actualDeadline.Equal(deadline) {
			return PreparationV1{}, ErrState
		}
		return prepared, nil
	}
	// Engine-level process-replacement fixture: no old controller timer survives
	// the modeled helper death; production still requires the original Group CAS.
	if f.engine.ValidatePlan(context.Background(), plan, &f.target, saved, deadline) != nil || f.engine.Apply(context.Background(), saved) != nil {
		t.Fatal("establish complete inverse target")
	}
	identity := networkexecutor.OwnedNamespaceIdentity{UID: 1001, GID: 1002, Namespace: 200, Host: 100, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}
	network := &networkFixture{snapshot: f.network.snapshot, active: false, identity: identity, before: f.network.before}
	restarted, err := New(f.kernel, network, f.listeners, f.engine.options)
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.kernel.batches)
	if restarted.RecoverPlan(context.Background(), plan, &f.target, saved, deadline, identity) != nil || len(f.kernel.batches) != before || restarted.Current() != saved.Composite.Hash {
		t.Fatal("inverse work recovery lost its physical target or made effects")
	}
	if restarted.RestoreOwned(context.Background(), plan.BeforeOwned) != nil || restarted.Current() != f.target.Composite.Hash || !network.active || len(f.listeners.actual) != 1 {
		t.Fatal("recovered inverse could not compensate to6")
	}
}

func knownLegacyRules(t testing.TB) configpoc.Revision {
	t.Helper()
	enabled := true
	config := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	for i, protocol := range []string{"tcp", "udp"} {
		port := uint16(18080 + i)
		config.Rules = append(config.Rules, configpoc.Rule{ID: "saved-" + protocol, Action: "allow", Enabled: &enabled, Match: &configpoc.Match{
			Source: "198.18.0.0/24", Destination: "198.19.0.2/32", Protocol: protocol,
			SourcePorts: configpoc.PortRange{From: 1024, To: 65535}, DestinationPorts: configpoc.PortRange{From: port, To: port},
		}})
	}
	revision, err := configpoc.Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestKnownCanonicalLegacyRulesArePreservedThroughSixAndInverse(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	legacy := knownLegacyRules(t)
	artifact, err := firewallnft.Compile(legacy.Config)
	if err != nil || f.kernel.Apply(context.Background(), artifact.Batch) != nil {
		t.Fatal("trusted supervisor provisioning", err)
	}
	f.kernel.batches = nil
	var prepared PreparationV1
	engine, err := New(f.kernel, f.network, f.listeners, Options{Legacy: legacy,
		ResolvePlan: func(ctx context.Context, plan configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, deadline time.Time) (PreparationV1, error) {
			if ctx.Err() != nil || plan != f.plan || previous != nil || target.Composite.Hash != f.target.Composite.Hash || !deadline.Equal(f.started.Add(10*time.Second)) {
				return PreparationV1{}, ErrState
			}
			return prepared, nil
		}})
	if err != nil {
		t.Fatal("known selected nonempty legacy rejected", err)
	}
	prepared, err = engine.Prepare(context.Background(), f.target)
	if err != nil || len(prepared.Before.LegacyFirewall.Revision.Config.Rules) != 2 || prepared.Before.LegacyFirewall.Revision.Hash != legacy.Hash || len(f.kernel.batches) != 0 {
		t.Fatal("prepare reset or discarded selected rules", err)
	}
	group, err := nftguardian.NewGroup(engine)
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	f.engine, f.group, f.prepared = engine, group, prepared
	confirmFixture(t, f)
	saved := installOriginalBaseline(t, f)
	plan, receipt := armFixtureOperation(t, f, "restore-saved-rules", f.target, saved)
	if group.ConfirmLease(context.Background(), plan, receipt) != nil || f.network.active || len(f.listeners.actual) != 0 {
		t.Fatal("confirm restored actual legacy")
	}
	data, exists, err := f.kernel.Observe(context.Background(), LegacyTable)
	if err != nil || !exists {
		t.Fatal(err)
	}
	observed, err := firewallnft.VerifyObservation(data, legacy)
	if err != nil || observed.Revision.Hash != legacy.Hash || len(observed.Revision.Config.Rules) != 2 {
		t.Fatal("legacy full policy was not restored exactly", err)
	}
}

func TestKnownLegacyRevisionDoesNotAdoptForeignPolicyFromComment(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	legacy := knownLegacyRules(t)
	for _, object := range f.kernel.objects[LegacyTable] {
		if table, ok := object["table"].(map[string]any); ok {
			table["comment"] = firewallnft.RuleStateCompilerVersion + ":" + legacy.Hash
		}
	}
	engine, err := New(f.kernel, f.network, f.listeners, Options{Legacy: legacy, ResolvePlan: f.engine.options.ResolvePlan})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Prepare(context.Background(), f.target); err == nil || len(f.kernel.batches) != 0 || f.network.calls != 0 {
		t.Fatal("matching comment adopted missing legacy rules")
	}
}
