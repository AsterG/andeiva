package routedactivation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func observedFixture(snapshot networkexecutor.PreparedSnapshot) (networkexecutor.ObservedSnapshot, error) {
	observed := networkexecutor.ObservedSnapshot{Version: 1, Links: snapshot.Links, Routes: snapshot.Routes}
	raw, err := json.Marshal(observed)
	if err != nil {
		return observed, err
	}
	sum := sha256.Sum256(raw)
	observed.Hash = hex.EncodeToString(sum[:])
	return networkexecutor.CanonicalObservedSnapshot(observed)
}
func (n *networkFixture) PrepareObserved(ctx context.Context, bindings []networkplan.Binding) (networkexecutor.ObservedSnapshot, error) {
	if ctx.Err() != nil || n.active || len(bindings) != 2 {
		return networkexecutor.ObservedSnapshot{}, ErrState
	}
	expected := map[string]string{}
	for _, b := range bindings {
		expected[b.Name] = b.HardwareAddress
	}
	for _, link := range n.snapshot.Links {
		if link.Name != "lo" && expected[link.Name] != link.MAC {
			return networkexecutor.ObservedSnapshot{}, ErrState
		}
	}
	return observedFixture(n.snapshot)
}
func (n *networkFixture) VerifyObserved(ctx context.Context, snapshot networkexecutor.ObservedSnapshot) error {
	if ctx.Err() != nil || n.active || !networkexecutor.ObservedMatchesPrepared(snapshot, n.snapshot) {
		return ErrState
	}
	return nil
}
func (n *networkFixture) RecoverObserved(ctx context.Context, snapshot networkexecutor.ObservedSnapshot, identity networkexecutor.OwnedNamespaceIdentity) error {
	if identity != n.identity {
		return ErrState
	}
	return n.VerifyObserved(ctx, snapshot)
}

func noNetworkBootFixture(t testing.TB) (assembledFixture, configpoc.RoutedActivationBundleV1) {
	t.Helper()
	f, saved := coldBootFixture(t)
	f.target = saved
	bindings := []networkplan.Binding{}
	for _, link := range f.network.snapshot.Links {
		if link.Name != "lo" {
			bindings = append(bindings, networkplan.Binding{Name: link.Name, HardwareAddress: link.MAC})
		}
	}
	var prepared PreparationV1
	engine, err := New(f.kernel, f.network, f.listeners, Options{Legacy: saved.Firewall, ObservedBindings: bindings, ResolvePlan: func(ctx context.Context, actual configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, deadline time.Time) (PreparationV1, error) {
		if ctx.Err() != nil || actual != f.plan || previous != nil || target.Composite.Hash != saved.Composite.Hash || !deadline.Equal(f.started.Add(10*time.Second)) {
			return PreparationV1{}, ErrState
		}
		return prepared, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = engine.PrepareColdBoot(context.Background(), saved, saved)
	if err != nil {
		t.Fatal(err)
	}
	baseline := BaselineV1{Saved: saved, Owned: prepared.Target, Dependencies: prepared.Dependencies}
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

func TestNoNetworkBootFourReadOnlyAndExpiryRestoreActualAbsence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, saved := noNetworkBootFixture(t)
		if f.prepared.Before.Version != 2 || f.prepared.Dependencies.Version != 2 || f.prepared.Before.NetworkState != NoNetwork || f.prepared.Before.Observed == nil || f.prepared.Target.LegacyFirewall.Revision.Hash != saved.Firewall.Hash || len(saved.Firewall.Config.Rules) != 2 || len(f.kernel.batches) != 0 || f.network.calls != 0 || f.listeners.calls != 0 {
			t.Fatal("fabricated plan or premature effect")
		}
		if f.engine.Apply(context.Background(), saved) == nil {
			t.Fatal("applied without selected Intent")
		}
		if f.group.BootstrapStartup(context.Background(), f.plan, saved, f.started) != nil {
			t.Fatal("boot4")
		}
		if f.engine.Current() != saved.Composite.Hash || f.network.calls != 0 || f.network.active || f.listeners.calls != 0 {
			t.Fatal("boot4 wrote L3/listeners or lost rules")
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		state, current, err := f.group.SnapshotObserved()
		if err != nil || state.Phase != "expired" || current != "" || f.engine.MatchOwned(context.Background(), f.plan.BeforeOwned) != nil {
			t.Fatal("expiry", state, current, err)
		}
		if len(f.kernel.objects) != 0 || f.network.calls != 0 || f.listeners.calls != 0 {
			t.Fatal("Boot4 rollback left effects")
		}
	})
}

func TestNoNetworkFourEditThenSixAndExactInverseExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, saved := noNetworkBootFixture(t)
		confirmFixture(t, f)
		cfg := saved.Firewall.Config
		cfg.Rules = append([]configpoc.Rule(nil), cfg.Rules...)
		cfg.Rules[0].Action = "deny"
		fw, err := configpoc.Canonical(cfg)
		if err != nil {
			t.Fatal(err)
		}
		edited, err := configpoc.NewRoutedActivationBundleV1(fw, saved.LocalServices)
		if err != nil {
			t.Fatal(err)
		}
		plan, receipt := armFixtureOperation(t, f, "edit-four", saved, edited)
		if f.group.ConfirmLease(context.Background(), plan, receipt) != nil || f.engine.Current() != edited.Composite.Hash || f.network.calls != 0 || f.listeners.calls != 0 {
			t.Fatal("ordinary4 edit was restricted to original saved or wrote L3")
		}
		_, _, six := artifactFixture(t)
		plan, receipt = armFixtureOperation(t, f, "first-six", edited, six)
		if f.group.ConfirmLease(context.Background(), plan, receipt) != nil || !f.network.active {
			t.Fatal("first6")
		}
		inverse, receipt := armFixtureOperation(t, f, "inverse-original", six, saved)
		currentFour := f.engine.Current()
		f.engine.mu.Lock()
		active := f.network.active
		f.engine.mu.Unlock()
		if currentFour != saved.Composite.Hash || active {
			t.Fatal("inverse did not restore original observed baseline")
		}
		time.Sleep(31 * time.Second)
		synctest.Wait()
		state, current, err := f.group.SnapshotObserved()
		if err != nil || state.Phase != "expired" || current != six.Composite.Hash || f.group.RecoverLease(inverse, receipt) != nil || !f.network.active {
			t.Fatal("inverse expiry", state, current, err)
		}
		plan, receipt = armFixtureOperation(t, f, "inverse-confirm", six, saved)
		if f.group.ConfirmLease(context.Background(), plan, receipt) != nil || f.network.active {
			t.Fatal("confirmed4")
		}
		plan, receipt = armFixtureOperation(t, f, "six-again", saved, six)
		if f.group.ConfirmLease(context.Background(), plan, receipt) != nil || !f.network.active {
			t.Fatal("6 after confirmed4")
		}
	})
}

func TestNoNetworkBootRejectsForeignHistoryBindingsTablesAndCancellation(t *testing.T) {
	for _, fault := range []string{"binding", "legacy", "foreign-table", "configured", "ctx"} {
		t.Run(fault, func(t *testing.T) {
			f, saved := noNetworkBootFixture(t)
			options := f.engine.options
			if fault == "binding" {
				options.ObservedBindings[0].HardwareAddress = "02:ff:00:00:00:01"
			}
			engine, err := New(f.kernel, f.network, f.listeners, options)
			if err != nil {
				t.Fatal(err)
			}
			target := saved
			switch fault {
			case "legacy":
				target.Firewall.Config.Rules = append([]configpoc.Rule(nil), saved.Firewall.Config.Rules...)
				target.Firewall.Config.Rules[0].Action = "deny"
				fw, _ := configpoc.Canonical(target.Firewall.Config)
				target, _ = configpoc.NewRoutedActivationBundleV1(fw, saved.LocalServices)
			case "foreign-table":
				f.kernel.objects[LocalTable] = []map[string]any{}
			case "configured":
				f.network.active = true
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "ctx" {
				cancel()
			}
			if _, err := engine.PrepareColdBoot(ctx, target, target); err == nil {
				t.Fatal("accepted", fault)
			}
			if len(f.kernel.batches) != 0 || f.network.calls != 0 || f.listeners.calls != 0 {
				t.Fatal("effect on negative prepare")
			}
		})
	}
}

func TestNoNetworkRecoverHelperOriginalScopeAndFinality(t *testing.T) {
	f, saved := noNetworkBootFixture(t)
	confirmFixture(t, f)
	f.network.identity = networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Namespace: 22, Host: 11, BootID: "12345678-1234-1234-1234-123456789abc", RunID: "0123456789abcdef0123456789abcdef"}
	options := f.engine.options
	options.ResolveRecoveredIdle = func(ctx context.Context, p configpoc.RoutedTransitionV1, deadline time.Time) (nftguardian.RecoveredIdleV1, error) {
		return nftguardian.RecoveredIdleV1{Plan: p, Bundle: &saved, OwnedRef: p.TargetOwned, Deadline: deadline, Scope: f.network.identity, Finality: nftguardian.TargetConfirmed}, nil
	}
	for _, fault := range []string{"scope", "uid", "gid", "boot", "target-ns", "host-ns", "deadline", "plan", "kernel", "none"} {
		t.Run(fault, func(t *testing.T) {
			engine, err := New(f.kernel, f.network, f.listeners, options)
			if err != nil {
				t.Fatal(err)
			}
			identity := f.network.identity
			deadline := f.started.Add(10 * time.Second)
			p := f.plan
			switch fault {
			case "scope":
				identity.RunID = strings.Repeat("f", 32)
			case "uid":
				identity.UID = 0
			case "gid":
				identity.GID = 0
			case "boot":
				identity.BootID = "22345678-1234-1234-1234-123456789abc"
			case "target-ns":
				identity.Namespace++
			case "host-ns":
				identity.Host++
			case "deadline":
				deadline = deadline.Add(time.Nanosecond)
			case "plan":
				p.Operation = "foreign"
			case "kernel":
				f.kernel.readFail = true
				defer func() { f.kernel.readFail = false }()
			}
			err = engine.RecoverPlan(context.Background(), p, nil, saved, deadline, identity)
			if fault != "none" {
				if err == nil {
					t.Fatal("recovery accepted", fault)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			group, err := nftguardian.NewGroup(engine)
			if err != nil {
				t.Fatal(err)
			}
			defer group.Close()
			if err := group.RecoverIdle(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			state, current, err := group.SnapshotObserved()
			if err != nil || state.Phase != "idle" || !state.Deadline.IsZero() || current != saved.Composite.Hash {
				t.Fatal(state, current, err)
			}
		})
	}
	if f.network.calls != 0 || f.listeners.calls != 0 {
		t.Fatal("read-only recovery mutated owned resources")
	}
}

func TestNoNetworkBootFailureAndLostReplyCompensateWithoutL3(t *testing.T) {
	for _, fault := range []string{"deny-fail", "deny-lost", "target-fail", "target-lost", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, saved := noNetworkBootFixture(t)
			switch fault {
			case "deny-fail":
				f.kernel.failAt = 1
			case "deny-lost":
				f.kernel.lostAt = 1
			case "target-fail":
				f.kernel.failAt = 2
			case "target-lost":
				f.kernel.lostAt = 2
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fault == "cancel" {
				cancel()
			}
			if err := f.group.BootstrapStartup(ctx, f.plan, saved, f.started); err == nil {
				t.Fatal("fault claimed success")
			}
			if len(f.kernel.objects) != 0 || f.network.calls != 0 || f.listeners.calls != 0 || f.network.active {
				t.Fatal("failed Boot4 did not restore exact absence")
			}
		})
	}
}

func TestNoNetworkObservedDriftFencesWithoutWritingInterfaces(t *testing.T) {
	f, saved := noNetworkBootFixture(t)
	if err := f.group.BootstrapStartup(context.Background(), f.plan, saved, f.started); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := f.group.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	f.network.snapshot.Links[0].Index++
	batches := len(f.kernel.batches)
	if f.group.ConfirmLease(context.Background(), f.plan, receipt) == nil || f.engine.Current() != "" {
		t.Fatal("confirmed replaced link")
	}
	if f.group.RecoverLease(f.plan, receipt) == nil || len(f.kernel.batches) != batches || f.network.calls != 0 {
		t.Fatal("overwrote uncertain scope")
	}
}

func TestNoNetworkInverseFreshHelperRestoresExactSix(t *testing.T) {
	f, saved := noNetworkBootFixture(t)
	confirmFixture(t, f)
	f.network.identity = networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Namespace: 22, Host: 11, BootID: "12345678-1234-1234-1234-123456789abc", RunID: "0123456789abcdef0123456789abcdef"}
	_, _, six := artifactFixture(t)
	plan, receipt := armFixtureOperation(t, f, "configured-six", saved, six)
	if f.group.ConfirmLease(context.Background(), plan, receipt) != nil {
		t.Fatal("confirm6")
	}
	prepared, err := f.engine.Prepare(context.Background(), saved)
	if err != nil {
		t.Fatal(err)
	}
	inverse := f.plan
	inverse.Operation = "pending-no-network"
	deadline := time.Now().UTC().Add(30 * time.Second)
	f.engine.options.ResolvePlan = func(ctx context.Context, actual configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, actualDeadline time.Time) (PreparationV1, error) {
		if ctx.Err() != nil || actual != inverse || previous == nil || previous.Composite.Hash != six.Composite.Hash || target.Composite.Hash != saved.Composite.Hash || !actualDeadline.Equal(deadline) {
			return PreparationV1{}, ErrState
		}
		return prepared, nil
	}
	// Model process replacement at the engine boundary: the old confirmed Group
	// has no pending timer. Durable finality remains the coordinator's decision.
	if err := f.engine.ValidatePlan(context.Background(), inverse, &six, saved, deadline); err != nil {
		t.Fatal(err)
	}
	if err := f.engine.Apply(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	if f.network.active {
		t.Fatal("inverse has not restored actual baseline")
	}
	engine, err := New(f.kernel, f.network, f.listeners, f.engine.options)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.RecoverPlan(context.Background(), inverse, &six, saved, deadline, f.network.identity); err != nil {
		t.Fatal("recover inverse Work", err)
	}
	if err := engine.RestoreOwned(context.Background(), inverse.BeforeOwned); err != nil || !f.network.active || engine.Current() != six.Composite.Hash {
		t.Fatal("exact prior6", err)
	}
}

type cancelNoNetworkKernel struct {
	*kernelFixture
	at     int
	cancel context.CancelFunc
}

func (k cancelNoNetworkKernel) Apply(ctx context.Context, data []byte) error {
	if err := k.kernelFixture.Apply(ctx, data); err != nil {
		return err
	}
	if len(k.batches) == k.at {
		k.cancel()
	}
	return ctx.Err()
}

func TestNoNetworkCancellationAfterEffectsUsesIndependentCompensation(t *testing.T) {
	for _, at := range []int{1, 2} {
		f, saved := noNetworkBootFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		f.engine.kernel = cancelNoNetworkKernel{f.kernel, at, cancel}
		if err := f.group.BootstrapStartup(ctx, f.plan, saved, f.started); err == nil {
			t.Fatal("canceled apply claimed success")
		}
		cancel()
		if len(f.kernel.objects) != 0 || f.network.calls != 0 || f.listeners.calls != 0 {
			t.Fatal("canceled apply lost exact absence")
		}
	}
}

func TestNoNetworkConcurrentConfirmAndRecoveryOwnOneLease(t *testing.T) {
	f, saved := noNetworkBootFixture(t)
	if err := f.group.BootstrapStartup(context.Background(), f.plan, saved, f.started); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := f.group.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); results <- f.group.ConfirmLease(context.Background(), f.plan, receipt) }()
	go func() { defer wg.Done(); results <- f.group.RecoverLease(f.plan, receipt) }()
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 || f.network.calls != 0 || f.listeners.calls != 0 {
		t.Fatal("multiple winners or unrelated effects", success)
	}
	if _, _, err := f.group.SnapshotObserved(); err != nil {
		t.Fatal("concurrent result lacks physical readback", err)
	}
}

func TestNoNetworkPreparationReturnDoesNotAliasSelectedBefore(t *testing.T) {
	f, saved := noNetworkBootFixture(t)
	confirmFixture(t, f)
	config := saved.Firewall.Config
	config.Rules = append([]configpoc.Rule(nil), config.Rules...)
	config.Rules[0].Action = "deny"
	fw, err := configpoc.Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	edited, err := configpoc.NewRoutedActivationBundleV1(fw, saved.LocalServices)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.engine.Prepare(context.Background(), edited)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Before.Observed.Links[0].Index++
	if f.engine.Current() != saved.Composite.Hash {
		t.Fatal("returned Before mutated selected ownership")
	}
}
