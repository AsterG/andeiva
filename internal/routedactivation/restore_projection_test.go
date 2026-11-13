package routedactivation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func TestSelectedSavedFourProjectionPreservesOriginalNetwork(t *testing.T) {
	for _, save := range []bool{false, true} {
		name := "without-save"
		if save {
			name = "saved-edit"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, original := noNetworkBootFixture(t)
				confirmFixture(t, f)
				baseline, err := f.engine.options.ResolveBaseline(context.Background(), original)
				if err != nil {
					t.Fatal(err)
				}
				selectedTarget := ""
				// Models the trusted adapter: readonly preparation receives the original
				// memento; only an exactly selected target receives its projected table state.
				f.engine.options.ResolveBaseline = func(ctx context.Context, target configpoc.RoutedActivationBundleV1) (BaselineV1, error) {
					if ctx.Err() != nil {
						return BaselineV1{}, ErrState
					}
					if target.Composite.Hash != selectedTarget {
						return baseline, nil
					}
					projected := baseline
					projected.Saved = target
					projected.Owned.LegacyFirewall = TableStateV1{Presence: Present, Revision: &target.Firewall}
					return projected, nil
				}
				step := func(id string, previous, target configpoc.RoutedActivationBundleV1, confirm bool) (configpoc.RoutedTransitionV1, nftguardian.State) {
					t.Helper()
					selectedTarget = ""
					prepared, err := f.engine.Prepare(context.Background(), target)
					if err != nil {
						t.Fatal("prepare "+id, err)
					}
					deadline := time.Now().UTC().Add(30 * time.Second)
					plan := configpoc.RoutedTransitionV1{Version: 1, Operation: id, Previous: strings.Repeat("1", 64), Target: strings.Repeat("2", 64), BeforeOwned: artifactDigest([]byte(id + "before")), TargetOwned: artifactDigest([]byte(id + "target")), Dependencies: strings.Repeat("7", 64)}
					f.engine.options.ResolvePlan = func(ctx context.Context, p configpoc.RoutedTransitionV1, prior *configpoc.RoutedActivationBundleV1, actual configpoc.RoutedActivationBundleV1, at time.Time) (PreparationV1, error) {
						if ctx.Err() != nil || p != plan || prior == nil || prior.Composite.Hash != previous.Composite.Hash || actual.Composite.Hash != target.Composite.Hash || !at.Equal(deadline) {
							return PreparationV1{}, ErrState
						}
						selectedTarget = actual.Composite.Hash
						return prepared, nil
					}
					if err := f.group.ArmUntilLease(context.Background(), plan, "lease-"+id, previous, target, deadline); err != nil {
						t.Fatal("arm "+id, err)
					}
					receipt, _, err := f.group.SnapshotObserved()
					if err != nil {
						t.Fatal(err)
					}
					if err := f.group.ApplyLease(context.Background(), plan, target, receipt); err != nil {
						t.Fatal("apply "+id, err)
					}
					if confirm && f.group.ConfirmLease(context.Background(), plan, receipt) != nil {
						t.Fatal("confirm " + id)
					}
					return plan, receipt
				}
				config := original.Firewall.Config
				config.Rules = append([]configpoc.Rule(nil), config.Rules...)
				config.Rules[0].Action = "deny"
				fw, err := configpoc.Canonical(config)
				if err != nil {
					t.Fatal(err)
				}
				edited, err := configpoc.NewRoutedActivationBundleV1(fw, original.LocalServices)
				if err != nil {
					t.Fatal(err)
				}
				step("edit-four", original, edited, true)
				saved := original
				if save {
					saved = edited
				}
				_, _, six := artifactFixture(t)
				step("first-six", edited, six, true)
				inverse, receipt := step("restore-saved", six, saved, false)
				if f.engine.Current() != saved.Composite.Hash {
					t.Fatal("wrong saved rules")
				}
				f.engine.mu.Lock()
				active := f.network.active
				f.engine.mu.Unlock()
				if active || !sameArtifact(baseline.Owned.Observed, f.engine.prepared.Target.Observed) {
					t.Fatal("original network memento changed")
				}
				time.Sleep(31 * time.Second)
				synctest.Wait()
				observed, current, err := f.group.SnapshotObserved()
				if err != nil || observed.Phase != "expired" || current != six.Composite.Hash || f.group.RecoverLease(inverse, receipt) != nil {
					t.Fatal("original expiry failed", err)
				}
				step("confirm-saved", six, saved, true)
				if f.engine.Current() != saved.Composite.Hash {
					t.Fatal("confirmed wrong target")
				}
			})
		})
	}
}

func TestRestoreProjectionRejectsCanonicalPhysicalMementoSubstitution(t *testing.T) {
	for _, mode := range []string{"prepared-network", "observed-index", "observed-mtu", "dependencies", "local"} {
		t.Run(mode, func(t *testing.T) {
			var f assembledFixture
			var saved configpoc.RoutedActivationBundleV1
			if mode == "prepared-network" {
				f = assembleFixture(t)
				defer f.group.Close()
				saved = installOriginalBaseline(t, f)
				confirmFixture(t, f)
			} else {
				f, saved = noNetworkBootFixture(t)
				confirmFixture(t, f)
				_, _, six := artifactFixture(t)
				plan, receipt := armFixtureOperation(t, f, "selected-six", saved, six)
				if f.group.ConfirmLease(context.Background(), plan, receipt) != nil {
					t.Fatal("confirm")
				}
			}
			original, err := f.engine.options.ResolveBaseline(context.Background(), saved)
			if err != nil {
				t.Fatal(err)
			}
			data, _ := json.Marshal(original)
			var changed BaselineV1
			if json.Unmarshal(data, &changed) != nil {
				t.Fatal("detach baseline")
			}
			switch mode {
			case "prepared-network":
				changed.Owned.Network.Links[0].MTU++
				changed.Owned.Network.Hash = ""
				data, _ = json.Marshal(changed.Owned.Network)
				changed.Owned.Network.Hash = artifactDigest(data)
				changed.Dependencies.Prepared = changed.Owned.Network
			case "observed-index", "observed-mtu":
				if mode == "observed-index" {
					changed.Owned.Observed.Links[0].Index += 10
				} else {
					changed.Owned.Observed.Links[0].MTU++
				}
				changed.Owned.Observed.Hash = ""
				data, _ = json.Marshal(changed.Owned.Observed)
				changed.Owned.Observed.Hash = artifactDigest(data)
				changed.Dependencies.Observed = changed.Owned.Observed
			case "dependencies":
				changed.Dependencies.Observed.Links[0].MTU++
			case "local":
				changed.Owned.LocalServices = TableStateV1{Presence: Present, Revision: &f.target.LocalServices}
			}
			if mode == "prepared-network" || mode == "observed-index" || mode == "observed-mtu" {
				// These substitutions are canonical and internally self-consistent.
				// Shape alone must not override the real retained physical memento.
				if _, err := configpoc.ProjectRoutedRestoreBaselineV1(changed, saved); err != nil {
					t.Fatal("mutation was not a canonical physical alternative", err)
				}
				if mode != "prepared-network" {
					if _, err := networkexecutor.CanonicalObservedSnapshot(*changed.Owned.Observed); err != nil {
						t.Fatal(err)
					}
				}
			}
			f.engine.options.ResolveBaseline = func(context.Context, configpoc.RoutedActivationBundleV1) (BaselineV1, error) { return changed, nil }
			before := len(f.kernel.batches)
			if _, err := f.engine.Prepare(context.Background(), saved); err == nil || len(f.kernel.batches) != before || !f.network.active {
				t.Fatal("physical/dependency/local substitution accepted", mode)
			}
		})
	}
}

func TestRestoreProjectionCannotActivateUnselectedTarget(t *testing.T) {
	f, original := noNetworkBootFixture(t)
	confirmFixture(t, f)
	baseline, err := f.engine.options.ResolveBaseline(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	f.engine.options.ResolveBaseline = func(context.Context, configpoc.RoutedActivationBundleV1) (BaselineV1, error) { return baseline, nil }
	_, _, six := artifactFixture(t)
	plan, receipt := armFixtureOperation(t, f, "configure-selected-six", original, six)
	if f.group.ConfirmLease(context.Background(), plan, receipt) != nil {
		t.Fatal("confirm")
	}
	cfg := original.Firewall.Config
	cfg.Rules = append([]configpoc.Rule(nil), cfg.Rules...)
	cfg.Rules[0].Action = "deny"
	fw, err := configpoc.Canonical(cfg)
	if err != nil {
		t.Fatal(err)
	}
	target, err := configpoc.NewRoutedActivationBundleV1(fw, original.LocalServices)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.Prepare(context.Background(), target); err != nil {
		t.Fatal("readonly projection", err)
	}
	batches := len(f.kernel.batches)
	// The selected resolver still binds the previous operation's exact six target.
	plan.Operation = "not-selected"
	if f.group.ArmUntilLease(context.Background(), plan, "unselected-lease", six, target, time.Now().UTC().Add(30*time.Second)) == nil || len(f.kernel.batches) != batches || !f.network.active || f.engine.Current() != six.Composite.Hash {
		t.Fatal("unselected prospective projection gained effect authority")
	}
}
