package routedactivation

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedflow"
	"github.com/AsterG/andeiva/internal/routedmodel"
	"github.com/AsterG/andeiva/internal/routednft"
)

func TestMarkedRoutedGroupConfirmAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		confirm, adoptLegacy                   bool
		earlyReadback, lateReadback, denyFails bool
	}{
		{name: "confirms", confirm: true},
		{name: "expires"},
		{name: "adopts legacy and restores", adoptLegacy: true},
		{name: "unexpected rules prevent retirement", earlyReadback: true},
		{name: "unexpected rules prevent confirmation", lateReadback: true},
		{name: "failed deny stays unverified", earlyReadback: true, denyFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := assembleFixture(t)
				defer f.group.Close()
				confirmFixture(t, f)
				ctx := context.Background()
				identity := networkexecutor.OwnedNamespaceIdentity{BootID: "12345678-1234-1234-1234-123456789abc", Namespace: 2, Host: 1}
				before, err := routedmodel.Canonical(*f.target.Firewall.Config.Routed)
				if err != nil {
					t.Fatal(err)
				}
				var prior *routedmodel.AdmissionMarks
				base := uint32(3)
				if !tc.adoptLegacy {
					reserved, _, err := routedmodel.ReserveAdmissionMarks(identity.BootID, 0, nil, before, before)
					if err != nil {
						t.Fatal(err)
					}
					// Model an already verified strict source. DHCP lease
					// ownership is outside this in-memory helper test.
					initial, err := routednft.CompileMarkedPolicy(before, reserved)
					if err != nil || f.kernel.Apply(ctx, initial.Batch) != nil {
						t.Fatal("establish strict source", err)
					}
					prior = &reserved
					base += prior.Issued
					f.engine.admission = prior
				}
				f.kernel.batches = nil
				networkCalls, listenerCalls := f.network.calls, f.listeners.calls
				rawLocal, _, err := f.kernel.Observe(ctx, LocalTable)
				if err != nil {
					t.Fatal(err)
				}

				policy := before.Policy
				policy.Rules = append([]routedmodel.Rule(nil), policy.Rules...)
				policy.Rules[0].Action = "deny"
				target, err := routedmodel.Canonical(policy)
				if err != nil {
					t.Fatal(err)
				}
				applied, _, err := routedmodel.ReserveAdmissionMarks(identity.BootID, base, prior, before, target)
				if err != nil {
					t.Fatal(err)
				}
				forward, err := routednft.CompileMarkedPolicy(target, applied)
				if err != nil {
					t.Fatal(err)
				}
				undo, restored, err := routednft.CompileRetainedWANChange(target, before, applied, applied.Issued)
				if err != nil {
					t.Fatal(err)
				}
				want := [][]byte{forward.Batch, undo.Batch}
				forwardBatches, forwardCleanups := 1, 1
				if tc.adoptLegacy {
					forwardBatches, forwardCleanups = 2, 0
				}
				var cleanups int
				f.engine.retireMarked = func(_ *routedflow.Retirement, _ context.Context) (routedflow.RetirementResult, error) {
					cleanups++
					transactions := forwardBatches + cleanups - forwardCleanups
					if cleanups > forwardCleanups+1 || len(f.kernel.batches) != transactions || !bytes.Equal(f.kernel.batches[transactions-1], want[transactions-forwardBatches]) {
						t.Error("directed cleanup ran before the exact rules replacement")
						return routedflow.RetirementResult{}, ErrState
					}
					if tc.lateReadback {
						f.kernel.objects[RoutedTable] = f.kernel.objects[RoutedTable][:1]
					}
					return routedflow.RetirementResult{Operation: "marked", Retired: routedflow.MaxRetirements, Limited: true}, nil
				}
				f.engine.options.ResolveAdmissionMarks = func(context.Context, configpoc.RoutedTransitionV1, time.Time) (*configpoc.RoutedBootMarkPlanV1, networkexecutor.OwnedNamespaceIdentity, error) {
					return &configpoc.RoutedBootMarkPlanV1{BaseIssued: base, Prior: prior, Applied: applied, Restored: restored}, identity, nil
				}
				fw, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &target.Policy})
				if err != nil {
					t.Fatal(err)
				}
				next, err := configpoc.NewRoutedActivationBundleV1(fw, f.target.LocalServices)
				if err != nil {
					t.Fatal(err)
				}
				if tc.earlyReadback || tc.lateReadback {
					plan, receipt := selectFixtureOperation(t, f, "marked", f.target, next)
					if tc.earlyReadback {
						f.kernel.corruptRoutedAt = 1
					}
					if tc.denyFails {
						f.kernel.failAt = 2
					}
					if err := f.group.ApplyLease(ctx, plan, next, receipt); err == nil {
						t.Fatal("published an applied outcome after unexpected readback")
					}
					f.engine.mu.Lock()
					defer f.engine.mu.Unlock()
					if tc.denyFails {
						if !f.engine.fenced || f.engine.marked.applyCleanup != nil || cleanups != 0 {
							t.Fatal("a failed closure must leave the helper fenced without an applied receipt")
						}
						return
					}
					closed := target.Policy
					closed.Rules = nil
					deny, err := routedmodel.Canonical(closed)
					if err != nil {
						t.Fatal(err)
					}
					raw, _, err := f.kernel.Observe(ctx, RoutedTable)
					marks := routedmodel.AdmissionMarks{Boot: identity.BootID, Revision: deny.Hash, Issued: restored.Issued}
					if _, verify := routednft.VerifyRetainedWANObservation(raw, deny, marks); err != nil || verify != nil ||
						!f.engine.fenced || f.engine.marked.applyCleanup != nil || f.network.calls != networkCalls || f.listeners.calls != listenerCalls ||
						(tc.earlyReadback && cleanups != 0) || (tc.lateReadback && cleanups != 1) {
						t.Fatal("uncertain readback did not leave verified forwarding denial", err, verify)
					}
					return
				}
				plan, receipt := armFixtureOperation(t, f, "marked", f.target, next)
				f.engine.mu.Lock()
				appliedExactly := cleanups == forwardCleanups && len(f.kernel.batches) == forwardBatches &&
					equalAdmissionMarks(*f.engine.admission, applied) && f.engine.marked.applyCleanup != nil && f.engine.marked.applyCleanup.Partial
				f.engine.mu.Unlock()
				if !appliedExactly {
					t.Fatal("bounded cleanup did not preserve a verified applied outcome")
				}
				if tc.confirm {
					if err := f.group.ConfirmLease(ctx, plan, receipt); err != nil {
						t.Fatal("confirm", err)
					}
				}
				time.Sleep(31 * time.Second)
				synctest.Wait()
				state, current, err := f.group.SnapshotObserved()
				if err != nil {
					t.Fatal(err)
				}
				f.engine.mu.Lock()
				defer f.engine.mu.Unlock()
				if tc.confirm {
					if state.Phase != "idle" || current != next.Composite.Hash || cleanups != 1 {
						t.Fatal("confirm changed the applied policy or ran a second cleanup", state, current)
					}
				} else if state.Phase != "expired" || current != f.target.Composite.Hash || cleanups != forwardCleanups+1 ||
					!equalAdmissionMarks(*f.engine.admission, restored) || f.engine.marked.undoCleanup == nil {
					t.Fatal("expiry did not apply the pre-reserved restore policy", state, current)
				}
				afterLocal, _, err := f.kernel.Observe(ctx, LocalTable)
				if err != nil || !bytes.Equal(rawLocal, afterLocal) || f.network.calls != networkCalls || f.listeners.calls != listenerCalls {
					t.Fatal("atomic rule change modified non-firewall state", err)
				}
			})
		})
	}
}
