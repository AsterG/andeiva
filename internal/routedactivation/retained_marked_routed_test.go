package routedactivation

import (
	"bytes"
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
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
		{name: "unexpected rules prevent reopening", earlyReadback: true},
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
				forward, err := routednft.CompileHeldMarkedPolicy(target, applied)
				if err != nil {
					t.Fatal(err)
				}
				restored, _, err := routedmodel.ReserveAdmissionMarks(identity.BootID, applied.Issued, &applied, target, before)
				if err != nil {
					t.Fatal(err)
				}
				undo, err := routednft.CompileHeldMarkedPolicy(before, restored)
				if err != nil {
					t.Fatal(err)
				}
				exact := func(batches [][]byte, replacement []byte) bool {
					return len(batches) == 3 && bytes.Equal(batches[0], routednft.ForwardHold(true)) &&
						bytes.Equal(batches[1], replacement) && bytes.Equal(batches[2], routednft.ForwardHold(false))
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
						f.kernel.corruptRoutedAt = 2
					}
					if tc.lateReadback {
						f.kernel.corruptRoutedAt = 3
					}
					if tc.denyFails {
						f.kernel.failAt = 3
					}
					if err := f.group.ApplyLease(ctx, plan, next, receipt); err == nil {
						t.Fatal("published an applied outcome after unexpected readback")
					}
					f.engine.mu.Lock()
					defer f.engine.mu.Unlock()
					if tc.denyFails {
						if !f.engine.fenced || f.engine.marked.applied {
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
						!f.engine.fenced || f.engine.marked.applied || f.network.calls != networkCalls || f.listeners.calls != listenerCalls {
						t.Fatal("uncertain readback did not leave verified forwarding denial", err, verify)
					}
					return
				}
				plan, receipt := armFixtureOperation(t, f, "marked", f.target, next)
				f.engine.mu.Lock()
				appliedExactly := exact(f.kernel.batches, forward.Batch) &&
					equalAdmissionMarks(*f.engine.admission, applied) && f.engine.marked.applied
				f.engine.mu.Unlock()
				if !appliedExactly {
					t.Fatal("the target was not installed and verified before the forwarding hold was removed")
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
					if state.Phase != "idle" || current != next.Composite.Hash || len(f.kernel.batches) != 3 {
						t.Fatal("confirm changed the applied policy", state, current)
					}
				} else if state.Phase != "expired" || current != f.target.Composite.Hash || len(f.kernel.batches) != 6 ||
					!exact(f.kernel.batches[3:], undo.Batch) || !equalAdmissionMarks(*f.engine.admission, restored) || f.engine.marked.applied {
					t.Fatal("expiry did not apply the pre-reserved restore policy", state, current)
				}
				afterLocal, _, err := f.kernel.Observe(ctx, LocalTable)
				if err != nil || !bytes.Equal(rawLocal, afterLocal) || f.network.calls != networkCalls || f.listeners.calls != listenerCalls {
					t.Fatal("rule change modified non-firewall state", err)
				}
			})
		})
	}
}
