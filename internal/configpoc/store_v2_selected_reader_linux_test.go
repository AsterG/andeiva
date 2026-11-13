//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// This fixture supplies preparation bytes only. Every effect method refuses;
// tests stop at the coordinator's durable after_intent boundary.
type readerPreparationOnlyV2 struct {
	identity   networkexecutor.OwnedNamespaceIdentity
	previous   RoutedActivationBundleV1
	snapshot   networkexecutor.PreparedSnapshot
	interfaces []localpolicy.Interface
}

func (a *readerPreparationOnlyV2) Identity() networkexecutor.OwnedNamespaceIdentity {
	return a.identity
}
func (a *readerPreparationOnlyV2) Prepare(_ context.Context, target RoutedActivationBundleV1, _ *RoutedBaselineV1) (RoutedPreparationV1, error) {
	snapshot := clone(a.snapshot)
	snapshot.PlanHash = target.Firewall.Config.Routed.Network.Hash
	snapshot.Hash = ""
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return RoutedPreparationV1{}, err
	}
	snapshot.Hash = checkpointDigest(raw)
	before := OwnedV1{Version: 1, Network: snapshot, NetworkState: Baseline, LegacyFirewall: TableStateV1{Presence: Present, Revision: &a.previous.Firewall}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Present, Revision: &a.previous.LocalServices}}
	after := clone(before)
	after.NetworkState = Configured
	after.LegacyFirewall = TableStateV1{Presence: Absent}
	after.RoutedFirewall = TableStateV1{Presence: Present, Revision: &target.Firewall}
	after.LocalServices = TableStateV1{Presence: Present, Revision: &target.LocalServices}
	return RoutedPreparationV1{Before: before, Target: after, Dependencies: DependenciesV1{Version: 1, Network: target.Firewall.Config.Routed.Network, Prepared: snapshot, LocalInterfaces: a.interfaces}}, nil
}
func (a *readerPreparationOnlyV2) PrepareBoot(context.Context, RoutedActivationBundleV1, RoutedActivationBundleV1) (RoutedPreparationV1, error) {
	return RoutedPreparationV1{}, ErrRecovery
}
func (a *readerPreparationOnlyV2) Observe(context.Context) (RoutedReceiptV1, string, error) {
	return RoutedReceiptV1{Phase: "bootstrap"}, "", nil
}
func (a *readerPreparationOnlyV2) Match(context.Context, RoutedSelectedPlanV1, string) error {
	return ErrRecovery
}
func (a *readerPreparationOnlyV2) Resume(context.Context, RoutedSelectedPlanV1) error {
	return ErrRecovery
}
func (a *readerPreparationOnlyV2) Arm(context.Context, RoutedSelectedPlanV1) error {
	return ErrRecovery
}
func (a *readerPreparationOnlyV2) Apply(context.Context, RoutedSelectedPlanV1) error {
	return ErrRecovery
}
func (a *readerPreparationOnlyV2) Confirm(context.Context, RoutedSelectedPlanV1) error {
	return ErrRecovery
}
func (a *readerPreparationOnlyV2) Recover(context.Context, RoutedSelectedPlanV1) error {
	return ErrRecovery
}
func (a *readerPreparationOnlyV2) Bootstrap(context.Context, RoutedSelectedPlanV1, time.Time) error {
	return ErrRecovery
}

func selectedIntentFixtureV2(t *testing.T) (*RoutedSelectionReaderV2, *v2Coordinator, SelectionReferenceV2) {
	t.Helper()
	r, c, p := selectedReaderFixtureV2(t)
	work, _, load := routedWorkFixtureV2(t)
	var deps v2RoutedDependencies
	if err := load(work.Transition.Dependencies, &deps); err != nil {
		t.Fatal(err)
	}
	previous, err := bundleFromConfigurationV2(*c.store.state.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	authority := &readerPreparationOnlyV2{identity: r.options.Identity, previous: previous, snapshot: deps.Value.Prepared, interfaces: deps.Value.LocalInterfaces}
	c.options.Routed, c.options.RoutedIdentity = authority, authority.identity
	doc, objects := compositeRoutedFixture(t, true)
	fw := objects[doc.Domains.Firewall.Revision].Config
	if _, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &fw}); err != nil {
		t.Fatal("stage", err)
	}
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return ErrInterrupted
		}
		return nil
	}
	seconds := uint64(60)

	candidate, e := NewRoutedActivationBundleV1(c.store.state.Configuration.Firewall.Candidate.Revision, c.store.state.Configuration.LocalServices.Candidate.Revision)
	if e != nil {
		t.Fatal("candidate bundle", e)
	}
	prepared, e := authority.Prepare(context.Background(), candidate, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = routedPreparationV2(prepared, previous, candidate, true); e != nil {
		t.Fatal("fixture preparation", e)
	}
	_, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrInterrupted) || c.store.state.Configuration.Intent == nil {
		t.Fatal("durable selected intent missing", err)
	}
	ref, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal("intent observe", err)
	}
	return r, c, ref
}

func TestSelectedReaderV2SelectedIntentPurposeAndCorrelation(t *testing.T) {
	r, c, ref := selectedIntentFixtureV2(t)
	if ref.Mode != "intent" {
		t.Fatal(ref)
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionRecoverV2, SelectionMatchBeforeV2, SelectionMatchTargetV2} {
		plan, err := r.Resolve(context.Background(), ref, purpose)
		if err != nil || !plan.Valid() || plan.Scope().Identity != r.options.Identity {
			t.Fatal(purpose, err)
		}
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionConfirmV2, SelectionBootstrapV2, SelectionResumeV2, "unknown"} {
		if _, err := r.Resolve(context.Background(), ref, purpose); !errors.Is(err, ErrDenied) {
			t.Fatal(purpose, err)
		}
	}
	for _, change := range []func(*SelectionReferenceV2){func(v *SelectionReferenceV2) { v.Generation++ }, func(v *SelectionReferenceV2) { v.Sequence++ }, func(v *SelectionReferenceV2) { v.State = ref.Previous }, func(v *SelectionReferenceV2) { v.Selection = ref.Previous }, func(v *SelectionReferenceV2) { v.Previous = "" }, func(v *SelectionReferenceV2) { v.WorkHash = ref.State }, func(v *SelectionReferenceV2) { v.Lineage = ref.State }, func(v *SelectionReferenceV2) { v.Mode = "active" }} {
		bad := ref
		change(&bad)
		if _, err := r.Resolve(context.Background(), bad, SelectionArmV2); !errors.Is(err, ErrConflict) {
			t.Fatal("forged correlation", bad, err)
		}
	}
	r.options.Identity.Namespace++
	if _, err := r.Resolve(context.Background(), ref, SelectionArmV2); err == nil {
		t.Fatal("foreign namespace accepted")
	}
	if c.store.state.Configuration.Intent == nil {
		t.Fatal("reader changed selected intent")
	}
}

func TestSelectedReaderV2CorruptionPendingAndCancelled(t *testing.T) {
	for _, mode := range []string{"cancelled", "object", "pending", "permissions", "zero"} {
		t.Run(mode, func(t *testing.T) {
			r, c, _ := selectedReaderFixtureV2(t)
			ctx := context.Background()
			switch mode {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "object":
				name, _ := v2ObjectName(c.store.selection.State)
				if err := os.WriteFile(filepath.Join(c.store.root.Name(), name), []byte("{}"), 0640); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(filepath.Join(c.store.root.Name(), "selection.pending"), []byte("{}"), 0640); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(filepath.Join(c.store.root.Name(), "selected.json"), 0660); err != nil {
					t.Fatal(err)
				}
			case "zero":
				r = &RoutedSelectionReaderV2{}
			}
			if _, err := r.Observe(ctx); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}

func TestSelectedReaderV2RevalidationRejectsPoolAndSelectionChange(t *testing.T) {
	for _, mode := range []string{"pool", "selection"} {
		t.Run(mode, func(t *testing.T) {
			r, c, _ := selectedReaderFixtureV2(t)
			captured, err := r.read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := captured.graph.cache.close(captured.graph); err != nil {
					t.Error(err)
				}
			})
			if mode == "pool" {
				if _, err = c.store.reserves.admission.ClaimClass("independent-claim", recoveryreserve.OrdinaryV2); err != nil {
					t.Fatal(err)
				}
			} else {
				if err = c.store.publish(clone(c.store.state)); err != nil {
					t.Fatal(err)
				}
			}
			if err = r.revalidate(context.Background(), captured); err == nil {
				t.Fatal("changed source accepted")
			}
		})
	}
}

func TestSelectedReaderV2ResourceSample(t *testing.T) {
	r, _, _ := selectedReaderFixtureV2(t)
	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := r.Observe(context.Background()); err != nil {
				b.Fatal(err)
			}
		}
	})
	t.Logf("selected reader temporary-store sample: %s; %s; allocation volume, not appliance RSS", result.String(), result.MemString())
}
