//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// The shared boundary fixture models OS incarnation changes. This wrapper
// supplies the existing same-incarnation cold rollback readback semantics.
type coldRecoveryAuthorityV1 struct{ *boundaryAuthorityFixtureV2 }

func (a coldRecoveryAuthorityV1) Recover(ctx context.Context, p RoutedSelectedPlanV1) error {
	if err := a.boundaryAuthorityFixtureV2.Recover(ctx, p); err != nil {
		return err
	}
	if p.Cold() {
		a.current = ""
	}
	return nil
}

func coldPlanReferenceV1(t *testing.T, r *RoutedSelectionReaderV2, c *v2Coordinator) RoutedWorkReferenceV1 {
	t.Helper()
	p, err := selectedRoutedPlanFromStoreV2(c.store, r.options.Identity)
	if err != nil {
		t.Fatal(err)
	}
	return p.Reference()
}

func TestColdContinuationV1SelectedIntentAndOpaqueAnchor(t *testing.T) {
	r, c, _ := selectedIntentFixtureV2(t)
	anchor, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	if data, err := json.Marshal(anchor); err != nil || string(data) != "{}" {
		t.Fatal("anchor serialized", string(data), err)
	}
	before := integrityFilesV1(t, c.store.root)
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionRecoverV2, SelectionMatchBeforeV2, SelectionMatchTargetV2} {
		plan, err := r.ResolveColdContinuationV1(context.Background(), anchor, expected, purpose)
		if err != nil || plan.Reference() != expected {
			t.Fatal(purpose, err)
		}
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionBootstrapV2, SelectionConfirmV2, SelectionResumeV2, "unknown"} {
		if _, err = r.ResolveColdContinuationV1(context.Background(), anchor, expected, purpose); err == nil {
			t.Fatal("unauthorized cold purpose", purpose)
		}
	}
	foreign := expected
	foreign.Generation++
	if _, err = r.ResolveColdContinuationV1(context.Background(), anchor, foreign, SelectionRecoverV2); err == nil {
		t.Fatal("foreign work generation accepted")
	}
	other := &RoutedSelectionReaderV2{area: r.area, options: r.options}
	if _, err = other.ResolveColdContinuationV1(context.Background(), anchor, expected, SelectionRecoverV2); err == nil {
		t.Fatal("anchor transferred to another reader")
	}
	if _, err = r.ResolveColdContinuationV1(context.Background(), RoutedColdAnchorV1{}, expected, SelectionRecoverV2); err == nil {
		t.Fatal("zero anchor accepted")
	}
	after := integrityFilesV1(t, c.store.root)
	if len(before) != len(after) {
		t.Fatal("reader changed files")
	}
	for name, hash := range before {
		if after[name] != hash {
			t.Fatal("reader changed file", name)
		}
	}
}

func TestColdContinuationV1FreshOrdinaryWorkRejected(t *testing.T) {
	c, a, p, fw := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, a)
	anchor, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &fw}); err != nil {
		t.Fatal(err)
	}
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return ErrInterrupted
		}
		return nil
	}
	seconds := uint64(60)
	if _, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionRecoverV2, SelectionArmV2, SelectionApplyV2, SelectionConfirmV2, SelectionMatchBeforeV2} {
		if _, err = r.ResolveColdContinuationV1(context.Background(), anchor, expected, purpose); err == nil {
			t.Fatal("new ordinary work accepted during cold", purpose)
		}
	}
}

func TestColdContinuationV1PendingRecoveryAndFinalResume(t *testing.T) {
	c, a, p, fw := boundaryCoordinatorFixtureV2(t)
	c.options.Routed = coldRecoveryAuthorityV1{a}
	r := sharedBoundaryReaderV2(t, c, a)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &fw}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(60)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); err != nil {
		t.Fatal(err)
	}
	anchor, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deadline := c.store.state.Configuration.Pending.Deadline
	c.options.Hook = func(point string) error {
		if point == "after_recovery_intent" {
			return ErrInterrupted
		}
		return nil
	}
	if err = c.revertLocked(context.Background(), "restart"); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	plan, err := r.ResolveColdContinuationV1(context.Background(), anchor, expected, SelectionRecoverV2)
	if err != nil || !plan.Deadline().Equal(deadline) {
		t.Fatal("original pending recovery lost", err)
	}
	c.options.Hook = nil
	if err = c.finishRecoveryLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	plan, err = r.ResolveColdContinuationV1(context.Background(), anchor, expected, SelectionResumeV2)
	if err != nil || plan.Resolution() != "before" {
		t.Fatal("recovered resume", err)
	}
	coldBootAfterCompletionV1(t, r, c, a, anchor)
}

func TestColdContinuationV1FreshBootExactPredecessor(t *testing.T) {
	c, a, _, _ := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, a)
	anchor, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	boot := v2BootID(a.identity.BootID)
	c.options.BootID = &boot
	c.options.Hook = func(point string) error {
		if point == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	if err = c.bootStartupLocked(context.Background(), boot); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionBootstrapV2, SelectionConfirmV2, SelectionMatchBeforeV2, SelectionMatchTargetV2} {
		plan, err := r.ResolveColdContinuationV1(context.Background(), anchor, expected, purpose)
		if err != nil || !plan.Deadline().Equal(plan.bootRecord.Started.Add(10*time.Second)) {
			t.Fatal(purpose, err)
		}
	}
	// Internal negative: same Running hash with different complete configuration
	// is not a predecessor proof. This is not an external token constructor.
	forged := anchor
	forged.configuration.Firewall.Generation++
	_, forged.configurationHash, err = v2Canonical(forged.configuration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.ResolveColdContinuationV1(context.Background(), forged, expected, SelectionBootstrapV2); err == nil {
		t.Fatal("Running-only anchor accepted", err)
	}
	plan, err := selectedRoutedPlanFromStoreV2(c.store, r.options.Identity)
	if err != nil {
		t.Fatal(err)
	}
	plan.work.Deadline = plan.work.Deadline.Add(time.Nanosecond)
	if coldContinuationLinkedV1(anchor, plan, SelectionBootstrapV2) {
		t.Fatal("original boot deadline changed")
	}
}

func coldBootAfterCompletionV1(t *testing.T, r *RoutedSelectionReaderV2, c *v2Coordinator, a *boundaryAuthorityFixtureV2, anchor RoutedColdAnchorV1) {
	t.Helper()
	// Preparation/effects remain simulated. This models a cold bootstrap request
	// after the real coordinator has durably completed compensation.
	a.current = ""
	a.receipt = RoutedReceiptV1{Phase: "bootstrap"}
	boot := v2BootID(a.identity.BootID)
	c.options.BootID = &boot
	c.options.Hook = func(point string) error {
		if point == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	if err := c.bootStartupLocked(context.Background(), boot); !errors.Is(err, ErrInterrupted) {
		t.Fatal("post-completion boot intent", err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionBootstrapV2, SelectionConfirmV2} {
		if _, err := r.ResolveColdContinuationV1(context.Background(), anchor, expected, purpose); err != nil {

			t.Fatal("post-completion boot linkage", purpose, err)
		}
	}
	for _, change := range []func(*RoutedColdAnchorV1){
		func(v *RoutedColdAnchorV1) { v.configuration.AuditTip = checkpointDigest([]byte("foreign audit")) },
		func(v *RoutedColdAnchorV1) {
			v.configuration.Startup.Hash = checkpointDigest([]byte("foreign startup"))
		},
		func(v *RoutedColdAnchorV1) { v.reference.Generation++ },
	} {
		bad := anchor
		bad.configuration = clone(anchor.configuration)
		change(&bad)
		_, bad.configurationHash, _ = v2Canonical(bad.configuration)
		if _, err := r.ResolveColdContinuationV1(context.Background(), bad, expected, SelectionBootstrapV2); err == nil {
			t.Fatal("altered completion lineage accepted")
		}
	}
}
