//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"
)

func TestFencedContinuationV1KeepsOriginalRecovery(t *testing.T) {
	r, c, _ := selectedIntentFixtureV2(t)
	anchor, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	if _, err := r.ResolveFencedContinuationV1(context.Background(), anchor, expected, SelectionRecoverV2); err != nil {
		t.Fatal("original compensation blocked", err)
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionBootstrapV2, SelectionConfirmV2, SelectionResumeV2} {
		if _, err := r.ResolveFencedContinuationV1(context.Background(), anchor, expected, purpose); err == nil {
			t.Fatal("fence authorized new effects", purpose)
		}
	}
}

func TestFencedContinuationV1DistinguishesSelectedFromNewBootstrap(t *testing.T) {
	c, authority, _, _ := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, authority)
	before, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	boot := v2BootID(authority.identity.BootID)
	c.options.BootID = &boot
	c.options.Hook = func(point string) error {
		if point == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	if err := c.bootStartupLocked(context.Background(), boot); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionBootstrapV2, SelectionConfirmV2} {
		if _, err := r.ResolveFencedContinuationV1(context.Background(), before, expected, purpose); err == nil {
			t.Fatal("quiescent fenced anchor authorized new boot", purpose)
		}
	}
	selected, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveFencedContinuationV1(context.Background(), selected, expected, SelectionConfirmV2); err != nil {
		t.Fatal("already selected boot closing denied", err)
	}
	if _, err := r.ResolveFencedContinuationV1(context.Background(), selected, expected, SelectionBootstrapV2); err == nil {
		t.Fatal("fence permitted bootstrap application")
	}
}

func TestFencedContinuationV1RejectsNewPendingConfirmation(t *testing.T) {
	c, authority, principal, firewall := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, authority)
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &firewall}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(60)
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); err != nil {
		t.Fatal(err)
	}
	pending := clone(*c.store.state.Configuration.Pending)
	anchor, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return ErrInterrupted
		}
		return nil
	}
	_, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: pending.OriginCommit, Target: pending.Target})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	expected := coldPlanReferenceV1(t, r, c)
	if _, err := r.ResolveFencedContinuationV1(context.Background(), anchor, expected, SelectionConfirmV2); err == nil {
		t.Fatal("fenced pending anchor authorized newly admitted confirmation")
	}
	selected, err := r.CaptureColdAnchorV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveFencedContinuationV1(context.Background(), selected, expected, SelectionConfirmV2); err != nil {
		t.Fatal("already selected confirmation denied", err)
	}
}
