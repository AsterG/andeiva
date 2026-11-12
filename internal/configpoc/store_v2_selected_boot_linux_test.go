//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func sharedBoundaryReaderV2(t *testing.T, c *v2Coordinator, a *boundaryAuthorityFixtureV2) *RoutedSelectionReaderV2 {
	t.Helper()
	c.store = sharedTestStoreV2(t, c.store)
	writers := make([]*recoveryreserve.PoolV2, 3)
	readers := make([]*recoveryreserve.ReadOnlyPoolV2, 3)
	for i, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
	}{{recoveryreserve.AdmissionV2, 4096}, {recoveryreserve.PlanV2, 16384}, {recoveryreserve.EmergencyV2, 8192}} {
		area, _ := checkpointFixtureArea(t)
		access := sharedTestAreaV2(t, area, "")
		var err error
		writers[i], err = recoveryreserve.PrepareSharedV2(area, 18, item.capacity, item.role, access)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = writers[i].Close() })
		profile, err := writers[i].Profile()
		if err != nil {
			t.Fatal(err)
		}
		readers[i], err = recoveryreserve.OpenReadOnlyV2(area, access, profile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = readers[i].Close() })
	}
	manager, err := newReserveManagerV2(writers[0], writers[1], writers[2])
	if err != nil {
		t.Fatal(err)
	}
	c.store.reserves, c.options.Reserves = manager, manager
	a.identity.UID = c.store.access.OwnerUID + 1
	c.options.RoutedIdentity = a.identity
	r, err := NewRoutedSelectionReaderV2(c.store.root, SelectionReaderOptionsV2{Access: *c.store.access, Identity: a.identity, Admission: readers[0], Plan: readers[1], Emergency: readers[2], Budget: reachabilityBudgetV2()})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSelectedReaderV2BootBoundaryRetainsBothReserveProofs(t *testing.T) {
	c, old, _, _ := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, old)
	boot := v2BootID(old.identity.BootID)
	c.options.BootID = &boot
	hook := func(point string) error {
		if point == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	c.options.Hook = hook
	c.store.mu.Lock()
	err := c.bootStartupLocked(context.Background(), boot)
	c.store.mu.Unlock()
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal("original boot", err)
	}
	original := c.store.state.Configuration.LastRecovery
	fresh := freshBoundaryAuthorityV2(old)
	options := c.options
	options.Routed, options.RoutedIdentity = fresh, fresh.identity
	newBoot := v2BootID(fresh.identity.BootID)
	options.BootID = &newBoot
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openSharedStoreV2(c.store.root, c.store.budget, *c.store.access)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openCoordinatorV2(context.Background(), reopened, c.firewall, c.local, options)
	t.Cleanup(func() {
		if opened != nil {
			opened.close()
		}
		_ = reopened.close()
	})
	if !errors.Is(err, ErrInterrupted) || reopened.state.RoutedBootBoundary == nil || reopened.state.RoutedBootBoundary.OldBoot == nil || reopened.state.RoutedBootBoundary.OldBoot.Object != original {
		t.Fatal("new boot boundary", err)
	}
	r.options.Identity = fresh.identity
	ref, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal("boundary closure", err)
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionBootstrapV2, SelectionConfirmV2, SelectionMatchBeforeV2, SelectionMatchTargetV2} {
		plan, err := r.Resolve(context.Background(), ref, purpose)
		if err != nil || !plan.Cold() || plan.Scope().Identity != fresh.identity {
			t.Fatal(purpose, err)
		}
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionRecoverV2, SelectionResumeV2} {
		if _, err := r.Resolve(context.Background(), ref, purpose); !errors.Is(err, ErrDenied) {
			t.Fatal(purpose, err)
		}
	}
	if fresh.bootstraps != 0 || fresh.applies != 0 || old.bootstraps != 0 {
		t.Fatal("reader invoked effects")
	}
}

func TestSelectedReaderV2PendingAndConfirmIntentAreDistinct(t *testing.T) {
	c, a, principal, target := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, a)
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &target}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	op, result, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal("commit", err)
	}
	pending, err := r.Observe(context.Background())
	if err != nil || pending.Mode != "pending" || !validHash(pending.WorkHash) {
		t.Fatal(pending, err)
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionMatchBeforeV2, SelectionMatchTargetV2} {
		if _, err = r.Resolve(context.Background(), pending, purpose); err != nil {
			t.Fatal(purpose, err)
		}
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionConfirmV2, SelectionRecoverV2, SelectionResumeV2} {
		if _, err = r.Resolve(context.Background(), pending, purpose); !errors.Is(err, ErrDenied) {
			t.Fatal(purpose, err)
		}
	}
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return ErrInterrupted
		}
		return nil
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: op.ID, Target: result.Current.Running.Hash}); !errors.Is(err, ErrInterrupted) {
		t.Fatal("confirm intent", err)
	}
	confirming, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if confirming.Mode != "intent" || confirming.WorkHash != pending.WorkHash || confirming.Selection == pending.Selection {
		t.Fatal("wrong confirmation correlation")
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionConfirmV2, SelectionRecoverV2} {
		if _, err = r.Resolve(context.Background(), confirming, purpose); err != nil {
			t.Fatal(purpose, err)
		}
	}
	if _, err = r.Resolve(context.Background(), pending, SelectionConfirmV2); !errors.Is(err, ErrConflict) {
		t.Fatal("old pending authorized confirm", err)
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionBootstrapV2, SelectionResumeV2} {
		if _, err = r.Resolve(context.Background(), confirming, purpose); !errors.Is(err, ErrDenied) {
			t.Fatal(purpose, err)
		}
	}
}

func TestSelectedReaderV2FinalActiveAllowsOnlyResumeAndMatch(t *testing.T) {
	c, a, p, target := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, a)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &target}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	op, pending, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpConfirm, Origin: op.ID, Target: pending.Current.Running.Hash}); err != nil {
		t.Fatal(err)
	}
	ref, err := r.Observe(context.Background())
	if err != nil || ref.Mode != "active" {
		t.Fatal(ref, err)
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionResumeV2, SelectionMatchBeforeV2, SelectionMatchTargetV2} {
		if _, err = r.Resolve(context.Background(), ref, purpose); err != nil {
			t.Fatal(purpose, err)
		}
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionConfirmV2, SelectionRecoverV2, SelectionBootstrapV2} {
		if _, err = r.Resolve(context.Background(), ref, purpose); !errors.Is(err, ErrDenied) {
			t.Fatal(purpose, err)
		}
	}
	view, err := r.PrepareView(context.Background(), ref)
	if err != nil || view.Baseline == nil || view.Saved.Firewall.Config.SchemaVersion != 4 || view.Current.Firewall.Config.SchemaVersion != 6 {
		t.Fatal("retained baseline", err)
	}
}
