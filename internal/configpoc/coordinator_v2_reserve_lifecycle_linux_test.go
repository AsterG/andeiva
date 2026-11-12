//go:build linux

package configpoc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func attachReserveManagerV2(t *testing.T, c *v2Coordinator) *v2ReserveManager {
	manager, _ := attachReserveAreasV2(t, c)
	return manager
}

func attachReserveAreasV2(t *testing.T, c *v2Coordinator) (*v2ReserveManager, []*os.Root) {
	t.Helper()
	pools := []*recoveryreserve.PoolV2{}
	areas := []*os.Root{}
	for _, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
	}{{recoveryreserve.AdmissionV2, 4096}, {recoveryreserve.PlanV2, 16384}, {recoveryreserve.EmergencyV2, 8192}} {
		area, _ := checkpointFixtureArea(t)
		pool, err := recoveryreserve.PrepareV2(area, 18, item.capacity, item.role)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pool.Close() })
		pools = append(pools, pool)
		areas = append(areas, area)
	}
	manager, err := newReserveManagerV2(pools[0], pools[1], pools[2])
	if err != nil {
		t.Fatal(err)
	}
	if err = c.store.enableClosingCreditsLocked(); err != nil {
		t.Fatal(err)
	}
	c.store.reserves = manager
	c.options.Reserves = manager
	return manager, areas
}

func TestReserveCoordinatorLifecycleArchivesAndReuses(t *testing.T) {
	c, area, _, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	for i := range 70 {
		result := coordinatorV2Stage(t, c, p, fmt.Sprintf("rule-%d", i))
		if result.Operation.Reserve == nil || result.Operation.Reserve.Plan == nil {
			t.Fatal("missing selected physical plan")
		}
		if len(c.store.state.ActiveReserves) != 0 || c.store.state.ReservedBytes != 0 || c.store.state.ReservedInodes != 0 || c.store.state.ReserveArchiveRoot == "" {
			t.Fatalf("terminal reservations not retired at %d", i)
		}
		archive, known, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: result.Operation.Reserve.Claims.Admission}, "claim")
		if err != nil || !known || validateArchiveFinalityV2(archive, c.store.state, c.store.readObject) != nil {
			t.Fatalf("missing terminal canonical bytes at %d: %v", i, err)
		}
	}
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatalf("real selected archives are not a complete graph: %v %+v", err, report)
	}
}

func TestReserveCoordinatorCommitConfirmArchive(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	coordinatorV2Stage(t, c, p, "confirmed")
	seconds := uint64(90)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if committed.Current.Pending == nil || len(c.store.state.ActiveReserves) != 1 || len(c.store.state.ClosingCredits) != 1 {
		t.Fatal("lease did not retain all resources")
	}
	confirmed := coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.Running.Hash})
	if confirmed.Current.Pending != nil || len(c.store.state.ActiveReserves) != 0 || len(c.store.state.ClosingCredits) != 0 || c.store.state.ReservedBytes != 0 {
		t.Fatal("confirmed lease not archived/released")
	}
	for _, engine := range engines[:2] {
		if engine.Current() != confirmed.Current.Firewall.Running.Hash {
			t.Fatal("selected state differs from simulated engine")
		}
	}
}

func TestReserveCoordinatorGateRejectsMissingResourcesBeforeEngine(t *testing.T) {
	c, _, engines, _, _ := coordinatorV2Fixture(t, false)
	if err := c.store.enableClosingCreditsLocked(); err != nil {
		t.Fatal(err)
	}
	for _, engine := range engines {
		engine.reset()
	}
	_, err := openCoordinatorV2(context.Background(), c.store, c.firewall, c.local, v2CoordinatorOptions{Now: c.options.Now, ManualTimeout: true})
	if err == nil {
		t.Fatal("marker accepted without trusted pools")
	}
	for _, engine := range engines {
		if engine.reads.Load() != 0 || engine.applies.Load() != 0 || engine.validations.Load() != 0 {
			t.Fatal("engine touched before resource gate")
		}
	}
}

func TestReserveCoordinatorInterruptedMaintenanceReopensExactProof(t *testing.T) {
	for _, point := range []string{"reserve_archive_selected", "reserve_archive_anchored", "reserve_role_retired", "reserve_physical_retired"} {
		t.Run(point, func(t *testing.T) {
			c, area, engines, p, _ := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			c.store.hook = func(stage string) error {
				if stage == point {
					return ErrInterrupted
				}
				return nil
			}
			config := coordinatorV2Rule("interrupted-archive")
			op, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpStage, Config: &config})
			if !errors.Is(err, ErrInterrupted) {
				t.Fatalf("interruption not reached: %v", err)
			}
			reads := engines[0].applies.Load()
			reopened, err := reopenBootV2(t, c, area, nil, nil)
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			if len(reopened.store.state.ActiveReserves) != 0 || reopened.store.state.ReservedBytes != 0 {
				t.Fatal("maintenance ownership escaped restart")
			}
			result, err := reopened.execute(context.Background(), p, op.ID)
			if err != nil || result.Operation.State != "final" || engines[0].applies.Load() != reads {
				t.Fatal("terminal replay changed engines", err)
			}
		})
	}
}

func TestReserveCoordinatorExpiredOrdinaryCannotStarveConfirm(t *testing.T) {
	c, _, _, p, now := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	coordinatorV2Stage(t, c, p, "lease-with-open-work")
	ns, err := c.store.namespace(p.Subject, "firewall", *now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// The pre-existing reusable namespace is explicitly shortened by trusted
	// fixture setup, rather than manufacturing an impossible expiry contract.
	st := clone(c.store.state)
	st.Namespaces[c.store.namespaceIndex(p.Subject, ns.ID)].AdmitUntil = now.Add(time.Second)
	if err = c.store.publish(st); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	for range 7 {
		if _, err = c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpValidate}, *now); err != nil {
			t.Fatal(err)
		}
	}
	*now = now.Add(2 * time.Second)
	if err = c.store.expire(*now); err != nil {
		t.Fatal(err)
	}
	if len(c.store.state.ActiveReserves) != 8 {
		t.Fatal("expected one pinned and seven held ordinary bundles")
	}
	c.store.budget = v2Budget{Bytes: c.store.used.Bytes + c.store.state.ReservedBytes + 1024, Inodes: c.store.used.Inodes + c.store.state.ReservedInodes + 1}
	result := coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.Running.Hash})
	if result.Current.Pending != nil || len(c.store.state.ActiveReserves) != 0 || c.store.state.ReservedBytes != 0 {
		t.Fatal("Confirm did not drain exact held owners")
	}
}

func TestReserveCoordinatorTimeoutArchivesUnusedClosingEscrow(t *testing.T) {
	c, area, _, p, now := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	before := c.store.state.Configuration.Running.Hash
	coordinatorV2Stage(t, c, p, "timeout-escrow")
	seconds := uint64(30)
	result := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	*now = now.Add(31 * time.Second)
	if err := c.tick(context.Background(), *now); err != nil {
		t.Fatal(err)
	}
	if c.store.state.Configuration.Running.Hash != before || len(c.store.state.ActiveReserves) != 0 || len(c.store.state.ClosingCredits) != 0 || c.store.state.ReservedBytes != 0 {
		t.Fatal("timeout did not release resolved exact group")
	}
	archive, known, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: result.Operation.Reserve.Claims.Admission}, "claim")
	if err != nil || !known || len(archive.UnusedEscrow) != 3 || archive.Child != "" || archive.LeaseResolution == "" {
		t.Fatal("unused escrow not archived as real origin", err)
	}
	c.close()
	_ = c.store.close()
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal(report, err)
	}
}

func TestReserveCoordinatorBootUsesSystemAndRetires(t *testing.T) {
	c, area, engines, _ := bootFixtureV2(t)
	attachReserveManagerV2(t, c)
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	if booted.store.state.SystemBundle != nil || booted.store.state.ReservedBytes != 0 {
		t.Fatal("system bundle not retired")
	}
	var record v2RecoveryRecord
	if err = booted.store.readObject(booted.store.state.Configuration.LastCompletedBoot, &record); err != nil || record.Reserve == nil || record.Reserve.Claims.Admission.Slot < 16 {
		t.Fatal("boot did not use dedicated system class", err)
	}
	for _, engine := range engines[:2] {
		if engine.Current() != booted.store.state.Configuration.Firewall.Startup.Hash {
			t.Fatal("boot readback mismatch")
		}
	}
	booted.close()
	_ = booted.store.close()
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal(report, err)
	}
}

func TestReserveCoordinatorFailedFinalPublicationKeepsLastGoodAndRecovers(t *testing.T) {
	c, area, engines, p, now := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	coordinatorV2Stage(t, c, p, "partial-final")
	for c.store.used.Inodes < 256 {
		if _, err := c.store.object(struct {
			Purpose string
			Index   uint64
		}{"inactive test padding", c.store.used.Inodes}); err != nil {
			t.Fatal(err)
		}
	}
	before := clone(c.store.state)
	zero := uint64(0)
	ns, err := c.store.namespace(p.Subject, "firewall", *now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.store.admit(p.Subject, ns.ID, before.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &zero}, *now)
	if err != nil {
		t.Fatal(err)
	}
	c.store.budget.Inodes = c.store.used.Inodes + c.store.state.ReservedInodes
	c.options.Hook = func(point string) error {
		if point == "after_readback" {
			c.store.hook = func(point string) error {
				if point == "before_select" {
					return ErrInterrupted
				}
				return nil
			}
		}
		return nil
	}
	_, err = c.execute(context.Background(), p, op.ID)
	if err == nil || !c.store.blocked || c.store.state.Configuration.Intent == nil || c.store.state.Configuration.Running.Hash != before.Configuration.Running.Hash {
		t.Fatal("failed final selection published target", err)
	}
	for _, engine := range engines[:2] {
		if engine.Current() != before.Configuration.Firewall.Running.Hash {
			t.Fatal("storage ambiguity did not compensate real simulated component")
		}
	}
	*now = now.Add(time.Second)
	resumed, err := reopenBootV2(t, c, area, nil, nil)
	if err != nil {
		t.Fatal("restart after partial final publication", err)
	}
	final, err := resumed.store.lookup(p.Subject, op.ID)
	if err != nil || final.State != "final" || final.Outcome.Code != "failed_rolled_back" || len(resumed.store.state.ActiveReserves) != 0 || resumed.store.state.ReservedBytes != 0 {
		t.Fatal("partial finalization could not close", err)
	}
}

func TestReserveCoordinatorEmergencyFailureRetainsMutationFence(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	m := attachReserveManagerV2(t, c)
	initial := clone(c.store.state.Configuration)
	coordinatorV2Stage(t, c, p, "emergency-failure")
	engines[0].base.SetFailure(initial.Firewall.Running.Hash, "before")
	engines[1].base.FailNext("before")
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return m.emergency.Close()
		}
		return nil
	}
	zero := uint64(0)
	_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	if !errors.Is(err, ErrRecovery) || !c.store.blocked || c.store.state.Configuration.Intent == nil || len(c.store.state.ActiveReserves) != 1 || c.store.state.Configuration.Running.Hash != initial.Running.Hash {
		t.Fatal("failed emergency persistence lost selected fence", err)
	}
	if err = m.maintain(c.store); !errors.Is(err, ErrRecovery) {
		t.Fatal("unverified emergency authorized retirement", err)
	}
}
