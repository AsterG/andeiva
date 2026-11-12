//go:build linux

package configpoc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func attachReserveManagerV2(t *testing.T, c *v2Coordinator) *v2ReserveManager {
	t.Helper()
	pools := []*recoveryreserve.PoolV2{}
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
	return manager
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
		archive, known, err := c.store.reserveArchiveLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: result.Operation.Reserve.Claims.Admission}, "claim")
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
