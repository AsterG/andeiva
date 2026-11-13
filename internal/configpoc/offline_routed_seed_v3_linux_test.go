//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func offlineSeedFixtureV3(t *testing.T) (*os.Root, RuntimePoolsV2, Revision, Revision, []SubjectV2, BudgetV2) {
	t.Helper()
	area, _ := checkpointFixtureArea(t)
	var pools []*recoveryreserve.PoolV2
	for _, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
	}{{recoveryreserve.AdmissionV2, 4096}, {recoveryreserve.PlanV2, 16384}, {recoveryreserve.EmergencyV2, 8192}} {
		poolArea, _ := checkpointFixtureArea(t)
		pool, err := recoveryreserve.PrepareV2(poolArea, 18, item.capacity, item.role)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pool.Close() })
		pools = append(pools, pool)
	}
	fw, err := Canonical(Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	ls, err := Canonical(Config{SchemaVersion: 3, DefaultAction: "deny", Rules: []Rule{}, LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	return area, RuntimePoolsV2{Admission: pools[0], Plan: pools[1], Emergency: pools[2]}, fw, ls, []SubjectV2{{ID: id, Login: "seed-admin", CredentialRevision: checkpointDigest([]byte("test-only-revision"))}}, BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}
}

func TestOfflineRoutedSeedV3DeclaredNotVerified(t *testing.T) {
	area, pools, fw, ls, subjects, budget := offlineSeedFixtureV3(t)
	if err := PrepareOfflineRoutedStoreV3(context.Background(), area, budget, pools, fw, ls, subjects, time.Now()); err != nil {
		t.Fatal(err)
	}
	if incompatible, err := openV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes}); err == nil {
		_ = incompatible.close()
		t.Fatal("private reader accepted shared seed")
	}
	access := sharedTestAreaV2(t, area, "checkpoint.lock")
	store, err := openSharedStoreV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes}, access)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	cfg := *store.state.Configuration
	if !declaredOfflineSeedV3(store.state, cfg, store.readObject) || cfg.VerifiedIndex != "" || store.state.Operational || cfg.LastCompletedBoot != "" {
		t.Fatal("offline declaration acquired physical authority")
	}
	if err = (&v2Coordinator{store: store}).validateReferencesLocked(); err != nil {
		t.Fatal("declaration rejected before physical bootstrap", err)
	}
	engines := []Engine{NewSimEngine("never-called-firewall")}
	if _, err = openCoordinatorV2(context.Background(), store, engines, []Engine{NewSimEngine("never-called-local")}, v2CoordinatorOptions{}); !errors.Is(err, ErrRecovery) {
		t.Fatal("seed opened without real runtime assembly", err)
	}
	root, err := area.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	reader := &v2ReachabilityReader{ctx: context.Background(), area: area, root: root, shared: &access, budget: reachabilityBudgetV2(), objects: map[string]bool{}, edges: map[string]uint8{}}
	if _, err = reader.traceLocked(store.lock); err != nil {
		t.Fatal("declared seed integrity", err)
	}
	changed := clone(store.state)
	changed.Generation++
	if declaredOfflineSeedV3(changed, cfg, store.readObject) {
		t.Fatal("later generation reused initial seed exception")
	}
	if err = PrepareOfflineRoutedStoreV3(context.Background(), area, budget, pools, fw, ls, subjects, time.Now()); err == nil {
		t.Fatal("reseed overwrote existing installation")
	}
}

func TestOfflineRoutedSeedV3RejectsInputsBeforePublication(t *testing.T) {
	for _, kind := range []string{"cancelled", "foreign", "hash", "rules", "subjects", "pools"} {
		t.Run(kind, func(t *testing.T) {
			area, pools, fw, ls, subjects, budget := offlineSeedFixtureV3(t)
			ctx := context.Background()
			switch kind {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "foreign":
				if err := area.WriteFile("foreign", []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "hash":
				fw.Hash = checkpointDigest([]byte("wrong"))
			case "rules":
				var err error
				fw, err = Canonical(coordinatorV2Rule("not-fresh"))
				if err != nil {
					t.Fatal(err)
				}
			case "subjects":
				subjects = nil
			case "pools":
				pools.Plan = pools.Admission
			}
			if err := PrepareOfflineRoutedStoreV3(ctx, area, budget, pools, fw, ls, subjects, time.Now()); err == nil {
				t.Fatal("unsafe seed accepted")
			}
			if _, err := area.Stat("selected.json"); !os.IsNotExist(err) {
				t.Fatal("invalid input published selector", err)
			}
			if kind == "foreign" {
				data, err := area.ReadFile("foreign")
				if err != nil || string(data) != "preserve" {
					t.Fatal("foreign data changed", err)
				}
			}
		})
	}
}
