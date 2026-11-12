//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// This authority models transport/effect replies only. Store, reservations,
// canonical validation and coordinator recovery are real; no kernel is used.
type boundaryAuthorityFixtureV2 struct {
	identity                            networkexecutor.OwnedNamespaceIdentity
	legacy                              Revision
	local                               Revision
	prepared                            networkexecutor.PreparedSnapshot
	current                             string
	receipt                             RoutedReceiptV1
	applies, arms, bootstraps, recovers int
	foreign                             int
}

func (a *boundaryAuthorityFixtureV2) Identity() networkexecutor.OwnedNamespaceIdentity {
	return a.identity
}
func (a *boundaryAuthorityFixtureV2) Prepare(_ context.Context, target RoutedActivationBundleV1, _ *RoutedBaselineV1) (RoutedPreparationV1, error) {
	before := OwnedV1{Version: 1, Network: a.prepared, NetworkState: Baseline, LegacyFirewall: TableStateV1{Presence: Present, Revision: &a.legacy}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}}
	after := clone(before)
	after.NetworkState = Configured
	after.LegacyFirewall = TableStateV1{Presence: Absent}
	after.RoutedFirewall = TableStateV1{Presence: Present, Revision: &target.Firewall}
	after.LocalServices = TableStateV1{Presence: Present, Revision: &target.LocalServices}
	return RoutedPreparationV1{Before: before, Target: after, Dependencies: DependenciesV1{Version: 1, Network: target.Firewall.Config.Routed.Network, Prepared: a.prepared, LocalInterfaces: target.LocalServices.Config.LocalServices.Interfaces}}, nil
}
func (a *boundaryAuthorityFixtureV2) PrepareBoot(_ context.Context, target, saved RoutedActivationBundleV1) (RoutedPreparationV1, error) {
	observed := networkexecutor.ObservedSnapshot{Version: 1, Links: a.prepared.Links, Routes: a.prepared.Routes}
	raw, _ := json.Marshal(observed)
	observed.Hash = checkpointDigest(raw)
	before := OwnedV1{Version: 2, NetworkState: NoNetwork, Observed: &observed, LegacyFirewall: TableStateV1{Presence: Absent}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}}
	after := clone(before)
	after.LegacyFirewall = TableStateV1{Presence: Present, Revision: &target.Firewall}
	if target.Firewall.Config.SchemaVersion != 4 || saved.Firewall.Hash != target.Firewall.Hash {
		return RoutedPreparationV1{}, ErrRecovery
	}
	return RoutedPreparationV1{Before: before, Target: after, Dependencies: DependenciesV1{Version: 2, NetworkMode: "none", Observed: &observed}}, nil
}
func (a *boundaryAuthorityFixtureV2) Observe(context.Context) (RoutedReceiptV1, string, error) {
	return a.receipt, a.current, nil
}
func (a *boundaryAuthorityFixtureV2) check(p RoutedSelectedPlanV1) error {
	if !p.Valid() || p.Scope().Identity != a.identity {
		a.foreign++
		return ErrRecovery
	}
	return nil
}
func (a *boundaryAuthorityFixtureV2) Match(_ context.Context, p RoutedSelectedPlanV1, side string) error {
	if err := a.check(p); err != nil {
		return err
	}
	want := p.target.Composite.Hash
	if side == "before" {
		want = p.previous.Composite.Hash
		if p.Cold() {
			want = ""
		}
	}
	if a.current != want {
		return ErrRecovery
	}
	return nil
}
func (a *boundaryAuthorityFixtureV2) Resume(ctx context.Context, p RoutedSelectedPlanV1) error {
	return a.Match(ctx, p, p.Resolution())
}
func (a *boundaryAuthorityFixtureV2) Arm(_ context.Context, p RoutedSelectedPlanV1) error {
	if err := a.check(p); err != nil {
		return err
	}
	a.arms++
	a.receipt = RoutedReceiptV1{Phase: "armed", ID: p.Lease(), Target: p.target.Composite.Hash, Deadline: p.Deadline()}
	return nil
}
func (a *boundaryAuthorityFixtureV2) Apply(_ context.Context, p RoutedSelectedPlanV1) error {
	if err := a.check(p); err != nil {
		return err
	}
	a.applies++
	a.current = p.target.Composite.Hash
	a.receipt.Phase = "pending"
	return nil
}
func (a *boundaryAuthorityFixtureV2) Confirm(_ context.Context, p RoutedSelectedPlanV1) error {
	if err := a.check(p); err != nil {
		return err
	}
	a.receipt.Phase = "idle"
	return nil
}
func (a *boundaryAuthorityFixtureV2) Recover(_ context.Context, p RoutedSelectedPlanV1) error {
	if err := a.check(p); err != nil {
		return err
	}
	a.recovers++
	a.current = p.previous.Composite.Hash
	a.receipt.Phase = "idle"
	return nil
}
func (a *boundaryAuthorityFixtureV2) Bootstrap(_ context.Context, p RoutedSelectedPlanV1, started time.Time) error {
	if err := a.check(p); err != nil {
		return err
	}
	if !started.Add(10 * time.Second).Equal(p.Deadline()) {
		return ErrRecovery
	}
	if a.receipt.ID == p.Lease() && a.receipt.Deadline.Equal(p.Deadline()) && a.current == p.target.Composite.Hash {
		return nil
	}
	a.bootstraps++
	a.applies++
	a.current = p.target.Composite.Hash
	a.receipt = RoutedReceiptV1{Phase: "pending", ID: p.Lease(), Target: p.target.Composite.Hash, Deadline: p.Deadline()}
	return nil
}

func boundaryCoordinatorFixtureV2(t *testing.T) (*v2Coordinator, *boundaryAuthorityFixtureV2, v2TrustedPrincipal, Config) {
	t.Helper()
	doc, objects := compositeRoutedFixture(t, true)
	target := objects[doc.Domains.Firewall.Revision].Config
	localConfig := Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}, {Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}}}, Services: []localpolicy.Service{}}}
	legacy := func(config Config) (*os.Root, Revision) {
		area, path := checkpointFixtureArea(t)
		store, err := openStore(path, 2048)
		if err != nil {
			t.Fatal(err)
		}
		revision, err := Canonical(config)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := Snapshot{Generation: 1, Running: revision, Startup: revision, LastGood: revision, Revoked: []string{}}
		if err = store.append(durableState{Snapshot: snapshot, Receipts: map[string]receipt{}}, Audit{Sequence: 1, Actor: "alice", At: time.Now().UTC(), Operation: OpSave, Surface: API, Result: "success", RunningHash: revision.Hash}, true, nil); err != nil {
			t.Fatal(err)
		}
		_ = store.lock.Close()
		return area, revision
	}
	fwConfig := coordinatorV2Rule("imported-tcp")
	udp := clone(fwConfig.Rules[0])
	udp.ID = "imported-udp"
	udp.Match.Protocol = "udp"
	fwConfig.Rules = append(fwConfig.Rules, udp)
	fw, fwRev := legacy(fwConfig)
	ls, lsRev := legacy(localConfig)
	area, _ := checkpointFixtureArea(t)
	subject := "durable-subject"
	store, err := prepareMigrationV2(area, fw, ls, []v2Subject{{ID: subject, Login: "alice", CredentialRevision: checkpointDigest([]byte("credential"))}}, nil, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	engines := []Engine{NewSimEngine("fw"), NewSimEngine("local")}
	engines[0].(*SimEngine).Drift(fwRev.Hash)
	engines[1].(*SimEngine).Drift(lsRev.Hash)
	c, err := openCoordinatorV2(context.Background(), store, engines[:1], engines[1:], v2CoordinatorOptions{ManualTimeout: true})
	if err != nil {
		t.Fatal(err)
	}
	attachReserveManagerV2(t, c)
	if err = c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); err != nil {
		t.Fatal(err)
	}
	snapshot := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: target.Routed.Network.Hash, Links: []networkexecutor.SnapshotLink{{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}, {Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}}, Routes: []networkexecutor.SnapshotRoute{}}
	raw, _ := json.Marshal(snapshot)
	snapshot.Hash = checkpointDigest(raw)
	a := &boundaryAuthorityFixtureV2{identity: networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Host: 11, Namespace: 22, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}, legacy: fwRev, local: lsRev, prepared: snapshot, receipt: RoutedReceiptV1{Phase: "bootstrap"}}
	c.options.Routed, c.options.RoutedIdentity = a, a.identity
	t.Cleanup(func() { c.close(); _ = store.close() })
	return c, a, v2TrustedPrincipal{Subject: subject, Role: RoleAdmin}, target
}

func reopenBoundaryCoordinatorV2(t *testing.T, c *v2Coordinator, a *boundaryAuthorityFixtureV2) (*v2Coordinator, error) {
	return reopenBoundaryCoordinatorHookV2(t, c, a, nil)
}
func reopenBoundaryCoordinatorHookV2(t *testing.T, c *v2Coordinator, a *boundaryAuthorityFixtureV2, hook func(string) error) (*v2Coordinator, error) {
	t.Helper()
	area := c.store.root
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	store, err := openV2(area, c.store.budget)
	if err != nil {
		return nil, err
	}
	options := c.options
	options.Hook = hook
	options.Routed, options.RoutedIdentity = a, a.identity
	boot := v2BootID(a.identity.BootID)
	options.BootID = &boot
	opened, err := openCoordinatorV2(context.Background(), store, c.firewall, c.local, options)
	t.Cleanup(func() {
		if opened != nil {
			opened.close()
		}
		_ = store.close()
	})
	return opened, err
}

func freshBoundaryAuthorityV2(old *boundaryAuthorityFixtureV2) *boundaryAuthorityFixtureV2 {
	fresh := &boundaryAuthorityFixtureV2{identity: old.identity, legacy: old.legacy, local: old.local, prepared: old.prepared, receipt: RoutedReceiptV1{Phase: "bootstrap"}}
	fresh.identity.BootID = "22345678-1234-1234-1234-123456789abc"
	fresh.identity.RunID = strings.Repeat("b", 32)
	fresh.identity.Host = 44
	fresh.identity.Namespace = 55
	return fresh
}

func TestRoutedOSBootBoundaryOldBootIntentUsesFreshStartupAndRetiresBothSystemSlots(t *testing.T) {
	c, old, _, _ := boundaryCoordinatorFixtureV2(t)
	boot := v2BootID(old.identity.BootID)
	c.options.BootID = &boot
	c.options.Hook = func(point string) error {
		if point == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	c.store.mu.Lock()
	err := c.bootStartupLocked(context.Background(), boot)
	c.store.mu.Unlock()
	if !errors.Is(err, ErrInterrupted) || old.bootstraps != 0 {
		t.Fatal("old boot intent fixture", err)
	}
	var original v2RecoveryRecord
	if err = c.store.readObject(c.store.state.Configuration.LastRecovery, &original); err != nil {
		t.Fatal(err)
	}
	deadline := original.Started.Add(10 * time.Second)
	fresh := freshBoundaryAuthorityV2(old)
	opened, err := reopenBoundaryCoordinatorV2(t, c, fresh)
	if err != nil {
		t.Fatal("fresh OS startup over old boot intent", err)
	}
	resolved, err := opened.recoveryLookupLocked(original.ID)
	if err != nil || resolved.State != "final" || resolved.Pinned || resolved.SupersededBy == "" || !resolved.Started.Add(10*time.Second).Equal(deadline) || resolved.Previous != original.Previous || resolved.Target != original.Target {
		t.Fatal("old boot attempt reinterpreted", err)
	}
	if fresh.bootstraps != 1 || fresh.recovers != 0 || fresh.foreign != 0 || opened.store.state.SystemBundle != nil || opened.store.state.RoutedBootBoundary != nil || opened.store.state.ReservedBytes != 0 || opened.store.state.ReservedInodes != 0 {
		t.Fatal("old/new boot reserves not retired")
	}
	area := opened.store.root
	opened.close()
	_ = opened.store.close()
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("boot intent closure", err, report)
	}
}

func TestRoutedOSBootBoundaryInterruptedSelectionsPreserveOriginAndDeadline(t *testing.T) {
	for _, point := range []string{"after_boot_intent", "after_boot_readback", "before_boot_boundary_completion", "after_boot_boundary_completion"} {
		t.Run(point, func(t *testing.T) {
			c, old, p, config := boundaryCoordinatorFixtureV2(t)
			if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
				t.Fatal(err)
			}
			seconds := uint64(90)
			origin, pending, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			if err != nil {
				t.Fatal(err)
			}
			immutable := clone(pending.Operation.Outcome)
			fresh := freshBoundaryAuthorityV2(old)
			interrupted, err := reopenBoundaryCoordinatorHookV2(t, c, fresh, func(actual string) error {
				if actual == point {
					return ErrInterrupted
				}
				return nil
			})
			if !errors.Is(err, ErrInterrupted) || interrupted == nil {
				t.Fatal("missing selected interruption", err)
			}
			var originalBoot v2RecoveryRecord
			ref := interrupted.store.state.Configuration.LastRecovery
			if point == "after_boot_boundary_completion" {
				ref = interrupted.store.state.Configuration.LastCompletedBoot
			}
			if err = interrupted.store.readObject(ref, &originalBoot); err != nil {
				t.Fatal(err)
			}
			if originalBoot.Kind != v2BootKind {
				t.Fatal("boot receipt lost")
			}
			opened, err := reopenBoundaryCoordinatorV2(t, interrupted, fresh)
			if err != nil {
				t.Fatal("resume selected boundary", err)
			}
			retained, err := opened.store.lookupRetained(p.Subject, origin.ID)
			if err != nil || retained.Pinned || !reflect.DeepEqual(retained.Outcome, immutable) {
				t.Fatal("retry rewrote original outcome", err)
			}
			var finalBoot v2RecoveryRecord
			if err = opened.store.readObject(opened.store.state.Configuration.LastCompletedBoot, &finalBoot); err != nil || !finalBoot.Started.Equal(originalBoot.Started) {
				t.Fatal("retry renewed boot deadline", err)
			}
			if fresh.bootstraps != 1 || fresh.recovers != 0 || fresh.foreign != 0 || opened.store.state.RoutedBootBoundary != nil {
				t.Fatal("retry lost physical/finality scope")
			}
		})
	}
}

func TestRoutedOSBootBoundaryRejectsExpiredNewBootWithoutRenewal(t *testing.T) {
	c, old, p, config := boundaryCoordinatorFixtureV2(t)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	origin, pending, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal(err)
	}
	fresh := freshBoundaryAuthorityV2(old)
	interrupted, err := reopenBoundaryCoordinatorHookV2(t, c, fresh, func(point string) error {
		if point == "after_boot_readback" {
			return ErrInterrupted
		}
		return nil
	})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	var boot v2RecoveryRecord
	if err = interrupted.store.readObject(interrupted.store.state.Configuration.LastRecovery, &boot); err != nil {
		t.Fatal(err)
	}
	interrupted.options.Now = func() time.Time { return boot.Started.Add(10*time.Second + time.Nanosecond) }
	selectedBefore, e := checkpointRead(interrupted.store.root, "selected.json", 4096)
	if e != nil {
		t.Fatal(e)
	}
	reopened, err := reopenBoundaryCoordinatorV2(t, interrupted, fresh)
	selectedAfter, e := checkpointRead(interrupted.store.root, "selected.json", 4096)
	if e != nil {
		t.Fatal(e)
	}
	if (!errors.Is(err, ErrExpired) && !errors.Is(err, ErrRecovery)) || fresh.bootstraps != 1 || fresh.recovers != 0 || string(selectedBefore) != string(selectedAfter) {
		t.Fatal("expired boot published/renewed target", err)
	}
	if reopened != nil && reopened.store.state.Configuration.Running.Hash != pending.Current.Running.Hash {
		t.Fatal("expired boot published Running")
	}
	retained, e := interrupted.store.lookupRetained(p.Subject, origin.ID)
	if e != nil || !retained.Pinned || !reflect.DeepEqual(retained.Outcome, pending.Operation.Outcome) {
		t.Fatal("expired boot consumed old reserve", e)
	}
}

func TestRoutedOSBootBoundaryCapturedProofRejectsSubstitutions(t *testing.T) {
	c, old, p, config := boundaryCoordinatorFixtureV2(t)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); err != nil {
		t.Fatal(err)
	}
	fresh := freshBoundaryAuthorityV2(old)
	interrupted, err := reopenBoundaryCoordinatorHookV2(t, c, fresh, func(point string) error {
		if point == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	store := interrupted.store
	original := clone(*store.state.RoutedBootBoundary)
	load := func(hash string, out any) error {
		name, e := v2ObjectName(hash)
		if e != nil {
			return e
		}
		data, e := checkpointRead(store.root, name, v2ObjectLimit)
		if e != nil || checkpointDigest(data) != hash {
			return errV2Unavailable
		}
		return checkpointDecode(data, out)
	}
	for name, change := range map[string]func(*v2RoutedBootBoundary){
		"same_boot":    func(b *v2RoutedBootBoundary) { b.NewIdentity.BootID = old.identity.BootID },
		"same_run":     func(b *v2RoutedBootBoundary) { b.NewIdentity.RunID = old.identity.RunID },
		"foreign_role": func(b *v2RoutedBootBoundary) { b.NewIdentity.GID++ },
		"foreign_work": func(b *v2RoutedBootBoundary) { b.OldWork = checkpointDigest([]byte("missing")) },
		"deadline_plus_ns": func(b *v2RoutedBootBoundary) {
			var op v2Operation
			if store.readObject(b.Origin.Object, &op) != nil {
				t.Fatal("origin")
			}
			deadline := op.Outcome.ConfirmationDeadline.Add(time.Nanosecond)
			op.Outcome.ConfirmationDeadline = &deadline
			h, e := store.object(op)
			if e != nil {
				t.Fatal(e)
			}
			b.Origin.Object = h
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clone(original)
			change(&candidate)
			if _, _, e := routedBootBoundarySourceV2(candidate, store.state.Lineage, load); e == nil {
				t.Fatal("foreign boundary proof accepted")
			}
		})
	}
}

func TestRoutedOSBootBoundaryPendingSelectsStartupWithoutRearmingOldLease(t *testing.T) {
	c, old, p, config := boundaryCoordinatorFixtureV2(t)
	_, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	origin, result, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal("pending", err)
	}
	immutable := clone(result.Operation.Outcome)
	deadline := result.Current.Pending.Deadline
	fresh := &boundaryAuthorityFixtureV2{identity: old.identity, legacy: old.legacy, local: old.local, prepared: old.prepared, receipt: RoutedReceiptV1{Phase: "bootstrap"}}
	fresh.identity.BootID = "22345678-1234-1234-1234-123456789abc"
	fresh.identity.RunID = strings.Repeat("b", 32)
	fresh.identity.Host = 44
	fresh.identity.Namespace = 55
	opened, err := reopenBoundaryCoordinatorV2(t, c, fresh)
	if err != nil {
		t.Fatal("new OS boot", err)
	}
	state := opened.store.state.Configuration
	if state.Pending != nil || state.Intent != nil || state.Running.Hash != result.Current.Startup.Hash || state.Running.Hash == result.Current.Running.Hash || fresh.bootstraps != 1 || fresh.recovers != 0 || fresh.arms != 0 || fresh.foreign != 0 {
		t.Fatal("boot adopted/renewed old work")
	}
	retained, err := opened.store.lookupRetained(p.Subject, origin.ID)
	if err != nil || retained.Pinned || !reflect.DeepEqual(retained.Outcome, immutable) || !retained.Outcome.ConfirmationDeadline.Equal(deadline) {
		t.Fatal("old outcome/deadline rewritten", err)
	}
	if opened.store.state.RoutedBootBoundary != nil || len(opened.store.state.ActiveReserves) != 0 || opened.store.state.SystemBundle != nil || len(opened.store.state.ClosingCredits) != 0 {
		t.Fatal("boot leaked retained reserve")
	}
	area := opened.store.root
	opened.close()
	_ = opened.store.close()
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("boot closure", err, report)
	}
}

func TestRoutedOSBootBoundarySameBootForeignRolesAreRefused(t *testing.T) {
	for _, mode := range []string{"same-boot", "foreign-role", "same-run"} {
		t.Run(mode, func(t *testing.T) {
			c, old, p, config := boundaryCoordinatorFixtureV2(t)
			if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
				t.Fatal(err)
			}
			seconds := uint64(90)
			if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); err != nil {
				t.Fatal(err)
			}
			fresh := &boundaryAuthorityFixtureV2{identity: old.identity, legacy: old.legacy, local: old.local, prepared: old.prepared, receipt: RoutedReceiptV1{Phase: "bootstrap"}}
			fresh.identity.BootID = "22345678-1234-1234-1234-123456789abc"
			fresh.identity.RunID = strings.Repeat("b", 32)
			if mode == "same-boot" {
				fresh.identity.BootID = old.identity.BootID
			}
			if mode == "foreign-role" {
				fresh.identity.UID++
			}
			if mode == "same-run" {
				fresh.identity.RunID = old.identity.RunID
			}
			_, err := reopenBoundaryCoordinatorV2(t, c, fresh)
			if !errors.Is(err, ErrRecovery) || fresh.applies != 0 || fresh.bootstraps != 0 {
				t.Fatal("unsafe boundary accepted", err)
			}
		})
	}
}
