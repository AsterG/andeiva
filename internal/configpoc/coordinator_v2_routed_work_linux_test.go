//go:build linux

package configpoc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func routedWorkFixtureV2(t *testing.T) (v2RoutedWork, map[string][]byte, func(string, any) error) {
	t.Helper()
	c, _, principal := routedCoordinatorFixtureV2(t)
	before := clone(*c.store.state.Configuration)
	document, revisions := compositeRoutedFixture(t, true)
	firewall := revisions[document.Domains.Firewall.Revision]
	local, e := Canonical(Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}, {Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}}}, Services: []localpolicy.Service{}}})
	if e != nil {
		t.Fatal(e)
	}
	before.LocalServices.Running, before.LocalServices.Startup, before.LocalServices.LastGood = local, local, local
	if e = before.refresh(); e != nil {
		t.Fatal(e)
	}
	objects := map[string][]byte{}
	put := func(v any) string {
		raw, hash, e := v2Canonical(v)
		if e != nil {
			t.Fatal(e)
		}
		objects[hash] = raw
		return hash
	}
	previousHash := put(before)
	target := clone(before)
	target.Firewall.Running = firewall
	if e = target.refresh(); e != nil {
		t.Fatal(e)
	}
	deadline := time.Date(2026, 11, 12, 1, 2, 3, 0, time.UTC)
	target.Pending = &v2Confirmation{OriginCommit: "origin", Owner: principal.Subject, Domain: "routed", Lease: "lease", Previous: previousHash, Target: target.Running.Hash, Deadline: deadline}
	snapshot := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: firewall.Config.Routed.Network.Hash, Links: []networkexecutor.SnapshotLink{{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}, {Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}}, Routes: []networkexecutor.SnapshotRoute{}}
	raw, _ := json.Marshal(snapshot)
	snapshot.Hash = checkpointDigest(raw)
	owned := OwnedV1{Version: 1, Network: snapshot, NetworkState: Baseline, LegacyFirewall: TableStateV1{Presence: Present, Revision: &before.Firewall.Running}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}}
	applied := clone(owned)
	applied.NetworkState = Configured
	applied.LegacyFirewall = TableStateV1{Presence: Absent}
	applied.RoutedFirewall = TableStateV1{Presence: Present, Revision: &firewall}
	applied.LocalServices = TableStateV1{Presence: Present, Revision: &local}
	dependencies := DependenciesV1{Version: 1, Network: firewall.Config.Routed.Network, Prepared: snapshot, LocalInterfaces: local.Config.LocalServices.Interfaces}
	work := v2RoutedWork{Version: 1, Lineage: c.store.state.Lineage, Operation: "origin", Subject: principal.Subject, Generation: 5, Lease: "lease", Deadline: deadline, Cold: true, Transition: RoutedTransitionV1{Version: 1, Operation: "origin", Previous: previousHash, Target: put(target)}}
	work.Scope = RoutedWorkScopeV1{Version: 1, Lineage: work.Lineage, Generation: work.Generation, Identity: networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Host: 11, Namespace: 22, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}}
	work.Transition.BeforeOwned = put(v2RoutedOwned{1, work.Lineage, work.Operation, "before", owned})
	work.Transition.TargetOwned = put(v2RoutedOwned{1, work.Lineage, work.Operation, "target", applied})
	work.Transition.Dependencies = put(v2RoutedDependencies{1, work.Lineage, work.Operation, dependencies})
	load := func(hash string, out any) error {
		raw, ok := objects[hash]
		if !ok || checkpointDigest(raw) != hash {
			return errV2Unavailable
		}
		return checkpointDecode(raw, out)
	}
	return work, objects, load
}

func TestRoutedWorkRejectsForgedContextAndBaselineChains(t *testing.T) {
	work, objects, load := routedWorkFixtureV2(t)
	put := func(v any) string {
		raw, h, e := v2Canonical(v)
		if e != nil {
			t.Fatal(e)
		}
		objects[h] = raw
		return h
	}
	original := put(work)
	plan, e := loadRoutedWorkV2(original, work.Lineage, load)
	if e != nil || !plan.Valid() {
		t.Fatal("valid typed work", e)
	}
	detached := plan.Baseline()
	detached.Saved.Firewall.Config.DefaultAction = "allow"
	if plan.Baseline().Saved.Firewall.Config.DefaultAction != "deny" {
		t.Fatal("baseline aliases caller")
	}
	for name, change := range map[string]func(*v2RoutedWork){
		"scope_lineage":         func(w *v2RoutedWork) { w.Scope.Lineage = strings.Repeat("f", 64) },
		"scope_generation":      func(w *v2RoutedWork) { w.Scope.Generation++ },
		"host_namespace":        func(w *v2RoutedWork) { w.Scope.Identity.Host = w.Scope.Identity.Namespace },
		"cold_baseline":         func(w *v2RoutedWork) { w.Baseline = original },
		"warm_missing_baseline": func(w *v2RoutedWork) { w.Cold = false },
		"deadline_one_ns":       func(w *v2RoutedWork) { w.Deadline = w.Deadline.Add(time.Nanosecond) },
		"wrong_subject":         func(w *v2RoutedWork) { w.Subject = "other" },
		"foreign_target_ref":    func(w *v2RoutedWork) { w.Transition.Target = w.Transition.Previous },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clone(work)
			change(&candidate)
			if _, e := loadRoutedWorkV2(put(candidate), work.Lineage, load); e == nil {
				t.Fatal("forged work accepted")
			}
		})
	}
	if _, e = loadRoutedWorkV2(original, work.Lineage, nil); e == nil {
		t.Fatal("missing reader accepted")
	}
	delete(objects, work.Transition.BeforeOwned)
	if _, e = loadRoutedWorkV2(original, work.Lineage, load); e == nil {
		t.Fatal("missing typed baseline accepted")
	}
}
