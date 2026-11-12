//go:build linux

package configpoc

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func TestRoutedRestoreProjectionKeepsPhysicalBaselineAndLocalExact(t *testing.T) {
	work, objects, load := routedWorkFixtureV2(t)
	raw, h, err := v2Canonical(work)
	if err != nil {
		t.Fatal(err)
	}
	objects[h] = raw
	plan, err := loadRoutedWorkV2(h, work.Lineage, load)
	if err != nil {
		t.Fatal(err)
	}
	original := *plan.Baseline()
	cfg := clone(original.Saved.Firewall.Config)
	cfg.Rules = coordinatorV2Rule("selected-saved").Rules
	enabled := true
	for i := range cfg.Rules {
		cfg.Rules[i].Enabled = &enabled
	}
	fw, err := Canonical(cfg)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewRoutedActivationBundleV1(fw, original.Saved.LocalServices)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectRoutedRestoreBaselineV1(original, target)
	if err != nil {
		t.Fatal(err)
	}
	if projected.Saved.Composite.Hash != target.Composite.Hash || projected.Owned.LegacyFirewall.Revision.Hash != target.Firewall.Hash || !RoutedOwnershipMatchesDependencies(projected.Owned, original.Dependencies) || projected.Owned.Network.Hash != original.Owned.Network.Hash {
		t.Fatal("projection changed memento")
	}
	projected.Owned.Network.Links[0].Index++
	if original.Owned.Network.Links[0].Index == projected.Owned.Network.Links[0].Index {
		t.Fatal("projection aliases original")
	}
	for name, change := range map[string]func(*RoutedBaselineV1, *RoutedActivationBundleV1){
		"network":      func(b *RoutedBaselineV1, _ *RoutedActivationBundleV1) { b.Owned.Network.Links[0].Index++ },
		"dependencies": func(b *RoutedBaselineV1, _ *RoutedActivationBundleV1) { b.Dependencies.Prepared.Links[0].MTU++ },
		"original-local": func(b *RoutedBaselineV1, _ *RoutedActivationBundleV1) {
			b.Owned.LocalServices = TableStateV1{Presence: Present, Revision: &target.LocalServices}
		},
		"target-local": func(_ *RoutedBaselineV1, tgt *RoutedActivationBundleV1) {
			c := Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}}
			local, e := Canonical(c)
			if e != nil {
				t.Fatal(e)
			}
			*tgt, e = NewRoutedActivationBundleV1(tgt.Firewall, local)
			if e != nil {
				t.Fatal(e)
			}
		},
		"target-hash": func(_ *RoutedBaselineV1, tgt *RoutedActivationBundleV1) {
			tgt.Composite.Hash = checkpointDigest([]byte("unselected"))
		},
	} {
		b, tgt := clone(original), clone(target)
		change(&b, &tgt)
		// Adding the exact original local revision is a valid physical baseline;
		// substitute a different revision to exercise canonical local binding.
		if name == "original-local" {
			local, e := Canonical(Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
			if e != nil {
				t.Fatal(e)
			}
			b.Owned.LocalServices.Revision = &local
		}
		if _, err := ProjectRoutedRestoreBaselineV1(b, tgt); err == nil {
			t.Fatal("accepted altered baseline", name)
		}
	}
	observed := networkexecutor.ObservedSnapshot{Version: 1, Links: clone(original.Owned.Network.Links), Routes: clone(original.Owned.Network.Routes)}
	data, _ := json.Marshal(observed)
	observed.Hash = checkpointDigest(data)
	none := RoutedBaselineV1{Saved: original.Saved, Owned: OwnedV1{Version: 2, NetworkState: NoNetwork, Observed: &observed, LegacyFirewall: original.Owned.LegacyFirewall, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}}, Dependencies: DependenciesV1{Version: 2, NetworkMode: "none", Observed: &observed}}
	altered := clone(none)
	altered.Owned.Observed.Links[0].Index++
	altered.Owned.Observed.Hash = ""
	data, _ = json.Marshal(altered.Owned.Observed)
	altered.Owned.Observed.Hash = checkpointDigest(data)
	if _, err := ProjectRoutedRestoreBaselineV1(altered, target); err == nil {
		t.Fatal("accepted inconsistent canonical observed/dependencies")
	}
}

func TestRoutedInverseWorkRequiresExactSelectedProjection(t *testing.T) {
	original, objects, load := routedWorkFixtureV2(t)
	put := func(v any) string {
		data, h, err := v2Canonical(v)
		if err != nil {
			t.Fatal(err)
		}
		objects[h] = data
		return h
	}
	originalHash := put(original)
	source, err := loadRoutedWorkV2(originalHash, original.Lineage, load)
	if err != nil {
		t.Fatal(err)
	}
	baseline := source.Baseline()
	cfg := clone(baseline.Saved.Firewall.Config)
	cfg.Rules = coordinatorV2Rule("selected-inverse").Rules
	enabled := true
	for i := range cfg.Rules {
		cfg.Rules[i].Enabled = &enabled
	}
	fw, err := Canonical(cfg)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := NewRoutedActivationBundleV1(fw, baseline.Saved.LocalServices)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := ProjectRoutedRestoreBaselineV1(*baseline, saved)
	if err != nil {
		t.Fatal(err)
	}
	var before v2Configuration
	if load(original.Transition.Target, &before) != nil {
		t.Fatal("before")
	}
	before.Pending = nil
	target := clone(before)
	target.Firewall.Running = saved.Firewall
	if target.refresh() != nil {
		t.Fatal("target")
	}
	deadline := original.Deadline.Add(time.Hour)
	previousHash := put(before)
	target.Pending = &v2Confirmation{OriginCommit: "inverse", Owner: original.Subject, Domain: "routed", Lease: "inverse-lease", Previous: previousHash, Target: target.Running.Hash, Deadline: deadline}
	inverse := v2RoutedWork{Version: 1, Kind: OpRollback, Lineage: original.Lineage, Operation: "inverse", Subject: original.Subject, Generation: original.Generation + 1, Lease: "inverse-lease", Deadline: deadline, Baseline: originalHash, Scope: original.Scope, Transition: RoutedTransitionV1{Version: 1, Operation: "inverse", Previous: previousHash, Target: put(target)}}
	inverse.Scope.Generation = inverse.Generation
	inverse.Transition.BeforeOwned = put(v2RoutedOwned{1, inverse.Lineage, inverse.Operation, "before", source.preparation.Target})
	inverse.Transition.TargetOwned = put(v2RoutedOwned{1, inverse.Lineage, inverse.Operation, "target", projected.Owned})
	inverse.Transition.Dependencies = put(v2RoutedDependencies{1, inverse.Lineage, inverse.Operation, source.preparation.Dependencies})
	if _, err := loadRoutedWorkV2(put(inverse), inverse.Lineage, load); err != nil {
		t.Fatal("selected changed saved4", err)
	}
	for name, change := range map[string]func(*OwnedV1){"legacy": func(o *OwnedV1) { o.LegacyFirewall = baseline.Owned.LegacyFirewall }, "network": func(o *OwnedV1) { o.Network.Links[0].Index++ }, "local": func(o *OwnedV1) { o.LocalServices = source.preparation.Target.LocalServices }} {
		bad := clone(projected.Owned)
		change(&bad)
		w := clone(inverse)
		w.Transition.TargetOwned = put(v2RoutedOwned{1, w.Lineage, w.Operation, "target", bad})
		if _, err := loadRoutedWorkV2(put(w), w.Lineage, load); err == nil {
			t.Fatal("accepted target artifact substitution", name)
		}
	}
}
