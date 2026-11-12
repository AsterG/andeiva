//go:build linux

package configpoc

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

func TestRoutedNoNetworkArtifactsExplicitAndDetached(t *testing.T) {
	work, _, load := routedWorkFixtureV2(t)
	var object v2RoutedDependencies
	if err := load(work.Transition.Dependencies, &object); err != nil {
		t.Fatal(err)
	}
	deps := object.Value
	observed := networkexecutor.ObservedSnapshot{Version: 1, Links: deps.Prepared.Links, Routes: deps.Prepared.Routes}
	raw, _ := json.Marshal(observed)
	observed.Hash = checkpointDigest(raw)
	owned := OwnedV1{Version: 2, NetworkState: NoNetwork, LegacyFirewall: TableStateV1{Presence: Absent}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}, Observed: &observed}
	none := DependenciesV1{Version: 2, NetworkMode: "none", Observed: &observed}
	canonical, err := CanonicalOwned(owned)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := CanonicalDependencies(none)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{canonical, dependencies} {
		raw, e := json.Marshal(value)
		if e != nil || bytes.Contains(raw, []byte(`"plan_hash"`)) || bytes.Contains(raw, []byte(`"network":`)) || bytes.Contains(raw, []byte(`"prepared":`)) {
			t.Fatal("no-network encoded a desired plan", string(raw), e)
		}
	}
	observed.Links[0].MTU = 9000
	if canonical.Observed.Links[0].MTU == 9000 || dependencies.Observed.Links[0].MTU == 9000 {
		t.Fatal("observed baseline aliases caller")
	}
	for name, mutate := range map[string]func(*OwnedV1){
		"old_version":     func(v *OwnedV1) { v.Version = 1 },
		"desired_network": func(v *OwnedV1) { v.Network = deps.Prepared },
		"wrong_state":     func(v *OwnedV1) { v.NetworkState = Baseline },
		"no_observation":  func(v *OwnedV1) { v.Observed = nil },
		"local_table":     func(v *OwnedV1) { v.LocalServices.Presence = Present },
		"routed_table":    func(v *OwnedV1) { v.RoutedFirewall.Presence = Present },
	} {
		t.Run(name, func(t *testing.T) {
			v := clone(canonical)
			mutate(&v)
			if _, err := CanonicalOwned(v); err == nil {
				t.Fatal("ambiguous ownership accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*DependenciesV1){
		"old_version":      func(v *DependenciesV1) { v.Version = 1 },
		"desired_plan":     func(v *DependenciesV1) { v.Network = deps.Network },
		"prepared_plan":    func(v *DependenciesV1) { v.Prepared = deps.Prepared },
		"no_mode":          func(v *DependenciesV1) { v.NetworkMode = "" },
		"local_interfaces": func(v *DependenciesV1) { v.LocalInterfaces = deps.LocalInterfaces },
		"neighbors":        func(v *DependenciesV1) { v.Neighbors = []localpolicy.NeighborLink{{Interface: "lan0"}} },
	} {
		t.Run(name, func(t *testing.T) {
			v := clone(dependencies)
			mutate(&v)
			if _, err := CanonicalDependencies(v); err == nil {
				t.Fatal("ambiguous dependency accepted")
			}
		})
	}
}

func TestRoutedArtifactUnionPreservesV1WireBytes(t *testing.T) {
	work, _, load := routedWorkFixtureV2(t)
	var o v2RoutedOwned
	var d v2RoutedDependencies
	if load(work.Transition.BeforeOwned, &o) != nil || load(work.Transition.Dependencies, &d) != nil {
		t.Fatal("fixture")
	}
	owned, err := CanonicalOwned(o.Value)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := CanonicalDependencies(d.Value)
	if err != nil {
		t.Fatal(err)
	}
	// Frozen V1 wire fields and their order, independently of the V2 union.
	oldOwned := struct {
		Version        int                              `json:"version"`
		Network        networkexecutor.PreparedSnapshot `json:"network"`
		NetworkState   NetworkState                     `json:"network_state"`
		LegacyFirewall TableStateV1                     `json:"legacy_firewall"`
		RoutedFirewall TableStateV1                     `json:"routed_firewall"`
		LocalServices  TableStateV1                     `json:"local_services"`
	}{owned.Version, owned.Network, owned.NetworkState, owned.LegacyFirewall, owned.RoutedFirewall, owned.LocalServices}
	oldDeps := struct {
		Version         int                              `json:"version"`
		Network         networkplan.Revision             `json:"network"`
		Prepared        networkexecutor.PreparedSnapshot `json:"prepared"`
		LocalInterfaces []localpolicy.Interface          `json:"local_interfaces"`
		Neighbors       []localpolicy.NeighborLink       `json:"neighbors"`
	}{deps.Version, deps.Network, deps.Prepared, deps.LocalInterfaces, deps.Neighbors}
	for _, pair := range [][2]any{{owned, oldOwned}, {deps, oldDeps}} {
		current, _ := json.Marshal(pair[0])
		legacy, _ := json.Marshal(pair[1])
		if !bytes.Equal(current, legacy) {
			t.Fatal("V1 canonical bytes changed")
		}
	}
}
