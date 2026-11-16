package routedactivation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/networkplan"
)

func TestAcquisitionFollowsKnownNetworkWithSameLocalRevision(t *testing.T) {
	_, deps, target := artifactFixture(t)
	n := deps.Network.Config
	for i := range n.Interfaces {
		if n.Interfaces[i].Role == networkplan.WAN {
			n.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "dhcp"}
		}
	}
	var err error
	deps.Network, err = networkplan.Canonical(n)
	if err != nil {
		t.Fatal(err)
	}
	fw := target.Firewall.Config
	fw.Routed.Network = deps.Network
	r, err := configpoc.CanonicalRouted(fw)
	if err != nil {
		t.Fatal(err)
	}
	before := [3]TableStateV1{{Presence: Absent}, {Presence: Absent}, {Presence: Present, Revision: &target.LocalServices}}
	after := before
	after[RoutedTable] = TableStateV1{Presence: Present, Revision: &r}
	k := &kernelFixture{objects: map[Table][]map[string]any{}}
	e := &Engine{kernel: k, prepared: PreparationV1{Dependencies: deps}}
	ctx := context.Background()
	initial, err := compileTable(LocalTable, before[LocalTable], false, deps, nil)
	if err != nil || k.Apply(ctx, initial) != nil {
		t.Fatal("baseline", err)
	}
	for i := range before {
		e.known[i] = []TableStateV1{before[i], after[i]}
	}
	for _, transition := range [][2][3]TableStateV1{{before, after}, {after, before}} {
		batch, err := e.compileChange(transition[0], transition[1], deps)
		if err != nil {
			t.Fatal(err)
		}
		var commands struct {
			NFTables []map[string]map[string]map[string]any `json:"nftables"`
		}
		if json.Unmarshal(batch, &commands) != nil {
			t.Fatal("batch")
		}
		localReplaced := false
		for _, c := range commands.NFTables {
			if table := c["delete"]["table"]; table != nil && table["name"] == localnft.TableName {
				localReplaced = true
			}
		}
		if !localReplaced {
			t.Fatal("same local revision skipped acquisition change")
		}
		if err = k.Apply(ctx, batch); err != nil {
			t.Fatal(err)
		}
		actual, err := e.knownTables(ctx)
		if err != nil || actual[RoutedTable].Presence != transition[1][RoutedTable].Presence {
			t.Fatal("known physical graph", err)
		}
		network, err := acquisitionNetwork(transition[1][RoutedTable], deps)
		if err != nil || !e.tableMatches(ctx, LocalTable, transition[1][LocalTable], deps, network) {
			t.Fatal("exact local readback", err)
		}
		wrong, _ := acquisitionNetwork(transition[0][RoutedTable], deps)
		if e.tableMatches(ctx, LocalTable, transition[1][LocalTable], deps, wrong) {
			t.Fatal("stale acquisition rule accepted")
		}
	}
	// A foreign rule cannot be treated as either known local state.
	batch, _ := e.compileChange(before, after, deps)
	if err = k.Apply(ctx, batch); err != nil {
		t.Fatal(err)
	}
	k.objects[LocalTable] = append(k.objects[LocalTable], k.objects[LocalTable][len(k.objects[LocalTable])-1])
	if _, err = e.knownTables(ctx); err == nil || !e.fenced {
		t.Fatal("extra local resource did not fence")
	}
}

func TestAcquisitionRejectsUnselectedNetworkAndStaleHashes(t *testing.T) {
	_, deps, target := artifactFixture(t)
	state := TableStateV1{Presence: Present, Revision: &target.Firewall}
	if _, err := acquisitionNetwork(state, deps); err != nil {
		t.Fatal(err)
	}
	state.Revision.Hash += "00"
	if _, err := acquisitionNetwork(state, deps); err == nil {
		t.Fatal("stale routed revision accepted")
	}
	state.Revision.Hash = target.Firewall.Hash[:64]
	deps.Network.Hash += "00"
	if _, err := acquisitionNetwork(state, deps); err == nil {
		t.Fatal("foreign dependency network accepted")
	}
	if _, err := acquisitionNetwork(TableStateV1{Presence: Absent, Revision: state.Revision}, deps); err == nil {
		t.Fatal("absent table with hidden revision accepted")
	}
	n, err := acquisitionNetwork(TableStateV1{Presence: Absent}, deps)
	if err != nil || n != nil {
		t.Fatal("NoNetwork gained acquisition authority")
	}
}
