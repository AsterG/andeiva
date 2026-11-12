// Typed routed artifacts are canonical data, never activation authority.
// They retain the same fixed laboratory ownership and resource bounds.
package configpoc

import (
	"bytes"

	"encoding/json"
	"errors"
	"net/netip"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"github.com/AsterG/andeiva/internal/networkplan"
)

// RoutedBaselineV1 retains the original authenticated cold state, never a
// baseline inferred from a later Running revision or encountered namespace.
type RoutedBaselineV1 struct {
	Saved        RoutedActivationBundleV1 `json:"saved"`
	Owned        OwnedV1                  `json:"owned"`
	Dependencies DependenciesV1           `json:"dependencies"`
}

const RoutedArtifactLimit = 256 << 10

var ErrRoutedArtifact = errors.New("ANDEIVA_ROUTED_ACTIVATION_STATE")

type Presence string

const (
	Absent  Presence = "absent"
	Present Presence = "present"
)

type NetworkState string

const (
	Baseline   NetworkState = "baseline"
	Configured NetworkState = "configured"
)

// An absent table has no Revision. Presence is proved by a successful fixed-table
// query, not a failed command. Local absence concerns only this manager's listeners.
type TableStateV1 struct {
	Presence Presence  `json:"presence"`
	Revision *Revision `json:"revision"`
}

type OwnedV1 struct {
	Version        int                              `json:"version"`
	Network        networkexecutor.PreparedSnapshot `json:"network"`
	NetworkState   NetworkState                     `json:"network_state"`
	LegacyFirewall TableStateV1                     `json:"legacy_firewall"`
	RoutedFirewall TableStateV1                     `json:"routed_firewall"`
	LocalServices  TableStateV1                     `json:"local_services"`
}

type DependenciesV1 struct {
	Version         int                              `json:"version"`
	Network         networkplan.Revision             `json:"network"`
	Prepared        networkexecutor.PreparedSnapshot `json:"prepared"`
	LocalInterfaces []localpolicy.Interface          `json:"local_interfaces"`
	Neighbors       []localpolicy.NeighborLink       `json:"neighbors"`
}

func CanonicalRoutedTable(input TableStateV1, schema int) (TableStateV1, error) {
	if input.Presence == Absent && input.Revision == nil {
		return input, nil
	}
	if input.Presence != Present || input.Revision == nil || input.Revision.Config.SchemaVersion != schema {
		return TableStateV1{}, ErrRoutedArtifact
	}
	r, err := Canonical(input.Revision.Config)
	if schema == 6 {
		r, err = CanonicalRouted(input.Revision.Config)
	}
	if err != nil || r.Hash != input.Revision.Hash {
		return TableStateV1{}, ErrRoutedArtifact
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > RoutedArtifactLimit {
		return TableStateV1{}, ErrRoutedArtifact
	}
	var detached Revision
	if json.Unmarshal(data, &detached) != nil {
		return TableStateV1{}, ErrRoutedArtifact
	}
	return TableStateV1{Presence: Present, Revision: &detached}, nil
}

func CanonicalOwned(input OwnedV1) (OwnedV1, error) {
	if input.Version != 1 || (input.NetworkState != Baseline && input.NetworkState != Configured) {
		return OwnedV1{}, ErrRoutedArtifact
	}
	network, err := networkexecutor.CanonicalPreparedSnapshot(input.Network)
	if err != nil {
		return OwnedV1{}, err
	}
	legacy, err := CanonicalRoutedTable(input.LegacyFirewall, 4)
	if err != nil {
		return OwnedV1{}, err
	}
	routed, err := CanonicalRoutedTable(input.RoutedFirewall, 6)
	if err != nil {
		return OwnedV1{}, err
	}
	local, err := CanonicalRoutedTable(input.LocalServices, 3)
	if err != nil {
		return OwnedV1{}, err
	}
	out := OwnedV1{1, network, input.NetworkState, legacy, routed, local}
	if routed.Revision != nil && routed.Revision.Config.Routed.Network.Hash != network.PlanHash {
		return OwnedV1{}, ErrRoutedArtifact
	}
	data, err := json.Marshal(out)
	if err != nil || len(data) > RoutedArtifactLimit {
		return OwnedV1{}, ErrRoutedArtifact
	}
	return out, nil
}

func CanonicalDependencies(input DependenciesV1) (DependenciesV1, error) {
	if input.Version != 1 || len(input.Network.Config.Interfaces) != 2 || len(input.LocalInterfaces) != 2 || len(input.Neighbors) > localpolicy.MaxNeighborInterfaces {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	network, err := networkplan.Canonical(input.Network.Config)
	if err != nil || network.Hash != input.Network.Hash || len(network.Config.Interfaces) != 2 {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	prepared, err := networkexecutor.CanonicalPreparedSnapshot(input.Prepared)
	if err != nil || prepared.PlanHash != network.Hash {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	inventory := networkinventory.Snapshot{SchemaVersion: 1}
	for _, l := range prepared.Links {
		inventory.Interfaces = append(inventory.Interfaces, networkinventory.Interface{Index: l.Index, Name: l.Name, HardwareAddress: l.MAC, Kind: networkinventory.Virtual})
	}
	if _, err := networkplan.Bind(network, inventory); err != nil {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	local, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: 1, Interfaces: input.LocalInterfaces, Services: []localpolicy.Service{}})
	if err != nil {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	expected := []localpolicy.Interface{}
	for _, i := range network.Config.Interfaces {
		zone := localpolicy.LAN
		if i.Role == networkplan.WAN {
			zone = localpolicy.WAN
		}
		if i.IPv4.Mode != "static" {
			return DependenciesV1{}, ErrRoutedArtifact
		}
		expected = append(expected, localpolicy.Interface{Name: i.Binding.Name, Zone: zone, Addresses: []string{netip.MustParsePrefix(i.IPv4.Address).Addr().String()}})
	}
	canonicalExpected, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: 1, Interfaces: expected, Services: []localpolicy.Service{}})
	if err != nil {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	want, _ := json.Marshal(canonicalExpected.Config.Interfaces)
	got, _ := json.Marshal(local.Config.Interfaces)
	if !bytes.Equal(want, got) {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	neighbors, err := localpolicy.CanonicalNeighborInventory(local.Config, input.Neighbors)
	if err != nil {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	out := DependenciesV1{1, network, prepared, local.Config.Interfaces, neighbors}
	data, err := json.Marshal(out)
	if err != nil || len(data) > RoutedArtifactLimit {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	var detached DependenciesV1
	if json.Unmarshal(data, &detached) != nil {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	return detached, nil
}

func OwnedBytes(input OwnedV1) ([]byte, error) {
	canonical, err := CanonicalOwned(input)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

func DependenciesBytes(input DependenciesV1) ([]byte, error) {
	canonical, err := CanonicalDependencies(input)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}
