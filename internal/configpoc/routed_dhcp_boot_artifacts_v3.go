package configpoc

import (
	"encoding/json"
	"net/netip"
	"reflect"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"github.com/AsterG/andeiva/internal/networkplan"
)

// Version 3 means LAN-static/WAN-DHCP bootstrap. Configured denotes the LAN
// baseline only; dynamic WAN authority remains separately selected R2 work.
// No address is invented for WAN and version 1 static semantics are unchanged.
func canonicalDHCPOwnedV3(input OwnedV1) (OwnedV1, error) {
	if input.Version != 3 || input.Observed != nil || (input.NetworkState != Baseline && input.NetworkState != Configured) {
		return OwnedV1{}, ErrRoutedArtifact
	}
	prepared, err := networkexecutor.CanonicalPreparedSnapshot(input.Network)
	if err != nil {
		return OwnedV1{}, err
	}
	legacy, e1 := CanonicalRoutedTable(input.LegacyFirewall, 4)
	routed, e2 := CanonicalRoutedTable(input.RoutedFirewall, 6)
	local, e3 := CanonicalRoutedTable(input.LocalServices, 3)
	if e1 != nil || e2 != nil || e3 != nil {
		return OwnedV1{}, ErrRoutedArtifact
	}
	if routed.Revision != nil {
		n := routed.Revision.Config.Routed.Network
		if _, err := networkexecutor.CanonicalLANBootstrapPlanV3(n); err != nil || n.Hash != prepared.PlanHash {
			return OwnedV1{}, ErrRoutedArtifact
		}
	}
	return OwnedV1{Version: 3, Network: prepared, NetworkState: input.NetworkState, LegacyFirewall: legacy, RoutedFirewall: routed, LocalServices: local}, nil
}

func canonicalDHCPDependenciesV3(input DependenciesV1) (DependenciesV1, error) {
	if input.Version != 3 || input.NetworkMode != "dhcp-lan" || input.Observed != nil || len(input.LocalInterfaces) != 1 || len(input.Neighbors) > localpolicy.MaxNeighborInterfaces {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	n, err := networkexecutor.CanonicalLANBootstrapPlanV3(input.Network)
	if err != nil {
		return DependenciesV1{}, err
	}
	s, err := networkexecutor.CanonicalPreparedSnapshot(input.Prepared)
	if err != nil || s.PlanHash != n.Hash {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	inv := networkinventory.Snapshot{SchemaVersion: 1}
	var lan networkplan.Interface
	for _, link := range s.Links {
		inv.Interfaces = append(inv.Interfaces, networkinventory.Interface{Index: link.Index, Name: link.Name, HardwareAddress: link.MAC, Kind: networkinventory.Virtual})
	}
	if _, err = networkplan.Bind(n, inv); err != nil {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	for _, i := range n.Config.Interfaces {
		if i.Role == networkplan.LAN {
			lan = i
		}
	}
	expected := []localpolicy.Interface{{Name: lan.Binding.Name, Zone: localpolicy.LAN, Addresses: []string{netip.MustParsePrefix(lan.IPv4.Address).Addr().String()}}}
	l, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: 1, Interfaces: input.LocalInterfaces, Services: []localpolicy.Service{}})
	if err != nil || !reflect.DeepEqual(l.Config.Interfaces, expected) {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	neighbors, err := localpolicy.CanonicalNeighborInventory(l.Config, input.Neighbors)
	if err != nil {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	out := DependenciesV1{Version: 3, Network: n, Prepared: s, LocalInterfaces: l.Config.Interfaces, Neighbors: neighbors, NetworkMode: "dhcp-lan"}
	raw, err := json.Marshal(out)
	if err != nil || len(raw) > RoutedArtifactLimit {
		return DependenciesV1{}, ErrRoutedArtifact
	}
	return out, nil
}

func routedWorkUsesDHCPV3(p RoutedSelectedPlanV1) bool {
	return p.preparation.Before.Version == 3 || p.preparation.Target.Version == 3 || p.preparation.Dependencies.Version == 3
}

func routedConfigurationUsesDHCPV3(c v2Configuration) bool {
	if c.Running.Config.SchemaVersion != 7 || c.Firewall.Running.Config.Routed == nil {
		return false
	}
	_, err := networkexecutor.CanonicalLANBootstrapPlanV3(c.Firewall.Running.Config.Routed.Network)
	return err == nil
}
