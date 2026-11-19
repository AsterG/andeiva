package previewruntime

import (
	"math"
	"net/netip"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

type routedDHCPServerScopeBindingV1 struct {
	subnet RoutedDHCPSubnetBindingV1
	kea    dhcpkea.Binding
}

type routedDHCPServerBindingPlanV1 []routedDHCPServerScopeBindingV1

// routedDHCPServerBindingPlanFromSelectedV1 consumes an authenticated
// preflight reply with the expected supervisor identity and Work. It only
// projects the selected configuration. The consumer must retain the selection
// barrier, verify live LAN identity and L3, and perform persistence and launch.
func routedDHCPServerBindingPlanFromSelectedV1(selected RoutedSelectedPreflightResultV4, identity networkexecutor.OwnedNamespaceIdentity, work configpoc.RoutedWorkReferenceV1) (routedDHCPServerBindingPlanV1, error) {
	if err := routedPreflightResultV4(selected, RoutedPreflightDHCPServerV1, identity, work); err != nil {
		return nil, err
	}
	policy := selected.Bundle.Firewall.Config.Routed
	interfaces := make(map[string]networkplan.Interface, len(policy.Network.Config.Interfaces))
	for _, iface := range policy.Network.Config.Interfaces {
		interfaces[iface.ID] = iface
	}
	plan := make(routedDHCPServerBindingPlanV1, 0, len(policy.DHCPServer.Scopes))
	for _, scope := range policy.DHCPServer.Scopes {
		iface, found := interfaces[scope.InterfaceID]
		if !found || iface.Role != networkplan.LAN || iface.IPv4.Mode != "static" {
			return nil, ErrIdentity
		}
		address, err := netip.ParsePrefix(iface.IPv4.Address)
		subnet := RoutedDHCPSubnetBindingV1{
			ScopeID: scope.ID, InterfaceID: iface.ID, HardwareMAC: iface.Binding.HardwareAddress, Subnet: scope.Subnet,
		}
		if err != nil || !validDHCPSubnetBindingV1(subnet) {
			return nil, ErrIdentity
		}
		plan = append(plan, routedDHCPServerScopeBindingV1{
			subnet: subnet,
			kea: dhcpkea.Binding{
				Interface: dhcpserver.Binding{InterfaceID: iface.ID, Role: string(iface.Role), Address: address},
				Name:      iface.Binding.Name,
			},
		})
	}
	return plan, nil
}

func (plan routedDHCPServerBindingPlanV1) subnetBindings() []RoutedDHCPSubnetBindingV1 {
	bindings := make([]RoutedDHCPSubnetBindingV1, len(plan))
	for i, scope := range plan {
		bindings[i] = scope.subnet
	}
	return bindings
}

// keaBindings consumes the exact ordered IDs returned by
// EnsureRoutedDHCPSubnetIDsV1 for this plan's subnetBindings.
func (plan routedDHCPServerBindingPlanV1) keaBindings(ids []uint32) ([]dhcpkea.Binding, error) {
	if len(plan) == 0 || len(ids) != len(plan) {
		return nil, ErrIdentity
	}
	seen := make(map[uint32]bool, len(ids))
	bindings := make([]dhcpkea.Binding, len(plan))
	for i, id := range ids {
		// Kea reserves 0xffffffff. Reuse the compiler's accepted range.
		if id == 0 || id == math.MaxUint32 || seen[id] {
			return nil, ErrIdentity
		}
		seen[id] = true
		bindings[i] = plan[i].kea
		bindings[i].SubnetID = id
	}
	return bindings, nil
}
