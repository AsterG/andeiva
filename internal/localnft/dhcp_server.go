package localnft

import (
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

// CompileForRoutedPolicy consumes the canonical routed revision selected by the
// caller. DHCP server controls are limited to local IPv4 unicast requests on
// the selected static LANs. Kea handles acquisition broadcasts on its raw
// socket, outside these Local-In UDP controls.
func CompileForRoutedPolicy(c localpolicy.Config, neighbors []NeighborLink, selected routedmodel.Revision) (Artifact, error) {
	canonical, err := routedmodel.Canonical(selected.Policy)
	if err != nil || canonical.Hash != selected.Hash || !equalJSON(canonical.Policy, selected.Policy) {
		return Artifact{}, ErrPolicy
	}
	policy := canonical.Policy
	if policy.DHCPServer == nil || !policy.DHCPServer.Enabled {
		return CompileForNetwork(c, neighbors, &policy.Network)
	}
	return compileForNetwork(c, neighbors, &policy.Network, &canonical)
}

func dhcpServerRules(policy routedmodel.Policy) []object {
	names := make(map[string]string, len(policy.Network.Config.Interfaces))
	for _, link := range policy.Network.Config.Interfaces {
		names[link.ID] = link.Binding.Name
	}
	rules := make([]object, 0, len(policy.DHCPServer.Scopes))
	for _, scope := range policy.DHCPServer.Scopes {
		// Canonical policy binds the router address to the static IPv4 address
		// of the scope's selected LAN and permits one scope per interface.
		rules = append(rules, rule("andeiva-dhcp-server:v1:"+scope.ID, []object{
			match(meta("nfproto"), "ipv4"), match(meta("iifname"), names[scope.InterfaceID]),
			match(payload("ip", "daddr"), scope.Router),
			match(meta("l4proto"), "udp"), match(payload("udp", "sport"), uint16(68)),
			match(payload("udp", "dport"), uint16(67)), {"counter": nil}, {"accept": nil},
		}))
	}
	return rules
}
