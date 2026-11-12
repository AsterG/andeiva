package routednft

import "github.com/AsterG/andeiva/internal/networkplan"

// LabPolicy is a fixed documentation-only test fixture, never a host plan.
func LabPolicy() Policy {
	n, _ := networkplan.Canonical(networkplan.Config{SchemaVersion: 1, IPv6Forwarding: "deny", Interfaces: []networkplan.Interface{
		{ID: "lan", Role: networkplan.LAN, Zone: "inside", Binding: networkplan.Binding{Name: "lan0", HardwareAddress: "02:00:00:00:01:01"}, IPv4: networkplan.IPv4{Mode: "static", Address: "198.18.0.1/24"}},
		{ID: "wan", Role: networkplan.WAN, Zone: "outside", Binding: networkplan.Binding{Name: "wan0", HardwareAddress: "02:00:00:00:02:01"}, IPv4: networkplan.IPv4{Mode: "static", Address: "198.19.0.1/24", Gateway: "198.19.0.2"}},
	}, Zones: []networkplan.Zone{{ID: "inside", Kind: networkplan.LAN}, {ID: "outside", Kind: networkplan.WAN}}, DefaultRoute: networkplan.DefaultRoute{InterfaceID: "wan", Metric: 10}, DNS: networkplan.DNS{Mode: "none", Servers: []string{}}})
	path := Path{FromZone: "inside", ToZone: "outside", FromInterface: "lan", ToInterface: "wan"}
	activeTCP, activeUDP := true, true
	return Policy{SchemaVersion: 1, LabOnly: true, Network: n, Rules: []Rule{
		{ID: "tcp-test", Enabled: &activeTCP, Path: path, Action: "allow", Source: "198.18.0.0/24", Destination: "198.19.0.2/32", Protocol: "tcp", SourcePorts: Ports{1024, 65535}, DestinationPorts: Ports{18080, 18080}},
		{ID: "udp-test", Enabled: &activeUDP, Path: path, Action: "allow", Source: "198.18.0.0/24", Destination: "198.19.0.2/32", Protocol: "udp", SourcePorts: Ports{1024, 65535}, DestinationPorts: Ports{18081, 18082}},
	}, NAT: []Masquerade{{ID: "lan-wan", Path: path, Source: "198.18.0.0/24"}}}
}
