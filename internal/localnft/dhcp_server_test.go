package localnft

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

func dhcpServerFixture(t *testing.T, lanCount int) (localpolicy.Config, routedmodel.Revision) {
	t.Helper()
	local, network := acquisitionFixture(t)
	server := dhcpserver.Config{SchemaVersion: 1, Enabled: true}
	for i := range lanCount {
		id := "lan"
		if i > 0 {
			id = fmt.Sprintf("lan%d", i)
			network.Config.Interfaces = append(network.Config.Interfaces, networkplan.Interface{
				ID: id, Role: networkplan.LAN, Zone: "inside",
				Binding: networkplan.Binding{Name: id, HardwareAddress: fmt.Sprintf("02:00:00:00:03:%02x", i)},
				IPv4:    networkplan.IPv4{Mode: "static", Address: fmt.Sprintf("198.18.%d.1/24", i)},
			})
		}
		server.Scopes = append(server.Scopes, dhcpserver.Scope{
			ID: fmt.Sprintf("scope%d", i), InterfaceID: id,
			Subnet: fmt.Sprintf("198.18.%d.0/24", i), Router: fmt.Sprintf("198.18.%d.1", i),
			Pools:        []dhcpserver.Pool{{First: fmt.Sprintf("198.18.%d.10", i), Last: fmt.Sprintf("198.18.%d.20", i)}},
			LeaseSeconds: 120, RenewSeconds: 60, RebindSeconds: 90,
		})
	}
	network, err := networkplan.Canonical(network.Config)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := routedmodel.Canonical(routedmodel.Policy{SchemaVersion: 2, LabOnly: true, Network: network, DHCPServer: &server})
	if err != nil {
		t.Fatal(err)
	}
	return local, policy
}

func TestDHCPServerLocalInExactRulesAndReadback(t *testing.T) {
	local, policy := dhcpServerFixture(t, 2)
	a, err := CompileForRoutedPolicy(local, nil, policy)
	if err != nil || len(a.ControlIDs) != 3 || len(a.Rules) != 0 {
		t.Fatal("expected one WAN acquisition and two LAN server controls", err)
	}
	objects := listing(t, a)
	for i := range 2 {
		body := objects[4+i]["rule"].(object)
		iface := fmt.Sprintf("lan%d", i)
		want := rule(fmt.Sprintf("andeiva-dhcp-server:v1:scope%d", i), []object{
			match(meta("nfproto"), "ipv4"), match(meta("iifname"), iface), match(payload("ip", "daddr"), fmt.Sprintf("198.18.%d.1", i)),
			match(meta("l4proto"), "udp"), match(payload("udp", "sport"), 68), match(payload("udp", "dport"), 67),
			{"counter": object{"packets": 0, "bytes": 0}}, {"accept": nil},
		})
		delete(body, "handle")
		if !equalJSON(body, want) {
			t.Fatal("wrong exact LAN rule", body)
		}
	}
	legacy, err := CompileForNetwork(local, nil, &policy.Policy.Network)
	if err != nil || !equalJSON(listing(t, legacy)[3], objects[3]) {
		t.Fatal("WAN acquisition changed", err)
	}
	observation, err := VerifyObservation(observed(t, objects), a)
	if err != nil || len(observation.Controls) != 3 || observation.Controls[2].ID != "andeiva-dhcp-server:v1:scope1" {
		t.Fatal("exact readback rejected", observation.Controls, err)
	}

	// The IP and UDP payloads imply these guards when nft elides them.
	unwrapped := listing(t, a)
	exprs := unwrapped[4]["rule"].(object)["expr"].([]any)
	unwrapped[4]["rule"].(object)["expr"] = []any{exprs[1], exprs[2], exprs[4], exprs[5], exprs[6], exprs[7]}
	if _, err = VerifyObservation(observed(t, unwrapped), a); err != nil {
		t.Fatal("equivalent typed payload readback rejected", err)
	}

	for _, tc := range []struct {
		name  string
		index int
		value any
	}{
		{"wrong family", 0, "ipv6"}, {"WAN interface", 1, "wan0"}, {"other LAN interface", 1, "lan1"},
		{"broadcast destination", 2, "255.255.255.255"}, {"other LAN destination", 2, "198.18.1.1"},
		{"wrong protocol", 3, "tcp"}, {"foreign source port", 4, 67}, {"foreign destination port", 5, 68},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := listing(t, a)
			mutated[4]["rule"].(object)["expr"].([]any)[tc.index].(object)["match"].(object)["right"] = tc.value
			if _, err := VerifyObservation(observed(t, mutated), a); err != ErrObservation {
				t.Fatal("changed DHCP control accepted", err)
			}
		})
	}
	duplicate := listing(t, a)
	duplicate[5] = duplicate[4]
	for _, changed := range [][]object{objects[:len(objects)-1], append(listing(t, a), objects[4]), duplicate} {
		if _, err = VerifyObservation(observed(t, changed), a); err != ErrObservation {
			t.Fatal("missing or duplicate DHCP control accepted", err)
		}
	}
}

func TestDHCPServerLocalInLegacyDisabledAndPolicyValidation(t *testing.T) {
	local, enabled := dhcpServerFixture(t, 2)
	original, err := CompileForNetwork(local, nil, &enabled.Policy.Network)
	if err != nil {
		t.Fatal(err)
	}
	active, err := CompileForRoutedPolicy(local, nil, enabled)
	if err != nil {
		t.Fatal(err)
	}
	disabled := enabled.Policy
	disabled.DHCPServer = &dhcpserver.Config{SchemaVersion: 1, Enabled: false, Scopes: enabled.Policy.DHCPServer.Scopes}
	legacy := disabled
	legacy.SchemaVersion, legacy.DHCPServer = 1, nil
	for _, policy := range []routedmodel.Policy{disabled, legacy} {
		revision, err := routedmodel.Canonical(policy)
		if err != nil {
			t.Fatal(err)
		}
		a, err := CompileForRoutedPolicy(local, nil, revision)
		if err != nil || !bytes.Equal(marshal(t, a), marshal(t, original)) {
			t.Fatal("disabled DHCP or V1 changed artifact bytes", err)
		}
		if _, err = VerifyObservation(observed(t, listing(t, active)), a); err != ErrObservation {
			t.Fatal("inactive configuration admitted a server rule", err)
		}
	}
	enabled.Policy.DHCPServer.Scopes[0], enabled.Policy.DHCPServer.Scopes[1] = enabled.Policy.DHCPServer.Scopes[1], enabled.Policy.DHCPServer.Scopes[0]
	if _, err = CompileForRoutedPolicy(local, nil, enabled); err != ErrPolicy {
		t.Fatal("noncanonical scopes accepted with canonical hash", err)
	}
	enabled.Policy.DHCPServer.Scopes[0].InterfaceID = "wan"
	if _, err = CompileForRoutedPolicy(local, nil, enabled); err != ErrPolicy {
		t.Fatal("WAN scope accepted", err)
	}
	if _, err = VerifyObservation(observed(t, listing(t, active)), active); err != nil {
		t.Fatal("caller mutation changed compiled policy", err)
	}
	active.DHCPPolicy.Hash = ""
	if _, err = VerifyObservation(observed(t, listing(t, active)), active); err != ErrObservation {
		t.Fatal("unverified policy hash accepted", err)
	}
}

func TestDHCPServerLocalInFullControlBudget(t *testing.T) {
	_, p := dhcpServerFixture(t, networkplan.MaxInterfaces-1)
	local := fixture()
	local.Interfaces, local.Services[0].Bindings = nil, nil
	var neighbors []NeighborLink
	for link, name := range []string{"lan0", "lan1"} {
		var owned, peer []string
		for i := range MaxNeighborAddresses {
			owned = append(owned, fmt.Sprintf("fd00:%x::%x", link+1, i+1))
			peer = append(peer, fmt.Sprintf("fd00:%x::%x", link+1, i+16))
		}
		local.Interfaces = append(local.Interfaces, localpolicy.Interface{Name: name, Zone: localpolicy.LAN, Addresses: owned})
		local.Services[0].Bindings = append(local.Services[0].Bindings, localpolicy.Binding{Interface: name, Zone: localpolicy.LAN, LocalAddress: owned[0], Sources: []string{peer[0] + "/128"}})
		neighbors = append(neighbors, NeighborLink{Interface: name, LocalAddresses: owned, PeerAddresses: peer})
	}
	a, err := CompileForRoutedPolicy(local, neighbors, p)
	if err != nil || len(a.ControlIDs) != maxRoutedControlRules {
		t.Fatal("maximum admitted scoped controls failed compilation", len(a.ControlIDs), err)
	}
	if _, err := VerifyObservation(observed(t, listing(t, a)), a); err != nil {
		t.Fatal("maximum admitted scoped controls failed readback", err)
	}
}
