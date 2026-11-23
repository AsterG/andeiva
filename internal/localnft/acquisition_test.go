package localnft

import (
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkplan"
)

func acquisitionFixture(t *testing.T) (localpolicy.Config, networkplan.Revision) {
	t.Helper()
	c := networkplan.Config{SchemaVersion: 1, Interfaces: []networkplan.Interface{
		{ID: "lan", Binding: networkplan.Binding{Name: "lan0", HardwareAddress: "02:00:00:00:01:01"}, Role: networkplan.LAN, Zone: "inside", IPv4: networkplan.IPv4{Mode: "static", Address: "198.18.0.1/24"}},
		{ID: "wan", Binding: networkplan.Binding{Name: "wan0", HardwareAddress: "02:00:00:00:02:01"}, Role: networkplan.WAN, Zone: "outside", IPv4: networkplan.IPv4{Mode: "dhcp"}},
	}, Zones: []networkplan.Zone{{ID: "inside", Kind: networkplan.LAN}, {ID: "outside", Kind: networkplan.WAN}}, DefaultRoute: networkplan.DefaultRoute{InterfaceID: "wan", Metric: 10}, DNS: networkplan.DNS{Mode: "none", Servers: []string{}}, IPv6Forwarding: "deny"}
	n, err := networkplan.Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	return localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}}}, n
}

func TestAcquisitionSelectedWANRuleAndCompleteReadback(t *testing.T) {
	c, n := acquisitionFixture(t)
	a, err := CompileForNetwork(c, nil, &n)
	if err != nil {
		t.Fatal(err)
	}
	objects := listing(t, a)
	if len(objects) != 4 || len(a.ControlIDs) != 1 || len(a.Rules) != 0 {
		t.Fatal("not one control rule")
	}
	r := objects[3]["rule"].(object)
	expr := r["expr"].([]any)
	if len(expr) != 7 {
		t.Fatal("unexpected admission predicates")
	}
	// Exact complete expression equality proves family/interface/both ports;
	// also excludes conntrack, address, UID and forwarding predicates.
	want := []object{match(meta("nfproto"), "ipv4"), match(meta("iifname"), "wan0"), match(meta("l4proto"), "udp"), match(payload("udp", "sport"), 67), match(payload("udp", "dport"), 68), {"counter": object{"packets": 0, "bytes": 0}}, {"accept": nil}}
	if !equalJSON(expr, want) {
		t.Fatal("wrong scoped acquisition rule")
	}
	if _, err = VerifyObservation(observed(t, objects), a); err != nil {
		t.Fatal(err)
	}
	for name, replacement := range map[string]any{"lan": "lan0", "ipv6": "ipv6", "ipv6_numeric": 10, "unknown_family": 0, "tcp": "tcp", "source_port": 66, "destination_port": 69} {
		t.Run(name, func(t *testing.T) {
			x := listing(t, a)
			i := map[string]int{"lan": 1, "ipv6": 0, "ipv6_numeric": 0, "unknown_family": 0, "tcp": 2, "source_port": 3, "destination_port": 4}[name]
			x[3]["rule"].(object)["expr"].([]any)[i].(map[string]any)["match"].(map[string]any)["right"] = replacement
			if _, e := VerifyObservation(observed(t, x), a); e == nil {
				t.Fatal("foreign admission accepted")
			}
		})
	}
	extra := append(listing(t, a), objects[3])
	if _, err = VerifyObservation(observed(t, extra), a); err == nil {
		t.Fatal("extra rule accepted")
	}
	if _, err = VerifyObservation(observed(t, objects[:3]), a); err == nil {
		t.Fatal("missing control accepted")
	}
	baseline, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyObservation(observed(t, objects), baseline); err == nil {
		t.Fatal("disabled service admitted stale rule")
	}
	if _, err = VerifyObservation(observed(t, listing(t, baseline)), a); err == nil {
		t.Fatal("active service accepted baseline")
	}
}

func TestAcquisitionStaticAbsentAndUntrustedRevision(t *testing.T) {
	c, n := acquisitionFixture(t)
	old := n.Hash
	n.Config.Interfaces[1].IPv4 = networkplan.IPv4{Mode: "static", Address: "198.18.1.10/24", Gateway: "198.18.1.1"}
	if _, err := CompileForNetwork(c, nil, &n); err == nil {
		t.Fatal("stale hash accepted")
	}
	var err error
	n, err = networkplan.Canonical(n.Config)
	if err != nil || n.Hash == old {
		t.Fatal(err)
	}
	a, err := CompileForNetwork(c, nil, &n)
	if err != nil || len(a.ControlIDs) != 0 {
		t.Fatal("static admission", err)
	}
	n.Config.Interfaces[1].Binding.Name = "lan0"
	if _, err = CompileForNetwork(c, nil, &n); err == nil {
		t.Fatal("changed interface accepted")
	}
	c, n = acquisitionFixture(t)
	a, err = CompileForNetwork(c, nil, &n)
	if err != nil {
		t.Fatal(err)
	}
	// Caller mutation cannot alter the retained canonical network.
	n.Config.Interfaces[1].Binding.Name = "foreign0"
	if a.Network.Config.Interfaces[1].Binding.Name != "wan0" {
		t.Fatal("artifact aliases caller")
	}
	raw, _ := json.Marshal(a)
	var copy Artifact
	if json.Unmarshal(raw, &copy) != nil {
		t.Fatal("artifact roundtrip")
	}
	copy.Network.Hash = old + "00"
	if _, err = VerifyObservation(observed(t, listing(t, a)), copy); err == nil {
		t.Fatal("tampered expected network accepted")
	}
}

func TestAcquisitionNumericFamilyReadback(t *testing.T) {
	c, n := acquisitionFixture(t)
	a, err := CompileForNetwork(c, nil, &n)
	if err != nil {
		t.Fatal(err)
	}
	objects := listing(t, a)
	expr := objects[3]["rule"].(object)["expr"].([]any)
	// NFPROTO_IPV4=2 in numeric nft output; the UDP payload permits nft to
	// remove the redundant l4proto guard, but does not imply an IP family.
	expr[0].(object)["match"].(object)["right"] = 2
	objects[3]["rule"].(object)["expr"] = append(expr[:2], expr[3:]...)
	if _, err = VerifyObservation(observed(t, objects), a); err != nil {
		t.Fatal("numeric IPv4 readback rejected", err)
	}
}

func TestAcquisitionCannotOmitFamilyGuard(t *testing.T) {
	c, n := acquisitionFixture(t)
	a, err := CompileForNetwork(c, nil, &n)
	if err != nil {
		t.Fatal(err)
	}
	objects := listing(t, a)
	expr := objects[3]["rule"].(object)["expr"].([]any)
	objects[3]["rule"].(object)["expr"] = expr[1:]
	if _, err = VerifyObservation(observed(t, objects), a); err == nil {
		t.Fatal("UDP alone does not imply IPv4; missing family admitted IPv6")
	}
}
