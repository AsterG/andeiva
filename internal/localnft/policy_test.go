package localnft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

func fixture() localpolicy.Config {
	return localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "src0", Zone: localpolicy.LAN, Addresses: []string{"192.0.2.1", "fd42:616e:6465:1::1", "fe80::1"}}}, Services: []localpolicy.Service{{
		ID: "admin", Owner: "management", Kind: localpolicy.ManagementHTTPS, Enabled: true, CompatibleZones: []localpolicy.Zone{localpolicy.LAN}, Authentication: localpolicy.Authenticated,
		Endpoints: []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: 8443, LastPort: 8443}},
		Bindings:  []localpolicy.Binding{{Interface: "src0", Zone: localpolicy.LAN, LocalAddress: "192.0.2.1", Sources: []string{"192.0.2.2/32"}}, {Interface: "src0", Zone: localpolicy.LAN, LocalAddress: "fd42:616e:6465:1::1", Sources: []string{"fd42:616e:6465:1::2/128"}}},
		Lifecycle: localpolicy.Lifecycle{VerifyListeners: true, VerifyRules: true, RevertOnFailure: true, ConfirmedManagementChanges: true},
	}}}
}

func peers() []NeighborLink {
	return []NeighborLink{{Interface: "src0", LocalAddresses: []string{"fd42:616e:6465:1::1", "fe80::1"}, PeerAddresses: []string{"fd42:616e:6465:1::2", "fd42:616e:6465:1::3", "fe80::2"}}}
}

func mustCompile(t *testing.T) Artifact {
	t.Helper()
	a, err := CompileWithNeighbors(fixture(), peers())
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func marshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func listing(t *testing.T, a Artifact) []object {
	t.Helper()
	objects, err := createObjects(a.Create)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range objects {
		for _, raw := range o {
			raw.(object)["handle"] = json.Number("18446744073709551615")
		}
	}
	return append([]object{{"metainfo": object{"version": "1.1.3", "release_name": "fixture", "json_schema_version": 1}}}, objects...)
}
func observed(t *testing.T, objects []object) []byte {
	t.Helper()
	return marshal(t, object{"nftables": objects})
}

func TestCompileDomainsLifecycleAndManagedSubset(t *testing.T) {
	a := mustCompile(t)
	if len(a.Rules) != 2 || len(a.ControlIDs) == 0 || len(a.Digest) != 64 || len(a.Batch) <= len(a.Create) {
		t.Fatal("incomplete artifact")
	}
	if err := ValidateManaged(fixture()); err != nil {
		t.Fatal(err)
	}
	objects, _ := createObjects(a.Create)
	chain := objects[1]["chain"].(object)
	if chain["hook"] != "input" || chain["policy"] != "drop" || chain["prio"] != json.Number("10") {
		t.Fatal(chain)
	}
	for _, prohibited := range []string{`"forward"`, `"output"`, `"nat"`, `"ct"`, `"loopback"`, `"flush"`} {
		if bytes.Contains(a.Create, []byte(prohibited)) {
			t.Fatal(prohibited)
		}
	}
	batch, _ := decodeObjects(a.Batch)
	if !equalJSON(batch[0], object{"delete": object{"table": object{"family": "inet", "name": TableName}}}) {
		t.Fatal("replacement scope")
	}
	c := fixture()
	c.Services[0].Enabled = false
	disabled, err := CompileWithNeighbors(c, peers())
	if err != nil || len(disabled.Rules) != 0 || len(disabled.ControlIDs) != 0 {
		t.Fatal("residual rules", err)
	}
	c = fixture()
	c.Services[0].Endpoints[0].FirstPort = 9443
	c.Services[0].Endpoints[0].LastPort = 9443
	changed, err := CompileWithNeighbors(c, peers())
	if err != nil || a.Digest == changed.Digest || a.Rules[0].ID == changed.Rules[0].ID {
		t.Fatal("port replacement", err)
	}
	c = fixture()
	c.Services[0].Kind = localpolicy.DNS
	c.Services[0].Endpoints[0].Protocol = localpolicy.UDP
	if _, err := Compile(c); err != nil {
		t.Fatal("UDP fixture", err)
	}
	if ValidateManaged(c) == nil {
		t.Fatal("unimplemented engine admitted")
	}
	c = fixture()
	c.Services[0].Bindings[1].LocalAddress = "fe80::1"
	c.Services[0].Bindings[1].Sources = []string{"fe80::2/128"}
	if ValidateManaged(c) == nil {
		t.Fatal("link-local administration admitted")
	}
	c = fixture()
	c.Services[0].Endpoints[0] = localpolicy.Endpoint{Protocol: localpolicy.TCP, FirstPort: 443, LastPort: 443}
	if ValidateManaged(c) == nil {
		t.Fatal("privileged listener admitted")
	}
}

func TestNeighborRulesExactAndProfileCanonical(t *testing.T) {
	a := mustCompile(t)
	objects, _ := createObjects(a.Create)
	seen := map[string]bool{}
	for _, entry := range objects[2 : 2+len(a.ControlIDs)] {
		r := entry["rule"].(object)
		id := r["comment"].(string)
		if !ControlID(id) || seen[id] {
			t.Fatal("control ownership", id)
		}
		seen[id] = true
		exprs := r["expr"].([]any)
		value := func(i int) any { return exprs[i].(object)["match"].(object)["right"] }
		if value(0) != "ipv6" || value(1) != "src0" || value(4) != json.Number("255") || value(7) != json.Number("0") {
			t.Fatal("ND guards")
		}
		source, destination, target := value(2).(string), value(3).(string), value(8).(string)
		switch value(6) {
		case json.Number("135"):
			if target != "fd42:616e:6465:1::1" && target != "fe80::1" {
				t.Fatal("NS target")
			}
			if destination != target && destination != solicitedNode(target) {
				t.Fatal("NS destination")
			}
			if source == "::" && destination != solicitedNode(target) {
				t.Fatal("DAD destination")
			}
		case json.Number("136"):
			if source != target || source == "::" || (destination != "ff02::1" && destination != "fd42:616e:6465:1::1" && destination != "fe80::1") {
				t.Fatal("NA scope")
			}
		default:
			t.Fatal("unexpected ICMP type")
		}
	}
	p := peers()
	p[0].LocalAddresses[0], p[0].LocalAddresses[1] = p[0].LocalAddresses[1], p[0].LocalAddresses[0]
	p[0].PeerAddresses[0], p[0].PeerAddresses[1] = p[0].PeerAddresses[1], p[0].PeerAddresses[0]
	b, err := CompileWithNeighbors(fixture(), p)
	if err != nil || !equalJSON(a, b) {
		t.Fatal("order-dependent profile", err)
	}
	p[0].PeerAddresses[0] = "fd42:616e:6465:1::4"
	b, err = CompileWithNeighbors(fixture(), p)
	if err != nil || a.Digest == b.Digest || a.Revision.Hash != b.Revision.Hash {
		t.Fatal("profile must bind artifact, not user revision", err)
	}
	c := fixture()
	c.Services[0].Enabled = false
	a, _ = CompileWithNeighbors(c, peers())
	b, _ = CompileWithNeighbors(c, p)
	if a.Digest == b.Digest {
		t.Fatal("inactive profile is not digest-bound")
	}
}

func TestValidationBudgetsAndUntrustedNeighbors(t *testing.T) {
	cases := map[string]func(*localpolicy.Config){
		"service_count":   func(c *localpolicy.Config) { c.Services = append(c.Services, c.Services[0], c.Services[0]) },
		"interface_count": func(c *localpolicy.Config) { c.Interfaces = append(c.Interfaces, c.Interfaces[0], c.Interfaces[0]) },
		"binding_count": func(c *localpolicy.Config) {
			for len(c.Services[0].Bindings) <= MaxBindings {
				c.Services[0].Bindings = append(c.Services[0].Bindings, c.Services[0].Bindings[0])
			}
		},
		"source_count":      func(c *localpolicy.Config) { c.Services[0].Bindings[0].Sources = make([]string, MaxSources+1) },
		"endpoint_count":    func(c *localpolicy.Config) { c.Services[0].Endpoints = nil },
		"command_injection": func(c *localpolicy.Config) { c.Interfaces[0].Name = "src0;id" },
		"foreign_ip":        func(c *localpolicy.Config) { c.Services[0].Bindings[0].LocalAddress = "192.0.2.99" },
		"config_frame":      func(c *localpolicy.Config) { c.Services[0].Owner = strings.Repeat("x", MaxConfig) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := fixture()
			change(&c)
			if _, err := Compile(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	bad := []NeighborLink{
		{Interface: "ens33", LocalAddresses: []string{"fd42:616e:6465:1::1"}, PeerAddresses: []string{"fe80::2"}},
		{Interface: "src0", LocalAddresses: []string{"fd42:616e:6465:1::99"}, PeerAddresses: []string{"fe80::2"}},
		{Interface: "src0", LocalAddresses: []string{"fe80::1"}, PeerAddresses: []string{"::"}},
		{Interface: "src0", LocalAddresses: []string{"fe80::1"}, PeerAddresses: []string{"fe80::1"}},
		{Interface: "src0", LocalAddresses: []string{"fe80::1"}, PeerAddresses: []string{"ff02::1"}},
		{Interface: "src0", LocalAddresses: []string{"fe80::1"}, PeerAddresses: []string{"fe80::2%src0"}},
		{Interface: "src0", LocalAddresses: []string{"fe80::1"}, PeerAddresses: []string{"fe80::2", "fe80::2"}},
	}
	for _, link := range bad {
		if _, err := CompileWithNeighbors(fixture(), []NeighborLink{link}); err == nil {
			t.Fatal("accepted neighbors", link)
		}
	}
}

func TestObservationCountersAndFailClosedPredicates(t *testing.T) {
	a := mustCompile(t)
	objects := listing(t, a)
	last := objects[len(objects)-1]["rule"].(object)["expr"].([]any)
	last[len(last)-2].(object)["counter"] = object{"packets": json.Number("18446744073709551615"), "bytes": json.Number("9007199254740993")}
	data := observed(t, objects)
	got, err := VerifyObservation(data, a)
	if err != nil || got.Rules[len(got.Rules)-1].Packets != ^uint64(0) || got.Rules[len(got.Rules)-1].Bytes != 9007199254740993 || got.ReadbackHash != hash(data) || len(got.Controls) != len(a.ControlIDs) {
		t.Fatal(got, err)
	}
	// Every service and ND predicate must be checked even when comments match.
	for i := 3; i < len(objects); i++ {
		exprs := objects[i]["rule"].(object)["expr"].([]any)
		for j := 0; j < len(exprs)-2; j++ {
			t.Run(fmt.Sprintf("predicate_%d_%d", i, j), func(t *testing.T) {
				copy := listing(t, a)
				copy[i]["rule"].(object)["expr"].([]any)[j].(object)["match"].(object)["right"] = "unexpected"
				if _, err := VerifyObservation(observed(t, copy), a); err == nil {
					t.Fatal("divergent expression accepted")
				}
			})
		}
	}
}

func TestObservationRejectsMalformedOrDivergentState(t *testing.T) {
	a := mustCompile(t)
	cases := map[string]func([]object) []object{
		"extra_rule":      func(o []object) []object { return append(o, o[len(o)-1]) },
		"missing_rule":    func(o []object) []object { return o[:len(o)-1] },
		"reordered_rules": func(o []object) []object { o[3], o[4] = o[4], o[3]; return o },
		"foreign_table":   func(o []object) []object { o[1]["table"].(object)["name"] = "filter"; return o },
		"priority":        func(o []object) []object { o[2]["chain"].(object)["prio"] = 0; return o },
		"policy":          func(o []object) []object { o[2]["chain"].(object)["policy"] = "accept"; return o },
		"hook":            func(o []object) []object { o[2]["chain"].(object)["hook"] = "forward"; return o },
		"comment":         func(o []object) []object { o[3]["rule"].(object)["comment"] = "other"; return o },
		"extra_field":     func(o []object) []object { o[3]["rule"].(object)["position"] = 1; return o },
		"bad_handle":      func(o []object) []object { o[1]["table"].(object)["handle"] = -1; return o },
		"bad_metainfo":    func(o []object) []object { o[0]["metainfo"].(object)["unknown"] = true; return o },
		"double_metainfo": func(o []object) []object { return append(o, o[0]) },
		"counter_float": func(o []object) []object {
			e := o[3]["rule"].(object)["expr"].([]any)
			e[len(e)-2].(object)["counter"] = object{"packets": 1.5, "bytes": 0}
			return o
		},
		"counter_overflow": func(o []object) []object {
			e := o[3]["rule"].(object)["expr"].([]any)
			e[len(e)-2].(object)["counter"] = object{"packets": json.Number("18446744073709551616"), "bytes": 0}
			return o
		},
		"counter_null": func(o []object) []object {
			e := o[3]["rule"].(object)["expr"].([]any)
			e[len(e)-2].(object)["counter"] = nil
			return o
		},
		"counter_unknown": func(o []object) []object {
			e := o[3]["rule"].(object)["expr"].([]any)
			e[len(e)-2].(object)["counter"] = object{"packets": 0, "bytes": 0, "x": 0}
			return o
		},
		"drop_missing": func(o []object) []object {
			e := o[3]["rule"].(object)["expr"].([]any)
			e[len(e)-1] = object{"drop": nil}
			return o
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyObservation(observed(t, change(listing(t, a))), a); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, bad := range [][]byte{nil, []byte(`{"nftables":[],"nftables":[]}`), []byte(`{"nftables":[],"other":1}`), []byte(`{"nftables":[]} {}`), bytes.Repeat([]byte(" "), MaxObservation+1)} {
		if _, err := VerifyObservation(bad, a); err == nil {
			t.Fatal("malformed JSON accepted")
		}
	}
	data := observed(t, listing(t, a))
	changed := a
	changed.Digest = strings.Repeat("0", 64)
	if _, err := VerifyObservation(data, changed); err == nil {
		t.Fatal("untrusted expected artifact accepted")
	}
	changed = a
	changed.Create = append([]byte(nil), a.Create...)
	changed.Create[0] = '['
	if _, err := VerifyObservation(data, changed); err == nil {
		t.Fatal("altered expected bytes accepted")
	}
}

func TestObserverAcceptsOnlyEquivalentKernelNormalization(t *testing.T) {
	a := mustCompile(t)
	for mask := 0; mask < 4; mask++ {
		o := listing(t, a)
		for _, entry := range o[3:] {
			r := entry["rule"].(object)
			es := r["expr"].([]any)
			result := []any{}
			for _, raw := range es {
				e := raw.(object)
				if m, ok := e["match"].(object); ok {
					left := m["left"].(object)
					if meta, ok := left["meta"].(object); ok {
						if meta["key"] == "nfproto" && mask&1 != 0 || meta["key"] == "l4proto" && mask&2 != 0 {
							continue
						}
						if meta["key"] == "l4proto" {
							m["right"] = map[string]int{"tcp": 6, "udp": 17, "ipv6-icmp": 58}[m["right"].(string)]
						}
					}
					if p, ok := left["payload"].(object); ok && p["protocol"] == "icmpv6" && p["field"] == "type" {
						if m["right"] == json.Number("135") {
							m["right"] = "nd-neighbor-solicit"
						} else {
							m["right"] = "nd-neighbor-advert"
						}
					}
				}
				result = append(result, e)
			}
			r["expr"] = result
		}
		if _, err := VerifyObservation(observed(t, o), a); err != nil {
			t.Fatal(mask, err)
		}
	}
}

func TestCompileAndObserveConcurrent(t *testing.T) {
	c, p := fixture(), peers()
	a := mustCompile(t)
	data := observed(t, listing(t, a))
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 5 {
				b, err := CompileWithNeighbors(c, p)
				if err != nil || b.Digest != a.Digest {
					t.Error("concurrent compile", err)
					return
				}
				if _, err := VerifyObservation(data, a); err != nil {
					t.Error("concurrent observe", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func TestMaximumRuntimeFootprint(t *testing.T) {
	c := fixture()
	c.Interfaces = nil
	for i := 1; i <= 2; i++ {
		addresses := []string{}
		for j := 1; j <= 4; j++ {
			addresses = append(addresses, fmt.Sprintf("fd42:616e:6465:%d::%d", i, j))
		}
		c.Interfaces = append(c.Interfaces, localpolicy.Interface{Name: fmt.Sprintf("lan%d", i), Zone: localpolicy.LAN, Addresses: addresses})
	}
	links := []NeighborLink{}
	for i, iface := range c.Interfaces {
		links = append(links, NeighborLink{Interface: iface.Name, LocalAddresses: iface.Addresses, PeerAddresses: []string{fmt.Sprintf("fd42:616e:6465:%d::10", i+1), fmt.Sprintf("fd42:616e:6465:%d::11", i+1), fmt.Sprintf("fd42:616e:6465:%d::12", i+1), fmt.Sprintf("fd42:616e:6465:%d::13", i+1)}})
	}
	s := c.Services[0]
	s.Bindings = nil
	for _, iface := range c.Interfaces {
		for _, address := range iface.Addresses[:2] {
			sources := []string{}
			for j := 16; j < 32; j++ {
				sources = append(sources, fmt.Sprintf("fd42:616e:6465:9::%x/128", j))
			}
			s.Bindings = append(s.Bindings, localpolicy.Binding{Interface: iface.Name, Zone: localpolicy.LAN, LocalAddress: address, Sources: sources})
		}
	}
	c.Services = []localpolicy.Service{s, s}
	c.Services[1].ID = "ssh"
	c.Services[1].Kind = localpolicy.ManagementSSH
	c.Services[1].Endpoints = []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: 2222, LastPort: 2222}}
	a, err := CompileWithNeighbors(c, links)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Rules) != MaxRules || len(a.ControlIDs) != 112 {
		t.Fatal("capacity not exercised", len(a.Rules), len(a.ControlIDs))
	}
	data := observed(t, listing(t, a))
	if _, err := VerifyObservation(data, a); err != nil {
		t.Fatal(err)
	}
	configBytes := marshal(t, c)
	t.Logf("config=%d create=%d replace=%d observed=%d permissions=%d controls=%d", len(configBytes), len(a.Create), len(a.Batch), len(data), len(a.Rules), len(a.ControlIDs))
}

func BenchmarkCompile(b *testing.B) {
	c, p := fixture(), peers()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := CompileWithNeighbors(c, p); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkObservation(b *testing.B) {
	a, _ := CompileWithNeighbors(fixture(), peers())
	o, _ := createObjects(a.Create)
	data, _ := json.Marshal(object{"nftables": o})
	b.ReportAllocs()
	for b.Loop() {
		if _, err := VerifyObservation(data, a); err != nil {
			b.Fatal(err)
		}
	}
}
