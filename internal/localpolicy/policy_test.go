package localpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func fixture() Config {
	return Config{SchemaVersion: SchemaVersion, Interfaces: []Interface{
		{Name: "lan0", Zone: LAN, Addresses: []string{"192.0.2.1", "2001:db8:1::1"}},
		{Name: "wan0", Zone: WAN, Addresses: []string{"198.51.100.1"}},
		{Name: "dmz0", Zone: Other, Addresses: []string{"203.0.113.1"}},
	}, Services: []Service{{ID: "admin", Owner: "management", Kind: ManagementHTTPS, Enabled: true,
		CompatibleZones: []Zone{LAN, WAN, Other}, Authentication: Authenticated,
		Endpoints: []Endpoint{{TCP, 443, 443}},
		Bindings:  []Binding{{Interface: "lan0", Zone: LAN, LocalAddress: "192.0.2.1", Sources: []string{"192.0.2.10/32"}}},
		Lifecycle: Lifecycle{true, true, true, true}}}}
}

func cloneConfig(t *testing.T, c Config) Config {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out Config
	if err = json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestManagementLANDefaultAndExplicitMultipleBindings(t *testing.T) {
	c := fixture()
	s, err := DefaultManagement("management", "admin", c.Interfaces[0], "192.0.2.1", []string{"192.0.2.10/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Bindings) != 1 || s.Bindings[0].Zone != LAN || s.Bindings[0].WANOptIn || len(s.Bindings[0].Sources) != 1 {
		t.Fatal("unsafe default", s)
	}
	if _, err = DefaultManagement("management", "admin", c.Interfaces[1], "198.51.100.1", []string{"198.51.100.10/32"}); !errors.Is(err, ErrPolicy) {
		t.Fatal("default must reject WAN")
	}
	if _, err = DefaultManagement("management", "admin", c.Interfaces[0], "192.0.2.1", nil); !errors.Is(err, ErrPolicy) {
		t.Fatal("must not infer LAN sources")
	}
	c.Services[0].Bindings = append(c.Services[0].Bindings,
		Binding{Interface: "wan0", Zone: WAN, LocalAddress: "198.51.100.1", Sources: []string{"198.51.100.10/32"}, WANOptIn: true},
		Binding{Interface: "dmz0", Zone: Other, LocalAddress: "203.0.113.1", Sources: []string{"203.0.113.10/32"}},
		Binding{Interface: "lan0", Zone: LAN, LocalAddress: "2001:db8:1::1", Sources: []string{"2001:db8:1::10/128"}})
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Rules) != 4 {
		t.Fatal("all explicit bindings must compile", len(a.Rules))
	}
	c.Services[0].Bindings = []Binding{c.Services[0].Bindings[1]}
	a, err = Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Rules) != 1 || a.Rules[0].Zone != WAN {
		t.Fatal("explicit WAN-only choice must work")
	}
}

func TestValidationNegative(t *testing.T) {
	cases := map[string]func(*Config){
		"schema":              func(c *Config) { c.SchemaVersion = 2 },
		"interface_injection": func(c *Config) { c.Interfaces[0].Name = "lan0;id" },
		"interface_wildcard":  func(c *Config) { c.Services[0].Bindings[0].Interface = "*" },
		"unknown_interface":   func(c *Config) { c.Services[0].Bindings[0].Interface = "missing" },
		"address_wildcard_v4": func(c *Config) { c.Services[0].Bindings[0].LocalAddress = "0.0.0.0" },
		"address_wildcard_v6": func(c *Config) { c.Services[0].Bindings[0].LocalAddress = "::" },
		"unknown_local":       func(c *Config) { c.Services[0].Bindings[0].LocalAddress = "192.0.2.2" },
		"mapped_v4":           func(c *Config) { c.Interfaces[0].Addresses = []string{"::ffff:192.0.2.1"} },
		"scoped_address":      func(c *Config) { c.Interfaces[0].Addresses = []string{"fe80::1%lan0"} },
		"multicast_local":     func(c *Config) { c.Interfaces[0].Addresses = []string{"ff02::1"} },
		"duplicate_address":   func(c *Config) { c.Interfaces[1].Addresses = c.Interfaces[0].Addresses },
		"zone_spoof": func(c *Config) {
			b := &c.Services[0].Bindings[0]
			b.Interface = "wan0"
			b.LocalAddress = "198.51.100.1"
		},
		"wan_requires_optin": func(c *Config) {
			c.Services[0].Bindings[0] = Binding{Interface: "wan0", Zone: WAN, LocalAddress: "198.51.100.1", Sources: []string{"198.51.100.10/32"}}
		},
		"lan_stale_optin":       func(c *Config) { c.Services[0].Bindings[0].WANOptIn = true },
		"incompatible_zone":     func(c *Config) { c.Services[0].CompatibleZones = []Zone{Other} },
		"protocol_injection":    func(c *Config) { c.Services[0].Endpoints[0].Protocol = "tcp accept" },
		"unknown_kind":          func(c *Config) { c.Services[0].Kind = "shell" },
		"owner_injection":       func(c *Config) { c.Services[0].Owner = "management\naccept" },
		"port_zero":             func(c *Config) { c.Services[0].Endpoints[0].FirstPort = 0 },
		"port_reverse":          func(c *Config) { c.Services[0].Endpoints[0].LastPort = 442 },
		"port_capacity":         func(c *Config) { c.Services[0].Endpoints = []Endpoint{{TCP, 1, 65535}} },
		"overlap_endpoints":     func(c *Config) { c.Services[0].Endpoints = append(c.Services[0].Endpoints, Endpoint{TCP, 440, 444}) },
		"no_source":             func(c *Config) { c.Services[0].Bindings[0].Sources = nil },
		"source_any":            func(c *Config) { c.Services[0].Bindings[0].Sources = []string{"0.0.0.0/0"} },
		"source_host_bits":      func(c *Config) { c.Services[0].Bindings[0].Sources = []string{"192.0.2.10/24"} },
		"source_family":         func(c *Config) { c.Services[0].Bindings[0].Sources = []string{"2001:db8::/64"} },
		"source_multicast":      func(c *Config) { c.Services[0].Bindings[0].Sources = []string{"224.0.0.0/24"} },
		"source_overlap":        func(c *Config) { c.Services[0].Bindings[0].Sources = []string{"192.0.2.0/24", "192.0.2.10/32"} },
		"duplicate_binding":     func(c *Config) { c.Services[0].Bindings = append(c.Services[0].Bindings, c.Services[0].Bindings[0]) },
		"no_management_auth":    func(c *Config) { c.Services[0].Authentication = NoAuthentication },
		"unknown_auth":          func(c *Config) { c.Services[0].Authentication = "guess" },
		"management_udp":        func(c *Config) { c.Services[0].Endpoints[0].Protocol = UDP },
		"no_management_confirm": func(c *Config) { c.Services[0].Lifecycle.ConfirmedManagementChanges = false },
		"no_revert":             func(c *Config) { c.Services[0].Lifecycle.RevertOnFailure = false },
		"no_listener_verify":    func(c *Config) { c.Services[0].Lifecycle.VerifyListeners = false },
		"no_rule_verify":        func(c *Config) { c.Services[0].Lifecycle.VerifyRules = false },
		"missing_dependency":    func(c *Config) { c.Services[0].DependsOn = []string{"missing"} },
		"self_dependency":       func(c *Config) { c.Services[0].DependsOn = []string{"admin"} },
		"duplicate_service":     func(c *Config) { c.Services = append(c.Services, c.Services[0]) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := fixture()
			change(&c)
			if _, err := Compile(c); !errors.Is(err, ErrPolicy) {
				t.Fatalf("expected rejection, got %v", err)
			}
		})
	}
}

func TestListenerConflictsAndDependencies(t *testing.T) {
	c := fixture()
	other := cloneConfig(t, c).Services[0]
	other.ID = "api"
	other.Kind = ManagementAPI
	c.Services = append(c.Services, other)
	if _, err := Compile(c); !errors.Is(err, ErrPolicy) {
		t.Fatal("conflicting listener accepted")
	}
	c.Services[1].Bindings[0].Sources = []string{"192.0.2.20/32"}
	if _, err := Compile(c); !errors.Is(err, ErrPolicy) {
		t.Fatal("source restrictions do not resolve socket conflicts")
	}
	c.Services[1].Endpoints[0] = Endpoint{TCP, 8443, 8443}
	c.Services[0].DependsOn = []string{"api"}
	if _, err := Compile(c); err != nil {
		t.Fatal(err)
	}
	c.Services[1].Enabled = false
	if _, err := Compile(c); !errors.Is(err, ErrPolicy) {
		t.Fatal("enabled dependency on disabled module accepted")
	}
	c.Services[0].Enabled = false
	c.Services[1].DependsOn = []string{"admin"}
	if _, err := Compile(c); !errors.Is(err, ErrPolicy) {
		t.Fatal("dormant dependency cycle accepted")
	}
	c.Services[1].DependsOn = nil
	c.Services[0].DependsOn = nil
	c.Services[1].Endpoints[0] = Endpoint{TCP, 443, 443}
	if a, err := Compile(c); err != nil || len(a.Rules) != 0 {
		t.Fatal("disabled module generated permissions", err)
	}
}

func TestCompilerIsLocalOnlyAndDualStack(t *testing.T) {
	c := fixture()
	c.Services[0].Bindings = append(c.Services[0].Bindings, Binding{Interface: "lan0", Zone: LAN, LocalAddress: "2001:db8:1::1", Sources: []string{"2001:db8:1::/64"}})
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		NFTables []map[string]map[string]json.RawMessage `json:"nftables"`
	}
	if err = json.Unmarshal(a.Create, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.NFTables) != 4 {
		t.Fatal("unexpected commands")
	}
	for _, command := range doc.NFTables {
		if len(command) != 1 || command["add"] == nil {
			t.Fatal("only add allowed")
		}
	}
	var chain struct {
		Table, Name, Hook, Policy string
		Priority                  int `json:"prio"`
	}
	if err = json.Unmarshal(doc.NFTables[1]["add"]["chain"], &chain); err != nil {
		t.Fatal(err)
	}
	if chain.Table != TableName || chain.Name != "input" || chain.Hook != "input" || chain.Policy != "drop" || chain.Priority != 10 {
		t.Fatal("unsafe chain", chain)
	}
	for _, text := range []string{`"nfproto"`, `"iifname"`, `"daddr"`, `"saddr"`, `"l4proto"`, `"dport"`, `"counter"`, `"accept"`, `"ip6"`, `"ipv6"`, `"192.0.2.10"`, `"2001:db8:1::"`} {
		if !bytes.Contains(a.Create, []byte(text)) {
			t.Error("missing required predicate", text)
		}
	}
	for _, text := range []string{`"forward"`, `"output"`, `"nat"`, `"flush"`, `"delete"`, `"ct"`, `"oifname"`} {
		if bytes.Contains(a.Create, []byte(text)) {
			t.Error("unexpected permission or operation", text)
		}
	}
	if a.Rules[0].Family == a.Rules[1].Family || a.Rules[0].Revision != a.Revision.Hash || a.Rules[0].Owner != "management" || a.Rules[0].Origin != "local_service" {
		t.Fatal("bad ownership/families")
	}
}

func TestUDPPortRangesAndIndependentSockets(t *testing.T) {
	c := fixture()
	s := cloneConfig(t, c).Services[0]
	s.ID = "dns"
	s.Owner = "resolver"
	s.Kind = DNS
	s.Endpoints = []Endpoint{{UDP, 5300, 5302}, {TCP, 5300, 5300}}
	s.Authentication = NoAuthentication
	c.Services = append(c.Services, s)
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Rules) != 3 || !bytes.Contains(a.Create, []byte(`"range":[5300,5302]`)) {
		t.Fatal("range not generated")
	}
}

func TestImpactEnableDisableAndPortChange(t *testing.T) {
	before := fixture()
	after := cloneConfig(t, before)
	after.Services[0].Endpoints[0] = Endpoint{TCP, 8443, 8443}
	d, err := Preview(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || len(d.Removed) != 1 || d.Added[0].Endpoint.FirstPort != 8443 || d.Removed[0].Endpoint.FirstPort != 443 || !d.RequiresConfirmed {
		t.Fatal("port replacement omitted", d)
	}
	after.Services[0].Enabled = false
	d, err = Preview(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 0 || len(d.Removed) != 1 || !d.RequiresConfirmed {
		t.Fatal("disabled service retained rule", d)
	}
	d, err = Preview(after, before)
	if err != nil || len(d.Added) != 1 || len(d.Removed) != 0 || !d.RequiresConfirmed {
		t.Fatal("enable impact", d, err)
	}
	d, err = Preview(before, before)
	if err != nil || d.RequiresConfirmed || len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatal("unchanged policy", d, err)
	}
}

func TestCanonicalOwnershipDeterminismAndNoAliasing(t *testing.T) {
	c := fixture()
	c.Services[0].Bindings[0].Sources = append(c.Services[0].Bindings[0].Sources, "192.0.2.20/32")
	original := cloneConfig(t, c)
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, original) {
		t.Fatal("compile mutated caller")
	}
	c.Interfaces[0], c.Interfaces[2] = c.Interfaces[2], c.Interfaces[0]
	c.Services[0].Bindings[0].Sources[0], c.Services[0].Bindings[0].Sources[1] = c.Services[0].Bindings[0].Sources[1], c.Services[0].Bindings[0].Sources[0]
	b, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest != b.Digest || a.Revision.Hash != b.Revision.Hash || !bytes.Equal(a.Create, b.Create) {
		t.Fatal("non-deterministic canonical policy")
	}
	c.Services[0].Owner = "different-owner"
	b, err = Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	if a.Rules[0].ID == b.Rules[0].ID || a.Revision.Hash == b.Revision.Hash {
		t.Fatal("ownership not bound to revision and identity")
	}
	a.Revision.Config.Services[0].Bindings[0].Sources[0] = "203.0.113.0/24"
	view, err := EffectiveView(original, "admin")
	if err != nil {
		t.Fatal(err)
	}
	view[0].Owner = "edited"
	view, err = EffectiveView(original, "admin")
	if err != nil || view[0].Owner != "management" {
		t.Fatal("view mutation escaped")
	}
	view, err = EffectiveView(original, "missing")
	if err != nil || len(view) != 0 {
		t.Fatal("filter failed")
	}
}

func TestManagementDependencyChangeRequiresConfirmation(t *testing.T) {
	before := fixture()
	s := cloneConfig(t, before).Services[0]
	s.ID, s.Owner, s.Kind = "time", "clock", NTP
	s.Endpoints = []Endpoint{{UDP, 123, 123}}
	s.Authentication = ProtocolAuthentication
	before.Services = append(before.Services, s)
	after := cloneConfig(t, before)
	after.Services[0].DependsOn = []string{"time"}
	d, err := Preview(before, after)
	if err != nil || !d.RequiresConfirmed || len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Fatal("management dependency change was not flagged", d, err)
	}
}

func TestTransitiveManagementDependencyChangeRequiresConfirmation(t *testing.T) {
	before := fixture()
	clock := cloneConfig(t, before).Services[0]
	clock.ID, clock.Owner, clock.Kind = "time", "clock", NTP
	clock.Endpoints = []Endpoint{{UDP, 123, 123}}
	clock.Authentication = ProtocolAuthentication
	resolver := cloneConfig(t, before).Services[0]
	resolver.ID, resolver.Owner, resolver.Kind = "dns", "resolver", DNS
	resolver.Endpoints = []Endpoint{{UDP, 53, 53}}
	resolver.DependsOn = []string{"time"}
	before.Services[0].DependsOn = []string{"dns"}
	before.Services = append(before.Services, clock, resolver)
	after := cloneConfig(t, before)
	after.Services[1].Endpoints = []Endpoint{{UDP, 124, 124}}
	d, err := Preview(before, after)
	if err != nil || !d.RequiresConfirmed || len(d.Added) != 1 || len(d.Removed) != 1 {
		t.Fatal("transitive dependency change was not flagged", d, err)
	}
}

func TestDecodeBoundary(t *testing.T) {
	data, err := json.Marshal(fixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte{}, data...), data...), []byte(`{"schema_version":1,"unknown":true}`), []byte(strings.Repeat(" ", maxDocument+1)), []byte(`null`), []byte(`{"schema_version":1`)} {
		if _, err = Decode(bad); !errors.Is(err, ErrPolicy) {
			t.Fatalf("accepted malformed boundary: %v", err)
		}
	}
	for _, bad := range []string{
		`{"schema_version":1,"schema_version":1}`,
		`{"schema_version":1,"Schema_Version":1}`,
		`{"Schema_Version":1}`,
		`{"schema_version":1,"services":[{"enabled":false,"enabled":true}]}`,
		`{"schema_version":1,"services":[{"enabled":false,"\u0065nabled":true}]}`,
		`{"schema_version":1,"services":[{"Enabled":true}]}`,
		strings.Repeat("[", 26) + "0" + strings.Repeat("]", 26),
	} {
		if _, err := Decode([]byte(bad)); !errors.Is(err, ErrPolicy) {
			t.Fatal("accepted ambiguous JSON", bad, err)
		}
	}
}

func TestConcurrentCompilation(t *testing.T) {
	c := fixture()
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 10 {
				b, err := Compile(c)
				if err != nil || b.Digest != a.Digest {
					t.Errorf("concurrent compile: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkCompile(b *testing.B) {
	c := fixture()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compile(c); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	data, _ := json.Marshal(fixture())
	f.Add(data)
	f.Add([]byte(`{"schema_version":1,"services":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Decode(data)
		if err != nil {
			return
		}
		a, err := Compile(r.Config)
		if err != nil || a.Revision.Hash != r.Hash {
			t.Fatalf("canonical decode not stable: %v", err)
		}
	})
}
