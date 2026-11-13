package dhcpserver

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func fixture() (Config, []Binding) {
	return Config{SchemaVersion: 1, Enabled: true, Scopes: []Scope{{
		ID: "office", InterfaceID: "lan", Subnet: "192.0.2.0/24", Router: "192.0.2.1",
		Pools: []Pool{{"192.0.2.10", "192.0.2.100"}}, Excluded: []string{"192.0.2.20"},
		Reservations: []Reservation{{"02:00:00:00:00:01", "192.0.2.30"}},
		DNS:          []string{"192.0.2.1"}, NTP: []string{"192.0.2.1"}, Domain: "office.example",
		LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000,
	}}}, []Binding{{"lan", "lan", netip.MustParsePrefix("192.0.2.1/24")}}
}

func TestScopeValidation(t *testing.T) {
	c, bindings := fixture()
	if err := c.Validate(bindings); err != nil {
		t.Fatal(err)
	}
	// Disabling retains declared configuration, without granting runtime authority.
	c.Enabled = false
	if err := c.Validate(bindings); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"version":              func(c *Config) { c.SchemaVersion = 2 },
		"empty":                func(c *Config) { c.Scopes = nil },
		"unknown-interface":    func(c *Config) { c.Scopes[0].InterfaceID = "wan" },
		"noncanonical-subnet":  func(c *Config) { c.Scopes[0].Subnet = "192.0.2.1/24" },
		"other-router":         func(c *Config) { c.Scopes[0].Router = "192.0.2.2" },
		"network-address":      func(c *Config) { c.Scopes[0].Pools[0].First = "192.0.2.0" },
		"broadcast":            func(c *Config) { c.Scopes[0].Pools[0].Last = "192.0.2.255" },
		"outside-subnet":       func(c *Config) { c.Scopes[0].Pools[0].Last = "192.0.3.1" },
		"reversed":             func(c *Config) { c.Scopes[0].Pools[0] = Pool{"192.0.2.50", "192.0.2.10"} },
		"overlap-pool":         func(c *Config) { c.Scopes[0].Pools = append(c.Scopes[0].Pools, Pool{"192.0.2.99", "192.0.2.110"}) },
		"router-in-pool":       func(c *Config) { c.Scopes[0].Pools[0].First = "192.0.2.1" },
		"excluded-reservation": func(c *Config) { c.Scopes[0].Reservations[0].Address = "192.0.2.20" },
		"router-reservation":   func(c *Config) { c.Scopes[0].Reservations[0].Address = "192.0.2.1" },
		"multicast-mac":        func(c *Config) { c.Scopes[0].Reservations[0].MAC = "01:00:00:00:00:01" },
		"zero-mac":             func(c *Config) { c.Scopes[0].Reservations[0].MAC = "00:00:00:00:00:00" },
		"duplicate-mac": func(c *Config) {
			c.Scopes[0].Reservations = append(c.Scopes[0].Reservations, c.Scopes[0].Reservations[0])
		},
		"duplicate-exclusion": func(c *Config) { c.Scopes[0].Excluded = append(c.Scopes[0].Excluded, c.Scopes[0].Excluded[0]) },
		"lease-infinite":      func(c *Config) { c.Scopes[0].LeaseSeconds = ^uint32(0) },
		"renew-after-rebind":  func(c *Config) { c.Scopes[0].RenewSeconds = 3001 },
		"duplicate-dns":       func(c *Config) { c.Scopes[0].DNS = []string{"192.0.2.1", "192.0.2.1"} },
		"dns-loopback":        func(c *Config) { c.Scopes[0].DNS = []string{"127.0.0.1"} },
		"domain-injection":    func(c *Config) { c.Scopes[0].Domain = "office\ninvalid" },
		"scope-alias":         func(c *Config) { c.Scopes = append(c.Scopes, c.Scopes[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			c, bindings := fixture()
			change(&c)
			if err := c.Validate(bindings); err != ErrInvalid {
				t.Fatalf("invalid scope accepted: %v", err)
			}
		})
	}
	for _, bindings := range [][]Binding{nil, {{"lan", "wan", netip.MustParsePrefix("192.0.2.1/24")}}, {{"lan", "lan", netip.MustParsePrefix("192.0.2.1/25")}}, {bindings[0], bindings[0]}} {
		c, _ := fixture()
		if c.Validate(bindings) != ErrInvalid {
			t.Fatal("untrusted or ambiguous binding accepted")
		}
	}
}

func TestDecodeStrictBoundaries(t *testing.T) {
	c, bindings := fixture()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil || decoded.Validate(bindings) != nil {
		t.Fatal("roundtrip", err)
	}
	for _, bad := range []string{
		string(raw) + " {}", strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(string(raw), `"schema_version":1`, `"Schema_Version":1`, 1),
		strings.Replace(string(raw), `"enabled":true`, `"enabled":true,"command":"anything"`, 1),
		strings.Repeat(" ", MaxConfigBytes+1), "", "null",
	} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatal("ambiguous input was decoded")
		}
	}
}

func BenchmarkValidateScope(b *testing.B) {
	c, bindings := fixture()
	b.ReportAllocs()
	for b.Loop() {
		if err := c.Validate(bindings); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCapacityAndNonOctetBroadcast(t *testing.T) {
	c, bindings := fixture()
	c.Scopes[0].Subnet = "192.0.2.0/25"
	bindings[0].Address = netip.MustParsePrefix("192.0.2.1/25")
	c.Scopes[0].Pools[0].Last = "192.0.2.127"
	if c.Validate(bindings) != ErrInvalid {
		t.Fatal("non-octet broadcast accepted")
	}
	c, bindings = fixture()
	c.Scopes[0].Subnet = "10.0.0.0/8"
	c.Scopes[0].Router = "10.0.0.1"
	c.Scopes[0].Pools = []Pool{{"10.0.0.2", "10.255.255.254"}}
	c.Scopes[0].Excluded, c.Scopes[0].Reservations = nil, nil
	bindings[0].Address = netip.MustParsePrefix("10.0.0.1/8")
	if c.Validate(bindings) != ErrInvalid {
		t.Fatal("unbounded lease capacity accepted")
	}
}
