package dhcpserver

import (
	"encoding/json"
	"fmt"
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

func TestAddressCapacityBoundary(t *testing.T) {
	for _, split := range []bool{false, true} {
		for _, extra := range []bool{false, true} {
			t.Run(fmt.Sprintf("split=%t/extra=%t", split, extra), func(t *testing.T) {
				c, bindings := fixture()
				s := &c.Scopes[0]
				s.Subnet, s.Router = "10.0.0.0/15", "10.0.0.1"
				// Inclusive endpoints span exactly 65,536 addresses.
				s.Pools = []Pool{{"10.0.0.2", "10.1.0.1"}}
				s.Excluded, s.Reservations = nil, nil
				s.DNS, s.NTP = []string{s.Router}, nil
				bindings[0].Address = netip.MustParsePrefix("10.0.0.1/15")
				if split {
					// The same limit applies across scopes, not to each separately.
					s.Subnet = "10.0.0.0/16"
					s.Pools = []Pool{{"10.0.0.2", "10.0.128.1"}}
					bindings[0].Address = netip.MustParsePrefix("10.0.0.1/16")
					other := *s
					other.ID, other.InterfaceID = "branch", "lan2"
					other.Subnet, other.Router = "10.1.0.0/16", "10.1.0.1"
					other.Pools = []Pool{{"10.1.0.2", "10.1.128.1"}}
					other.DNS = []string{other.Router}
					c.Scopes = append(c.Scopes, other)
					bindings = append(bindings, Binding{"lan2", "lan", netip.MustParsePrefix("10.1.0.1/16")})
				}
				if extra {
					last := &c.Scopes[len(c.Scopes)-1].Pools[0].Last
					*last = netip.MustParseAddr(*last).Next().String()
				}
				var want error
				if extra {
					want = ErrInvalid
				}
				if err := c.Validate(bindings); err != want {
					t.Fatalf("capacity validation: got %v, want %v", err, want)
				}
			})
		}
	}
}

func TestScopeCountBoundary(t *testing.T) {
	for _, count := range []int{32, 33} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c, _ := fixture()
			template := c.Scopes[0]
			c.Scopes = nil
			var bindings []Binding
			for i := 0; i < count; i++ {
				s := template
				s.ID, s.InterfaceID = fmt.Sprintf("scope-%d", i), fmt.Sprintf("lan-%d", i)
				s.Subnet, s.Router = fmt.Sprintf("10.0.%d.0/24", i), fmt.Sprintf("10.0.%d.1", i)
				s.Pools = []Pool{{fmt.Sprintf("10.0.%d.10", i), fmt.Sprintf("10.0.%d.100", i)}}
				s.Excluded, s.Reservations = nil, nil
				s.DNS, s.NTP = []string{s.Router}, nil
				b := Binding{s.InterfaceID, "lan", netip.MustParsePrefix(s.Router + "/24")}
				if err := (Config{SchemaVersion: 1, Enabled: true, Scopes: []Scope{s}}).Validate([]Binding{b}); err != nil {
					t.Fatalf("scope %d is not independently valid: %v", i, err)
				}
				c.Scopes, bindings = append(c.Scopes, s), append(bindings, b)
			}
			var want error
			if count == 33 {
				want = ErrInvalid
			}
			if err := c.Validate(bindings); err != want {
				t.Fatalf("scope count: got %v, want %v", err, want)
			}
		})
	}
}

func TestLeaseTimerStrictOrdering(t *testing.T) {
	for _, tc := range []struct {
		name          string
		renew, rebind uint32
		want          error
	}{
		{"strictly-increasing", 58, 59, nil},
		{"T1-equals-T2", 59, 59, ErrInvalid},
		{"T2-equals-lease", 58, 60, ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, bindings := fixture()
			c.Scopes[0].LeaseSeconds = 60
			c.Scopes[0].RenewSeconds, c.Scopes[0].RebindSeconds = tc.renew, tc.rebind
			if err := c.Validate(bindings); err != tc.want {
				t.Fatalf("timer ordering: got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestOverlappingSubnetsAcrossDistinctInterfaces(t *testing.T) {
	for _, thirdOctet := range []int{2, 3} {
		t.Run(fmt.Sprintf("192.0.%d.128/25", thirdOctet), func(t *testing.T) {
			c, bindings := fixture()
			other := c.Scopes[0]
			other.ID, other.InterfaceID = "branch", "lan2"
			other.Subnet, other.Router = fmt.Sprintf("192.0.%d.128/25", thirdOctet), fmt.Sprintf("192.0.%d.129", thirdOctet)
			other.Pools = []Pool{{fmt.Sprintf("192.0.%d.140", thirdOctet), fmt.Sprintf("192.0.%d.200", thirdOctet)}}
			other.Excluded, other.Reservations = nil, nil
			other.DNS, other.NTP = []string{other.Router}, nil
			binding := Binding{"lan2", "lan", netip.MustParsePrefix(other.Router + "/25")}
			if err := (Config{SchemaVersion: 1, Enabled: true, Scopes: []Scope{other}}).Validate([]Binding{binding}); err != nil {
				t.Fatal("second scope is not independently valid", err)
			}
			c.Scopes, bindings = append(c.Scopes, other), append(bindings, binding)
			var want error
			if thirdOctet == 2 {
				want = ErrInvalid
			}
			if err := c.Validate(bindings); err != want {
				t.Fatalf("cross-interface overlap: got %v, want %v", err, want)
			}
		})
	}
}

func TestReservationOutsideDynamicPool(t *testing.T) {
	c, bindings := fixture()
	c.Scopes[0].Reservations[0].Address = "192.0.2.200"
	if err := c.Validate(bindings); err != nil {
		t.Fatal("usable reservation outside the dynamic pool was rejected", err)
	}
	c.Scopes[0].Reservations[0].Address = "192.0.3.200"
	if err := c.Validate(bindings); err != ErrInvalid {
		t.Fatal("reservation outside the subnet was accepted", err)
	}
}
