package networkplan

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/networkinventory"
)

func sample() Config {
	return Config{
		SchemaVersion: SchemaVersion, IPv6Forwarding: "deny",
		Zones: []Zone{{ID: "outside", Kind: WAN}, {ID: "inside", Kind: LAN}},
		Interfaces: []Interface{
			{ID: "uplink", Binding: Binding{Name: "port0", HardwareAddress: "02:00:00:00:00:01"}, Role: WAN, Zone: "outside", IPv4: IPv4{Mode: "dhcp"}},
			{ID: "users", Binding: Binding{Name: "port1", HardwareAddress: "02:00:00:00:00:02"}, Role: LAN, Zone: "inside", IPv4: IPv4{Mode: "static", Address: "192.0.2.10/24"}},
		},
		DefaultRoute: DefaultRoute{InterfaceID: "uplink", Metric: 100},
		DNS:          DNS{Mode: "dhcp", InterfaceID: "uplink"},
	}
}

func TestCanonicalPreservesHostAndCallerInput(t *testing.T) {
	input := sample()
	before, _ := json.Marshal(input)
	first, err := Canonical(input)
	if err != nil || len(first.Hash) != 64 {
		t.Fatal(first, err)
	}
	if first.Config.Interfaces[1].IPv4.Address != "192.0.2.10/24" {
		t.Fatal("interface address was masked to the network")
	}
	after, _ := json.Marshal(input)
	if string(before) != string(after) {
		t.Fatal("canonicalization changed caller-owned data")
	}
	input.Interfaces[0], input.Interfaces[1] = input.Interfaces[1], input.Interfaces[0]
	input.Zones[0], input.Zones[1] = input.Zones[1], input.Zones[0]
	second, err := Canonical(input)
	if err != nil || first.Hash != second.Hash {
		t.Fatal("identity collection order changed revision", err)
	}
	first.Config.Interfaces[0].ID = "changed"
	if input.Interfaces[1].ID != "uplink" {
		t.Fatal("revision aliases caller interface slice")
	}
}

func TestCanonicalRejectsAmbiguousOrUnsafePlans(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{"version", func(c *Config) { c.SchemaVersion++ }},
		{"ipv6-not-explicit", func(c *Config) { c.IPv6Forwarding = "" }},
		{"ipv6-bypass", func(c *Config) { c.IPv6Forwarding = "allow" }},
		{"single-interface", func(c *Config) { c.Interfaces = c.Interfaces[:1] }},
		{"unknown-zone", func(c *Config) { c.Interfaces[1].Zone = "missing" }},
		{"role-mismatch", func(c *Config) { c.Interfaces[1].Zone = "outside" }},
		{"duplicate-zone", func(c *Config) { c.Zones[1].ID = c.Zones[0].ID }},
		{"duplicate-id", func(c *Config) { c.Interfaces[1].ID = c.Interfaces[0].ID }},
		{"duplicate-device", func(c *Config) { c.Interfaces[1].Binding = c.Interfaces[0].Binding }},
		{"duplicate-mac", func(c *Config) { c.Interfaces[1].Binding.HardwareAddress = c.Interfaces[0].Binding.HardwareAddress }},
		{"option-in-name", func(c *Config) { c.Interfaces[0].Binding.Name = "--config" }},
		{"shell-in-name", func(c *Config) { c.Interfaces[0].Binding.Name = "eth0;id" }},
		{"long-name", func(c *Config) { c.Interfaces[0].Binding.Name = strings.Repeat("a", 16) }},
		{"loopback", func(c *Config) { c.Interfaces[0].Binding.Name = "lo" }},
		{"multicast-mac", func(c *Config) { c.Interfaces[0].Binding.HardwareAddress = "01:00:00:00:00:01" }},
		{"no-mac", func(c *Config) { c.Interfaces[0].Binding.HardwareAddress = "00:00:00:00:00:00" }},
		{"lan-dhcp", func(c *Config) { c.Interfaces[1].IPv4 = IPv4{Mode: "dhcp"} }},
		{"dhcp-with-address", func(c *Config) { c.Interfaces[0].IPv4.Address = "198.51.100.2/24" }},
		{"lan-with-gateway", func(c *Config) { c.Interfaces[1].IPv4.Gateway = "192.0.2.1" }},
		{"host-network-address", func(c *Config) { c.Interfaces[1].IPv4.Address = "192.0.2.0/24" }},
		{"host-broadcast-address", func(c *Config) { c.Interfaces[1].IPv4.Address = "192.0.2.255/24" }},
		{"ipv6-address", func(c *Config) { c.Interfaces[1].IPv4.Address = "2001:db8::2/64" }},
		{"loopback-address", func(c *Config) { c.Interfaces[1].IPv4.Address = "127.0.0.2/24" }},
		{"multicast-address", func(c *Config) { c.Interfaces[1].IPv4.Address = "224.0.0.2/24" }},
		{"default-through-lan", func(c *Config) { c.DefaultRoute.InterfaceID = "users" }},
		{"default-metric", func(c *Config) { c.DefaultRoute.Metric = 0 }},
		{"dhcp-dns-on-lan", func(c *Config) { c.DNS.InterfaceID = "users" }},
		{"dns-mixed-modes", func(c *Config) { c.DNS.Servers = []string{"192.0.2.1"} }},
		{"dns-repeated", func(c *Config) { c.DNS = DNS{Mode: "static", Servers: []string{"198.51.100.1", "198.51.100.1"}} }},
		{"dns-multicast", func(c *Config) { c.DNS = DNS{Mode: "static", Servers: []string{"224.0.0.1"}} }},
		{"dns-loopback", func(c *Config) { c.DNS = DNS{Mode: "static", Servers: []string{"127.0.0.1"}} }},
		{"dns-ipv6", func(c *Config) { c.DNS = DNS{Mode: "static", Servers: []string{"2001:db8::1"}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := sample()
			tc.edit(&config)
			revision, err := Canonical(config)
			var detail *Invalid
			if !errors.Is(err, ErrInvalid) || !errors.As(err, &detail) || revision.Hash != "" || detail.Field == "" {
				t.Fatal("expected a stable rejection without partial revision", revision, err)
			}
		})
	}
}

func TestStaticWANOverlapAndGateway(t *testing.T) {
	for _, tc := range []struct {
		address, gateway string
		valid            bool
	}{
		{"198.51.100.2/24", "198.51.100.1", true},
		{"198.51.100.0/31", "198.51.100.1", true},
		{"198.51.100.2/24", "198.51.100.2", false},
		{"198.51.100.2/24", "198.51.100.0", false},
		{"198.51.100.2/24", "198.51.100.255", false},
		{"198.51.100.2/24", "203.0.113.1", false},
		{"198.51.100.2/24", "", false},
		{"192.0.2.129/25", "192.0.2.130", false},
	} {
		t.Run(tc.address+"-"+tc.gateway, func(t *testing.T) {
			config := sample()
			config.Interfaces[0].IPv4 = IPv4{Mode: "static", Address: tc.address, Gateway: tc.gateway}
			config.DNS = DNS{Mode: "static", Servers: []string{"198.51.100.53"}}
			_, err := Canonical(config)
			if (err == nil) != tc.valid {
				t.Fatal("unexpected static plan result", err)
			}
		})
	}
}

func observation(c Config) networkinventory.Snapshot {
	result := networkinventory.Snapshot{SchemaVersion: networkinventory.SchemaVersion}
	for i, iface := range c.Interfaces {
		result.Interfaces = append(result.Interfaces, networkinventory.Interface{
			Index: i + 2, Name: iface.Binding.Name, HardwareAddress: iface.Binding.HardwareAddress, Kind: networkinventory.DeviceBacked,
		})
	}
	return result
}

func TestBindingRequiresExactCurrentDevice(t *testing.T) {
	config := sample()
	revision, err := Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	observed := observation(config)
	report, err := Bind(revision, observed)
	if err != nil || report.Revision != revision.Hash || len(report.InventoryHash) != 64 || !reflect.DeepEqual(report.RequiredDHCP, []string{"uplink"}) {
		t.Fatal(report, err)
	}
	// An observed address is not evidence of a DHCP lease or an available gateway.
	observed.Interfaces[0].Addresses = []networkinventory.Address{{IP: netip.MustParseAddr("198.51.100.2")}}
	report, err = Bind(revision, observed)
	if err != nil || len(report.RequiredDHCP) != 1 {
		t.Fatal("observed address silently became a verified DHCP lease", err)
	}
	observed.Interfaces[0].Index = 42
	reindexed, err := Bind(revision, observed)
	if err != nil || reindexed.Interfaces[0].Index != 42 || reindexed.Revision != revision.Hash {
		t.Fatal("kernel reindexing after boot changed persistent configuration", err)
	}
	for _, edit := range []func(*networkinventory.Snapshot){
		func(s *networkinventory.Snapshot) { s.SchemaVersion++ },
		func(s *networkinventory.Snapshot) { s.Interfaces = s.Interfaces[:1] },
		func(s *networkinventory.Snapshot) { s.Interfaces[0].Index++ },
		func(s *networkinventory.Snapshot) { s.Interfaces[0].Name = "replaced" },
		func(s *networkinventory.Snapshot) { s.Interfaces[0].HardwareAddress = "02:00:00:00:00:99" },
		func(s *networkinventory.Snapshot) { s.Interfaces[0].PointToPoint = true },
		func(s *networkinventory.Snapshot) { s.Interfaces[0].Kind = networkinventory.Loopback },
	} {
		input := observation(config)
		edit(&input)
		report, err := Bind(revision, input)
		if !errors.Is(err, ErrInvalid) || report.Revision != "" {
			t.Fatal("stale/invalid observation produced an applicable plan", report, err)
		}
	}
	revision.Hash = strings.Repeat("0", 64)
	if _, err := Bind(revision, observation(config)); !errors.Is(err, ErrInvalid) {
		t.Fatal("forged revision accepted")
	}
}

func BenchmarkCanonical(b *testing.B) {
	config := sample()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Canonical(config); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCanonicalRejectsOversizedFieldsBeforeParsing(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"mac":        func(c *Config) { c.Interfaces[0].Binding.HardwareAddress = strings.Repeat("a", 65) },
		"prefix":     func(c *Config) { c.Interfaces[1].IPv4.Address = strings.Repeat("1", 19) },
		"gateway":    func(c *Config) { c.Interfaces[0].IPv4.Gateway = strings.Repeat("1", 16) },
		"dns_count":  func(c *Config) { c.DNS.Servers = make([]string, 5) },
		"dns_length": func(c *Config) { c.DNS = DNS{Mode: "static", Servers: []string{strings.Repeat("1", 16)}} },
	} {
		t.Run(name, func(t *testing.T) {
			c := sample()
			change(&c)
			if _, err := Canonical(c); err == nil {
				t.Fatal("accepted oversized input")
			}
		})
	}
}
