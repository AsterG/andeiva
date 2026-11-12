package networkplan

import (
	"errors"
	"strings"
	"testing"
)

func TestValidationIdentifiesExactField(t *testing.T) {
	cases := []struct {
		name, code, field string
		edit              func(*Config)
	}{
		{"schema", "SCHEMA", "schema_version", func(c *Config) { c.SchemaVersion++ }},
		{"ipv6", "SCHEMA", "ipv6_forwarding", func(c *Config) { c.IPv6Forwarding = "allow" }},
		{"interfaces-min", "LIMIT", "interfaces", func(c *Config) { c.Interfaces = c.Interfaces[:1] }},
		{"interfaces-max", "LIMIT", "interfaces", func(c *Config) { c.Interfaces = make([]Interface, MaxInterfaces+1) }},
		{"zones-min", "LIMIT", "zones", func(c *Config) { c.Zones = c.Zones[:1] }},
		{"zones-max", "LIMIT", "zones", func(c *Config) { c.Zones = make([]Zone, MaxZones+1) }},
		{"dns-max", "LIMIT", "dns.servers", func(c *Config) { c.DNS.Servers = make([]string, 5) }},
		{"mac-length", "LIMIT", "interfaces[0].binding.hardware_address", func(c *Config) { c.Interfaces[0].Binding.HardwareAddress = strings.Repeat("x", 65) }},
		{"address-length", "LIMIT", "interfaces[0].ipv4.address", func(c *Config) { c.Interfaces[0].IPv4.Address = strings.Repeat("x", 19) }},
		{"gateway-length", "LIMIT", "interfaces[0].ipv4.gateway", func(c *Config) { c.Interfaces[0].IPv4.Gateway = strings.Repeat("x", 16) }},
		{"deterministic-first", "SCHEMA", "schema_version", func(c *Config) { c.SchemaVersion++; c.IPv6Forwarding = "allow"; c.Interfaces = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := sample()
			tc.edit(&c)
			_, err := Canonical(c)
			var invalid *Invalid
			if !errors.As(err, &invalid) || invalid.Code != "ANDEIVA_NETWORK_"+tc.code || invalid.Field != tc.field {
				t.Fatalf("unexpected validation: %#v (%v)", invalid, err)
			}
		})
	}
}
