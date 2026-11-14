package dhcpkea

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/dhcpserver"
)

func fixture() (dhcpserver.Config, []Binding) {
	c := dhcpserver.Config{SchemaVersion: 1, Enabled: true, Scopes: []dhcpserver.Scope{{
		ID: "office", InterfaceID: "lan", Subnet: "198.18.1.0/24", Router: "198.18.1.1",
		Pools:    []dhcpserver.Pool{{First: "198.18.1.10", Last: "198.18.1.40"}},
		Excluded: []string{"198.18.1.20"}, Reservations: []dhcpserver.Reservation{{MAC: "02:00:00:00:00:01", Address: "198.18.1.30"}},
		DNS: []string{"198.18.1.53", "198.18.1.54"}, NTP: []string{"198.18.1.123"}, Domain: "office.example",
		LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000,
	}}}
	return c, []Binding{{Interface: dhcpserver.Binding{InterfaceID: "lan", Role: "lan", Address: netip.MustParsePrefix("198.18.1.1/24")}, Name: "lan0", SubnetID: 17}}
}
func compiled(t *testing.T, c dhcpserver.Config, b []Binding) (Artifact, document) {
	t.Helper()
	a, e := Compile(c, b)
	if e != nil {
		t.Fatal(e)
	}
	var d document
	if e := json.Unmarshal(a.JSON, &d); e != nil {
		t.Fatal(e)
	}
	return a, d
}

func TestCompiledProfileAndGolden(t *testing.T) {
	c, b := fixture()
	a, d := compiled(t, c, b)
	expected, e := os.ReadFile("testdata/kea-2.6.3.json")
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(a.JSON, expected) {
		t.Fatal("fixture changed")
	}
	if !a.Enabled || len(a.Digest) != 64 || len(a.JSON) > MaxArtifactBytes {
		t.Fatal(a)
	}
	s := d.DHCP4
	subnet := s.Subnets[0]
	if !s.Database.Persist || s.Database.Name != LeaseFile || s.Database.MaxRowErrors != 1 || s.Database.LFCInterval != 3600 || s.Sanity.LeaseChecks != "warn" {
		t.Fatal(s.Database, s.Sanity)
	}
	if s.Interfaces.SocketType != "raw" || !s.Interfaces.RequireAll || s.Interfaces.MaxRetries != 0 || !reflect.DeepEqual(s.Interfaces.Names, []string{"lan0"}) {
		t.Fatal(s.Interfaces)
	}
	if s.DDNS.Enabled || s.SendDDNS || s.MultiThreading.Enabled || s.Queue.Enabled || s.ReservationsGlobal || !s.ReservationsInSubnet || !s.ReservationsOutOfPool {
		t.Fatal("unexpected feature")
	}
	if subnet.ID != 17 || subnet.Interface != "lan0" || subnet.ValidLifetime != 3600 || subnet.MinValidLifetime != 3600 || subnet.MaxValidLifetime != 3600 || subnet.Renew != 1800 || subnet.Rebind != 3000 {
		t.Fatal(subnet)
	}
	if !reflect.DeepEqual(subnet.Pools, []pool{{"198.18.1.10 - 198.18.1.19"}, {"198.18.1.21 - 198.18.1.29"}, {"198.18.1.31 - 198.18.1.40"}}) {
		t.Fatal(subnet.Pools)
	}
	if len(s.Classes) != 2 || s.Classes[0].Name != "DROP" || s.Classes[0].Test != "not (pkt4.giaddr == 0.0.0.0) or option[82].exists" {
		t.Fatal(s.Classes)
	}
	if subnet.ClientClass != "andeiva-subnet-17" || s.Classes[1].Name != subnet.ClientClass || s.Classes[1].Test != "pkt.iface == 'lan0'" {
		t.Fatal("unbound subnet classification")
	}
	for _, bad := range []string{"control-socket", "hooks-libraries", "config-control", "dhcp4o6-port", "password", "server-tag"} {
		if bytes.Contains(a.JSON, []byte(bad)) {
			t.Fatal(bad)
		}
	}
	for _, path := range []string{"/usr/", "/etc/", "/tmp/", "https://"} {
		if bytes.Contains(a.JSON, []byte(path)) {
			t.Fatal(path)
		}
	}
}

func TestDisabledHasNoArtifact(t *testing.T) {
	c, b := fixture()
	c.Enabled = false
	a, e := Compile(c, b)
	if e != nil || a.Enabled || a.JSON != nil || a.Digest != "" {
		t.Fatal(a, e)
	}
	c.Scopes[0].Reservations[0].Address = "198.18.1.20"
	if _, e := Compile(c, b); e != ErrInvalid {
		t.Fatal("disabled invalid retention admitted")
	}
	a, e = Compile(dhcpserver.Config{SchemaVersion: 1}, nil)
	if e != nil || a.JSON != nil {
		t.Fatal(a, e)
	}
}

func TestBindingAndConfigurationRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*dhcpserver.Config, *[]Binding){
		"schema": func(c *dhcpserver.Config, _ *[]Binding) { c.SchemaVersion = 2 },
		"wan":    func(_ *dhcpserver.Config, b *[]Binding) { (*b)[0].Interface.Role = "wan" },
		"other-prefix": func(_ *dhcpserver.Config, b *[]Binding) {
			(*b)[0].Interface.Address = netip.MustParsePrefix("198.18.1.1/25")
		},
		"missing":         func(_ *dhcpserver.Config, b *[]Binding) { *b = nil },
		"extra":           func(_ *dhcpserver.Config, b *[]Binding) { *b = append(*b, (*b)[0]) },
		"subnet-zero":     func(_ *dhcpserver.Config, b *[]Binding) { (*b)[0].SubnetID = 0 },
		"subnet-reserved": func(_ *dhcpserver.Config, b *[]Binding) { (*b)[0].SubnetID = ^uint32(0) },
		"ipv6": func(_ *dhcpserver.Config, b *[]Binding) {
			(*b)[0].Interface.Address = netip.MustParsePrefix("2001:db8::1/64")
		},
		"excluded-reservation": func(c *dhcpserver.Config, _ *[]Binding) {
			c.Scopes[0].Excluded = append(c.Scopes[0].Excluded, c.Scopes[0].Reservations[0].Address)
		},
		"domain-injection": func(c *dhcpserver.Config, _ *[]Binding) { c.Scopes[0].Domain = "x\",\"hooks-libraries\":[]" },
		"timer":            func(c *dhcpserver.Config, _ *[]Binding) { c.Scopes[0].RenewSeconds = c.Scopes[0].LeaseSeconds },
	} {
		t.Run(name, func(t *testing.T) {
			c, b := fixture()
			mutate(&c, &b)
			a, e := Compile(c, b)
			if e != ErrInvalid || a.JSON != nil || a.Enabled {
				t.Fatal(a, e)
			}
		})
	}
	for _, name := range []string{"", "*", "lo", ".", "..", "eth0/1", "eth0:1", "eth0@peer", "eth0\n", "-x", "lan'0", strings.Repeat("a", 16)} {
		c, b := fixture()
		b[0].Name = name
		if _, e := Compile(c, b); e != ErrInvalid {
			t.Fatal(name, e)
		}
	}
}

func TestDeterminismOrderingAndNoAliasing(t *testing.T) {
	c, b := fixture()
	s := c.Scopes[0]
	s.ID = "guest"
	s.InterfaceID = "guest"
	s.Subnet = "198.18.2.0/24"
	s.Router = "198.18.2.1"
	s.Pools = []dhcpserver.Pool{{First: "198.18.2.10", Last: "198.18.2.40"}}
	s.Excluded = nil
	s.Reservations = nil
	c.Scopes = append(c.Scopes, s)
	b = append(b, Binding{Interface: dhcpserver.Binding{InterfaceID: "guest", Role: "lan", Address: netip.MustParsePrefix("198.18.2.1/24")}, Name: "lan1", SubnetID: 91})
	before, _ := json.Marshal(c)
	first, e := Compile(c, b)
	if e != nil {
		t.Fatal(e)
	}
	var wire document
	if e := json.Unmarshal(first.JSON, &wire); e != nil {
		t.Fatal(e)
	}
	classes := map[string]string{}
	for _, class := range wire.DHCP4.Classes {
		classes[class.Name] = class.Test
	}
	for _, s := range wire.DHCP4.Subnets {
		if classes[s.ClientClass] != "pkt.iface == '"+s.Interface+"'" {
			t.Fatal("cross-interface selection is not constrained")
		}
	}
	after, _ := json.Marshal(c)
	if !bytes.Equal(before, after) {
		t.Fatal("input mutated")
	}
	slices.Reverse(c.Scopes)
	slices.Reverse(b)
	second, e := Compile(c, b)
	if e != nil || first.Digest != second.Digest || !bytes.Equal(first.JSON, second.JSON) {
		t.Fatal("order changed IDs/document", e)
	}
	c.Scopes[0].DNS[0] = "198.18.1.99"
	if !bytes.Equal(first.JSON, second.JSON) {
		t.Fatal("returned alias")
	}
	for _, change := range []func([]Binding){func(b []Binding) { b[1].SubnetID = b[0].SubnetID }, func(b []Binding) { b[1].Name = b[0].Name }, func(b []Binding) { b[1].Interface.InterfaceID = b[0].Interface.InterfaceID }} {
		bad := append([]Binding(nil), b...)
		change(bad)
		if _, e := Compile(c, bad); e != ErrInvalid {
			t.Fatal("ambiguous mapping")
		}
	}
}

func TestSubtractedPoolsExactlyMatchDeclaredSet(t *testing.T) {
	// A simple per-address oracle checks interval endpoints and every allocation.
	c, b := fixture()
	s := &c.Scopes[0]
	s.Pools = []dhcpserver.Pool{{First: "198.18.1.1", Last: "198.18.1.10"}, {First: "198.18.1.15", Last: "198.18.1.40"}}
	s.Excluded = []string{"198.18.1.1", "198.18.1.10", "198.18.1.16", "198.18.1.40"}
	s.Reservations = []dhcpserver.Reservation{{MAC: "02:00:00:00:00:01", Address: "198.18.1.15"}, {MAC: "02:00:00:00:00:02", Address: "198.18.1.39"}, {MAC: "02:00:00:00:00:03", Address: "198.18.1.60"}}
	_, d := compiled(t, c, b)
	actual := map[string]bool{}
	for _, p := range d.DHCP4.Subnets[0].Pools {
		ends := strings.Split(p.Range, " - ")
		for n := number(ends[0]); n <= number(ends[1]); n++ {
			if actual[address(n)] {
				t.Fatal("duplicate")
			}
			actual[address(n)] = true
		}
	}
	for last := 1; last < 255; last++ {
		a := fmt.Sprintf("198.18.1.%d", last)
		want := last >= 1 && last <= 10 || last >= 15 && last <= 40
		for _, x := range s.Excluded {
			if x == a {
				want = false
			}
		}
		for _, r := range s.Reservations {
			if r.Address == a {
				want = false
			}
		}
		if actual[a] != want {
			t.Fatal(a, want, actual[a])
		}
	}
	slices.Reverse(s.Pools)
	slices.Reverse(s.Reservations)
	slices.Reverse(s.Excluded)
	_, again := compiled(t, c, b)
	if !reflect.DeepEqual(d, again) {
		t.Fatal("set ordering changed output")
	}
	s.Pools = []dhcpserver.Pool{{First: "198.18.1.10", Last: "198.18.1.10"}}
	_, empty := compiled(t, c, b)
	if len(empty.DHCP4.Subnets[0].Pools) != 0 {
		t.Fatal("invented dynamic allocation")
	}
}

func BenchmarkCompile(b *testing.B) {
	c, bindings := fixture()
	b.ReportAllocs()
	for b.Loop() {
		if _, e := Compile(c, bindings); e != nil {
			b.Fatal(e)
		}
	}
}

func denseFixture(count int) (dhcpserver.Config, []Binding) {
	c := dhcpserver.Config{SchemaVersion: 1, Enabled: true}
	var bindings []Binding
	for i := 0; i < count; i++ {
		ip := func(n int) string { return netip.AddrFrom4([4]byte{10, byte(i), byte(n >> 8), byte(n)}).String() }
		id := fmt.Sprintf("scope%d", i)
		s := dhcpserver.Scope{ID: id, InterfaceID: id, Subnet: ip(0) + "/16", Router: ip(1), Pools: []dhcpserver.Pool{{First: ip(10), Last: ip(1033)}}, LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000}
		for j := 0; j < 256; j++ {
			s.Excluded = append(s.Excluded, ip(10+4*j))
			s.Reservations = append(s.Reservations, dhcpserver.Reservation{MAC: fmt.Sprintf("02:00:00:%02x:00:%02x", i, j), Address: ip(12 + 4*j)})
		}
		c.Scopes = append(c.Scopes, s)
		bindings = append(bindings, Binding{Interface: dhcpserver.Binding{InterfaceID: id, Role: "lan", Address: netip.MustParsePrefix(ip(1) + "/16")}, Name: fmt.Sprintf("lan%d", i), SubnetID: uint32(i + 1)})
	}
	return c, bindings
}

func TestInputAndExpansionBounds(t *testing.T) {
	accepted := 0
	for count := 1; count <= 32; count++ {
		c, b := denseFixture(count)
		raw, e := json.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		a, e := Compile(c, b)
		if len(raw) > dhcpserver.MaxConfigBytes {
			if e != ErrInvalid || a.JSON != nil {
				t.Fatal("oversized configuration admitted")
			}
			break
		}
		if e != nil || len(a.JSON) > MaxArtifactBytes {
			t.Fatal(count, e, len(a.JSON))
		}
		accepted = count
		var d document
		if e := json.Unmarshal(a.JSON, &d); e != nil {
			t.Fatal(e)
		}
		for _, s := range d.DHCP4.Subnets {
			if len(s.Pools) > 32+256+256 || len(s.Reservations) != 256 {
				t.Fatal("expansion", len(s.Pools))
			}
		}
		t.Logf("scopes=%d input=%d artifact=%d", count, len(raw), len(a.JSON))
	}
	if accepted == 0 {
		t.Fatal("no dense configuration tested")
	}
	c, b := fixture()
	c.Scopes[0].Subnet = "10.0.0.0/15"
	c.Scopes[0].Router = "10.0.0.1"
	c.Scopes[0].Pools = []dhcpserver.Pool{{First: "10.0.0.2", Last: "10.1.0.1"}}
	c.Scopes[0].Excluded = nil
	c.Scopes[0].Reservations = nil
	b[0].Interface.Address = netip.MustParsePrefix("10.0.0.1/15")
	_, d := compiled(t, c, b)
	if len(d.DHCP4.Subnets[0].Pools) != 1 {
		t.Fatal("capacity enumerated")
	}
	c.Scopes[0].Pools[0].Last = "10.1.0.2"
	if _, e := Compile(c, b); e != ErrInvalid {
		t.Fatal("capacity limit")
	}
}

func TestDNSPriorityAndOperationalBindingNotJSON(t *testing.T) {
	c, b := fixture()
	first, _ := compiled(t, c, b)
	slices.Reverse(c.Scopes[0].DNS)
	next, d := compiled(t, c, b)
	if first.Digest == next.Digest || d.DHCP4.Subnets[0].Options[1].Data != "198.18.1.54, 198.18.1.53" {
		t.Fatal("DNS priority lost")
	}
	raw, e := json.Marshal(b[0])
	if e != nil || string(raw) != "{}" {
		t.Fatal(string(raw), e)
	}
}

func BenchmarkCompileDense(b *testing.B) {
	c, bindings := denseFixture(2)
	b.ReportAllocs()
	for b.Loop() {
		if _, e := Compile(c, bindings); e != nil {
			b.Fatal(e)
		}
	}
}
