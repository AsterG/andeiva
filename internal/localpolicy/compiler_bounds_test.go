package localpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// Each permission must retain every boundary in both address families. Checking
// tokens across a whole batch can miss one rule with a missing predicate.
func TestEveryRuleRetainsItsScope(t *testing.T) {
	c := fixture()
	s := &c.Services[0]
	s.Kind = DNS
	s.Endpoints = []Endpoint{{TCP, 443, 443}, {UDP, 5300, 5302}}
	s.Bindings = append(s.Bindings, Binding{Interface: "lan0", Zone: LAN, LocalAddress: "2001:db8:1::1", Sources: []string{"2001:db8:1::/64"}})
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	var batch struct {
		Commands []struct {
			Add struct {
				Rule *struct {
					Family, Table, Chain, Comment string
					Expr                          json.RawMessage
				} `json:"rule"`
			} `json:"add"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(a.Create, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Commands) != 6 || len(a.Rules) != 4 {
		t.Fatal("expected two declarations and four permissions")
	}
	seen := make(map[string]bool)
	for i, command := range batch.Commands[2:] {
		rule := command.Add.Rule
		r := a.Rules[i]
		if rule == nil || rule.Family != "inet" || rule.Table != "andeiva_local_poc" || rule.Chain != "input" || rule.Comment != "andeiva-local:"+r.ID {
			t.Fatalf("rule %d escaped its table, chain or identity", i)
		}
		ip, family, local, source, bits := "ip", "ipv4", "192.0.2.1", "192.0.2.10", 32
		if r.LocalAddress == "2001:db8:1::1" {
			ip, family, local, source, bits = "ip6", "ipv6", "2001:db8:1::1", "2001:db8:1::", 64
		} else if r.LocalAddress != local {
			t.Fatal("unexpected destination")
		}
		protocol, ports := "tcp", "443"
		if r.Endpoint.Protocol == UDP {
			protocol, ports = "udp", `{"range":[5300,5302]}`
		} else if r.Endpoint.Protocol != TCP {
			t.Fatal("unexpected protocol")
		}
		key := family + "/" + protocol
		if seen[key] {
			t.Fatal("duplicate permission", key)
		}
		seen[key] = true
		want := fmt.Sprintf(`[
			{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":%q}},
			{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"lan0"}},
			{"match":{"op":"==","left":{"payload":{"protocol":%q,"field":"daddr"}},"right":%q}},
			{"match":{"op":"==","left":{"payload":{"protocol":%q,"field":"saddr"}},"right":{"prefix":{"addr":%q,"len":%d}}}},
			{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":%q}},
			{"match":{"op":"==","left":{"payload":{"protocol":%q,"field":"dport"}},"right":%s}},
			{"counter":null},{"accept":null}
		]`, family, ip, local, ip, source, bits, protocol, protocol, ports)
		var gotExpr, wantExpr any
		if err := json.Unmarshal(rule.Expr, &gotExpr); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(want), &wantExpr); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotExpr, wantExpr) {
			t.Fatalf("permission %s changed its scope or verdict: %s", key, rule.Expr)
		}
	}
}

func capacityFixture() Config {
	c := fixture()
	base := c.Services[0]
	c.Services = nil
	for i := range MaxServices {
		s := base
		s.ID = fmt.Sprintf("service-%02d", i)
		port := uint16(10000 + i*16)
		s.Endpoints = []Endpoint{{TCP, port, port}}
		binding := base.Bindings[0]
		binding.Sources = nil
		for j := range 64 {
			binding.Sources = append(binding.Sources, fmt.Sprintf("192.0.2.%d/32", j+1))
		}
		s.Bindings = []Binding{binding}
		c.Services = append(c.Services, s)
	}
	return c
}

func TestCapacityBoundaries(t *testing.T) {
	t.Run("rules", func(t *testing.T) {
		c := capacityFixture()
		a, err := Compile(c)
		if err != nil || len(a.Rules) != MaxRules {
			t.Fatalf("4096 rules must compile: count=%d error=%v", len(a.Rules), err)
		}
		// 63*64 + 5*13 = 4097, with only 68 listeners and 64 services.
		last := &c.Services[len(c.Services)-1]
		port := last.Endpoints[0].FirstPort
		last.Endpoints = nil
		for offset := range uint16(5) {
			last.Endpoints = append(last.Endpoints, Endpoint{TCP, port + offset, port + offset})
		}
		last.Bindings[0].Sources = last.Bindings[0].Sources[:13]
		if _, err := Compile(c); !errors.Is(err, ErrPolicy) || err.Error() != "local_policy_invalid: rule_capacity" {
			t.Fatalf("4097 rules must fail the rule limit: %v", err)
		}
	})
	t.Run("services", func(t *testing.T) {
		c := capacityFixture()
		c.Services = append(c.Services, c.Services[0])
		c.Services[len(c.Services)-1].ID = "extra-service"
		if _, err := Canonical(c); !errors.Is(err, ErrPolicy) || err.Error() != "local_policy_invalid: capacity" {
			t.Fatalf("65 services must fail before expansion: %v", err)
		}
	})
	t.Run("listeners", func(t *testing.T) {
		c := fixture()
		c.Services[0].Endpoints = []Endpoint{{TCP, 1, 4096}}
		if _, err := Compile(c); err != nil {
			t.Fatal("4096 listener declarations must compile", err)
		}
		c.Services[0].Endpoints[0].LastPort = 4097
		if _, err := Compile(c); !errors.Is(err, ErrPolicy) || err.Error() != "local_policy_invalid: rule_capacity" {
			t.Fatalf("4097 listeners must fail the expansion limit: %v", err)
		}
	})
}

func BenchmarkCompileCapacity(b *testing.B) {
	c := capacityFixture()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compile(c); err != nil {
			b.Fatal(err)
		}
	}
}
