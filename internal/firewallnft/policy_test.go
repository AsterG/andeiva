package firewallnft

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func testConfig() configpoc.Config {
	c := DefaultConfig()
	c.Rules = []configpoc.Rule{{ID: "service", Action: "allow", Match: &configpoc.Match{Source: "198.18.0.0/30", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 30000, To: 40000}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}
	return c
}
func observed(t *testing.T, c configpoc.Config) []byte {
	t.Helper()
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(object{"nftables": policyObjects(a.Revision)})
	return data
}
func TestCompilerReadback(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		c := testConfig()
		c.Rules[0].Match.Protocol = protocol
		for _, action := range []string{"allow", "deny"} {
			c.Rules[0].Action = action
			a, err := Compile(c)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := Compile(c)
			if !bytes.Equal(a.Batch, b.Batch) || a.Digest != b.Digest || len(a.Digest) != 64 {
				t.Fatal("unstable compile")
			}
			if bytes.Contains(a.Batch, []byte("flush")) || bytes.Count(a.Batch, []byte(`"delete"`)) != 1 || bytes.Contains(a.Create, []byte(`"delete"`)) {
				t.Fatal("unbounded write")
			}
			obs, err := InspectObservation(observed(t, c))
			if err != nil || obs.Revision.Hash != a.Revision.Hash || len(obs.Rules) != 1 || obs.Rules[0].ID != "service" {
				t.Fatalf("readback: %v", err)
			}
		}
	}
	if _, err := DecodeObservation(observed(t, DefaultConfig())); err != nil {
		t.Fatal(err)
	}
}
func TestCompilerStrictBoundaries(t *testing.T) {
	for _, mutate := range []func(*configpoc.Config){
		func(c *configpoc.Config) { c.SchemaVersion = 1 },
		func(c *configpoc.Config) { c.DefaultAction = "allow" },
		func(c *configpoc.Config) { c.Rules[0].Match = nil },
		func(c *configpoc.Config) { c.Rules[0].Match.Source = "198.18.0.2/30" },
		func(c *configpoc.Config) { c.Rules[0].Match.Destination = "::/0" },
		func(c *configpoc.Config) { c.Rules[0].Match.Protocol = "icmp" },
		func(c *configpoc.Config) { c.Rules[0].Match.SourcePorts.From = 0 },
		func(c *configpoc.Config) { c.Rules[0].Match.DestinationPorts.To = 1 },
		func(c *configpoc.Config) { c.Rules[0].ID = "x;flush ruleset" },
		func(c *configpoc.Config) { c.Rules = append(c.Rules, c.Rules[0]) },
	} {
		c := testConfig()
		mutate(&c)
		if _, err := Compile(c); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}
func TestObservationRejectsExpressionLossAndDrift(t *testing.T) {
	valid := observed(t, testConfig())
	for _, pair := range [][2]string{
		{`"prio":0`, `"prio":1,"prio":0`}, {`"policy":"drop"`, `"policy":"accept"`},
		{`"right":"reply"`, `"right":"original"`}, {`"right":"established"`, `"right":"new"`},
		{`"right":1095648325`, `"right":1`}, {`"right":"src0"`, `"right":"any"`},
		{`"right":"198.18.0.6"`, `"right":"198.18.0.7"`}, {`"range":[30000,40000]`, `"range":[1,65535]`},
		{`"counter":{"bytes":0,"packets":0}`, `"counter":{"bytes":-1,"packets":0}`},
	} {
		mutated := bytes.Replace(valid, []byte(pair[0]), []byte(pair[1]), 1)
		if bytes.Equal(mutated, valid) {
			t.Fatalf("mutation absent %s", pair[0])
		}
		if _, err := InspectObservation(mutated); err == nil {
			t.Fatalf("accepted drift %s", pair[0])
		}
	}
	for _, data := range [][]byte{append(bytes.Clone(valid), []byte(`{}`)...), bytes.Repeat([]byte(" "), MaxObservation+1)} {
		if _, err := InspectObservation(data); err == nil {
			t.Fatal("accepted invalid envelope")
		}
	}
	for ruleIndex := 2; ruleIndex < 4; ruleIndex++ {
		for exprIndex := 0; exprIndex < 13; exprIndex++ {
			var envelope struct {
				Objects []object `json:"nftables"`
			}
			_ = json.Unmarshal(valid, &envelope)
			rule := envelope.Objects[ruleIndex]["rule"].(map[string]any)
			exprs := rule["expr"].([]any)
			rule["expr"] = append(exprs[:exprIndex], exprs[exprIndex+1:]...)
			data, _ := json.Marshal(envelope)
			_, err := InspectObservation(data)
			if (err == nil) != (exprIndex == 0 || exprIndex == 5) {
				t.Fatalf("expression deletion rule=%d expr=%d err=%v", ruleIndex, exprIndex, err)
			}
		}
	}
}
func TestCountersAndKernelProtocolNormalization(t *testing.T) {
	a, _ := Compile(testConfig())
	objects := policyObjects(a.Revision)
	for _, entry := range objects[2:] {
		rule := entry["rule"].(object)
		exprs := rule["expr"].([]object)
		exprs[len(exprs)-2] = object{"counter": object{"packets": 3, "bytes": 128}}
		rule["expr"] = append(append([]object{}, exprs[1:5]...), exprs[6:]...)
		rule["handle"] = 42
	}
	data, _ := json.Marshal(object{"nftables": objects})
	obs, err := InspectObservation(data)
	if err != nil || obs.Rules[0].Packets != 6 || obs.Rules[0].Bytes != 256 {
		t.Fatalf("normalized counter readback: %v", err)
	}
	data = bytes.ReplaceAll(data, []byte(`"packets":3`), []byte(`"packets":18446744073709551615`))
	if _, err := InspectObservation(data); err == nil {
		t.Fatal("aggregate overflow accepted")
	}
}

// This small interpreter evaluates generated selectors, independently of the
// compiler's direction logic. Native kernel evidence remains a separate gate.
type packet struct {
	source, destination, protocol, input, output, direction, state string
	sport, dport                                                   uint16
	mark                                                           uint32
}

func evaluate(t *testing.T, c configpoc.Config, p packet) (bool, uint32) {
	t.Helper()
	a, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range policyObjects(a.Revision)[2:] {
		rule := entry["rule"].(object)
		matched := true
		mark := p.mark
		for _, expr := range rule["expr"].([]object) {
			if raw, ok := expr["match"]; ok {
				m := raw.(object)
				left := m["left"].(object)
				right := m["right"]
				var actual any
				if raw, ok := left["meta"]; ok {
					switch raw.(object)["key"] {
					case "nfproto":
						actual = "ipv4"
						if netip.MustParseAddr(p.source).Is6() {
							actual = "ipv6"
						}
					case "iifname":
						actual = p.input
					case "oifname":
						actual = p.output
					case "l4proto":
						actual = p.protocol
					}
				}
				if raw, ok := left["payload"]; ok {
					v := raw.(object)
					switch v["field"] {
					case "saddr":
						actual = p.source
					case "daddr":
						actual = p.destination
					case "sport":
						actual = p.sport
					case "dport":
						actual = p.dport
					}
				}
				if raw, ok := left["ct"]; ok {
					switch raw.(object)["key"] {
					case "direction":
						actual = p.direction
					case "state":
						actual = p.state
					case "mark":
						actual = p.mark
					}
				}
				matches := equalJSON(actual, right)
				if obj, ok := right.(object); ok {
					if raw, ok := obj["prefix"]; ok {
						v := raw.(object)
						prefix := netip.PrefixFrom(netip.MustParseAddr(v["addr"].(string)), v["len"].(int))
						matches = prefix.Contains(netip.MustParseAddr(actual.(string)))
					}
					if raw, ok := obj["range"]; ok {
						bounds := raw.([]uint16)
						n := actual.(uint16)
						matches = n >= bounds[0] && n <= bounds[1]
					}
				}
				if states, ok := right.([]string); ok {
					matches = false
					for _, state := range states {
						matches = matches || actual == state
					}
				}
				if !matches {
					matched = false
					break
				}
			}
			if _, ok := expr["mangle"]; ok {
				mark = AdmittedMark
			}
			if _, ok := expr["accept"]; ok && matched {
				return true, mark
			}
			if _, ok := expr["drop"]; ok && matched {
				return false, p.mark
			}
		}
	}
	return false, p.mark
}
func TestStatefulResponsesAndRevocation(t *testing.T) {
	c := testConfig()
	request := packet{source: "198.18.0.2", destination: "198.18.0.6", protocol: "tcp", input: "src0", output: "dst0", direction: "original", state: "new", sport: 35000, dport: 18080}
	allowed, mark := evaluate(t, c, request)
	if !allowed || mark != AdmittedMark {
		t.Fatal("request not admitted")
	}
	reply := packet{source: request.destination, destination: request.source, protocol: "tcp", input: "dst0", output: "src0", direction: "reply", state: "established", sport: 18080, dport: 35000, mark: mark}
	if allowed, _ := evaluate(t, c, reply); !allowed {
		t.Fatal("stateful reply denied")
	}
	for name, mutate := range map[string]func(*packet){
		"unsolicited reverse":         func(p *packet) { p.direction = "original"; p.state = "new"; p.mark = 0 },
		"denied request forged reply": func(p *packet) { p.mark = 0 },
		"invalid":                     func(p *packet) { p.state = "invalid" },
		"untracked":                   func(p *packet) { p.state = "untracked" },
		"related":                     func(p *packet) { p.state = "related" },
		"wrong direction":             func(p *packet) { p.direction = "original" },
		"source port":                 func(p *packet) { p.sport = 18081 },
		"destination port":            func(p *packet) { p.dport = 42000 },
		"wrong interface":             func(p *packet) { p.input = "src0" },
		"ipv6":                        func(p *packet) { p.source = "2001:db8::1" },
		"unknown":                     func(p *packet) { p.protocol = "icmp" },
	} {
		t.Run(name, func(t *testing.T) {
			p := reply
			mutate(&p)
			if allowed, _ := evaluate(t, c, p); allowed {
				t.Fatal("forbidden reply admitted")
			}
		})
	}
	for _, state := range []string{"invalid", "untracked", "related"} {
		p := request
		p.state = state
		if allowed, _ := evaluate(t, c, p); allowed {
			t.Fatal("invalid original admitted")
		}
	}
	for name, mutate := range map[string]func(*configpoc.Config){
		"deleted":       func(c *configpoc.Config) { c.Rules = nil },
		"narrowed port": func(c *configpoc.Config) { c.Rules[0].Match.SourcePorts.To = 34000 },
		"narrowed cidr": func(c *configpoc.Config) { c.Rules[0].Match.Source = "198.18.0.1/32" },
		"changed tuple": func(c *configpoc.Config) {
			c.Rules[0].Match.DestinationPorts.From = 18081
			c.Rules[0].Match.DestinationPorts.To = 18081
		},
		"earlier deny": func(c *configpoc.Config) {
			deny := c.Rules[0]
			deny.ID = "block"
			deny.Action = "deny"
			c.Rules = append([]configpoc.Rule{deny}, c.Rules...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := testConfig()
			mutate(&policy)
			if allowed, _ := evaluate(t, policy, reply); allowed {
				t.Fatal("revoked reply admitted")
			}
		})
	}
	// A new rule with the same tuple intentionally permits the admitted flow.
	c.Rules[0].ID = "replacement"
	if allowed, _ := evaluate(t, c, reply); !allowed {
		t.Fatal("same-tuple current permission lost")
	}
	deny := c.Rules[0]
	deny.Action = "deny"
	deny.ID = "later-deny"
	c.Rules = append(c.Rules, deny)
	if allowed, _ := evaluate(t, c, reply); !allowed {
		t.Fatal("later deny violated first match")
	}
}
