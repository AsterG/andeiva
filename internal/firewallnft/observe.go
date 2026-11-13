package firewallnft

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftengine"
)

// Counters are aggregate packet/byte observations, not per-flow logs. They reset
// on each atomic table replacement and include both directions of the rule.
type RuleCounter struct {
	ID      string `json:"id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}
type Observation struct {
	Revision configpoc.Revision `json:"revision"`
	Rules    []RuleCounter      `json:"rules"`
}

func DecodeObservation(data []byte) (configpoc.Revision, error) {
	observed, err := InspectObservation(data)
	return observed.Revision, err
}

// InspectObservation verifies semantic expressions and order before exposing
// counters. IDs and revision comments alone never establish effective policy.
func InspectObservation(data []byte) (Observation, error) {
	return inspectObservation(data, nil)
}

// VerifyObservation uses a complete trusted revision, including disabled rules,
// and compares every effective expression and its order against its compiler.
func VerifyObservation(data []byte, expected configpoc.Revision) (Observation, error) {
	r, err := configpoc.Canonical(expected.Config)
	if err != nil || r.Hash != expected.Hash {
		return Observation{}, ErrObservation
	}
	return inspectObservation(data, &r)
}

func inspectObservation(data []byte, trusted *configpoc.Revision) (Observation, error) {
	if len(data) == 0 || len(data) > MaxObservation || !nftengine.UniqueJSONFields(data) {
		return Observation{}, ErrObservation
	}
	var envelope struct {
		Objects []object `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || len(envelope.Objects) > 131 {
		return Observation{}, ErrObservation
	}
	objects := make([]object, 0, len(envelope.Objects))
	counts := make([]RuleCounter, 0, 128)
	for index, entry := range envelope.Objects {
		if len(entry) != 1 {
			return Observation{}, ErrObservation
		}
		if meta, exists := entry["metainfo"]; exists {
			if index != 0 || !nftengine.ValidMetainfo(meta) {
				return Observation{}, ErrObservation
			}
			continue
		}
		for key, value := range entry {
			if key != "table" && key != "chain" && key != "rule" {
				return Observation{}, ErrObservation
			}
			body, ok := value.(map[string]any)
			if !ok {
				return Observation{}, ErrObservation
			}
			if handle, exists := body["handle"]; exists {
				if _, ok := unsigned(handle); !ok {
					return Observation{}, ErrObservation
				}
				delete(body, "handle")
			}
			if key == "rule" {
				exprs, ok := body["expr"].([]any)
				if !ok || len(exprs) < 8 || len(exprs) > 13 {
					return Observation{}, ErrObservation
				}
				count := RuleCounter{}
				found := false
				for _, raw := range exprs {
					expr, ok := raw.(map[string]any)
					if !ok {
						return Observation{}, ErrObservation
					}
					if rawCounter, exists := expr["counter"]; exists {
						counter, ok := rawCounter.(map[string]any)
						if !ok || len(counter) != 2 || found {
							return Observation{}, ErrObservation
						}
						var valid bool
						count.Packets, valid = unsigned(counter["packets"])
						if !valid {
							return Observation{}, ErrObservation
						}
						count.Bytes, valid = unsigned(counter["bytes"])
						if !valid {
							return Observation{}, ErrObservation
						}
						expr["counter"] = object{"packets": 0, "bytes": 0}
						found = true
					}
				}
				if !found {
					return Observation{}, ErrObservation
				}
				counts = append(counts, count)
			}
		}
		objects = append(objects, entry)
	}
	if len(objects) < 2 || (len(objects)-2)%2 != 0 {
		return Observation{}, ErrObservation
	}
	config := DefaultConfig()
	if trusted != nil {
		config = trusted.Config
	} else {
		for i := 2; i < len(objects); i += 2 {
			body, ok := objects[i]["rule"].(map[string]any)
			if !ok {
				return Observation{}, ErrObservation
			}
			comment, _ := body["comment"].(string)
			prefix := CompilerVersion + ":"
			if !strings.HasPrefix(comment, prefix) || !strings.HasSuffix(comment, ":f") {
				return Observation{}, ErrObservation
			}
			id := strings.TrimSuffix(strings.TrimPrefix(comment, prefix), ":f")
			exprs, ok := body["expr"].([]any)
			if !ok {
				return Observation{}, ErrObservation
			}
			m, err := extractMatch(exprs)
			if err != nil {
				return Observation{}, err
			}
			last, ok := exprs[len(exprs)-1].(map[string]any)
			if !ok || len(last) != 1 {
				return Observation{}, ErrObservation
			}
			action := ""
			if value, exists := last["accept"]; exists && value == nil {
				action = "allow"
			}
			if value, exists := last["drop"]; exists && value == nil {
				action = "deny"
			}
			config.Rules = append(config.Rules, configpoc.Rule{ID: id, Action: action, Match: m})
		}
	}
	artifact, err := Compile(config)
	if err != nil {
		return Observation{}, ErrObservation
	}
	expected := policyObjects(artifact.Revision)
	active := 0
	for _, rule := range config.Rules {
		if rule.IsEnabled() {
			active++
		}
	}
	if len(expected) != len(objects) || len(counts) != active*2 {
		return Observation{}, ErrObservation
	}
	for i := range expected {
		if !sameObject(objects[i], expected[i]) {
			return Observation{}, ErrObservation
		}
	}
	result := Observation{Revision: artifact.Revision, Rules: make([]RuleCounter, 0, len(config.Rules))}
	i := 0
	for _, rule := range config.Rules {
		if !rule.IsEnabled() {
			continue
		}
		a, b := counts[2*i], counts[2*i+1]
		i++
		if math.MaxUint64-a.Packets < b.Packets || math.MaxUint64-a.Bytes < b.Bytes {
			return Observation{}, ErrObservation
		}
		result.Rules = append(result.Rules, RuleCounter{ID: rule.ID, Packets: a.Packets + b.Packets, Bytes: a.Bytes + b.Bytes})
	}
	return result, nil
}

func unsigned(value any) (uint64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseUint(n.String(), 10, 64)
	return v, err == nil
}
func equalJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

func extractMatch(exprs []any) (*configpoc.Match, error) {
	m := &configpoc.Match{}
	seen := map[string]bool{}
	for _, raw := range exprs {
		expr, ok := raw.(map[string]any)
		if !ok {
			return nil, ErrObservation
		}
		comparison, ok := expr["match"].(map[string]any)
		if !ok {
			continue
		}
		left, ok := comparison["left"].(map[string]any)
		if !ok {
			continue
		}
		selector, ok := left["payload"].(map[string]any)
		if !ok {
			continue
		}
		protocol, _ := selector["protocol"].(string)
		field, _ := selector["field"].(string)
		key := protocol + ":" + field
		if seen[key] {
			return nil, ErrObservation
		}
		seen[key] = true
		right := comparison["right"]
		var err error
		switch {
		case protocol == "ip" && field == "saddr":
			m.Source, err = parseAddress(right)
		case protocol == "ip" && field == "daddr":
			m.Destination, err = parseAddress(right)
		case (protocol == "tcp" || protocol == "udp") && (field == "sport" || field == "dport"):
			if m.Protocol != "" && m.Protocol != protocol {
				return nil, ErrObservation
			}
			m.Protocol = protocol
			var p configpoc.PortRange
			p, err = parsePorts(right)
			if field == "sport" {
				m.SourcePorts = p
			} else {
				m.DestinationPorts = p
			}
		default:
			return nil, ErrObservation
		}
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

func parseAddress(value any) (string, error) {
	if text, ok := value.(string); ok {
		a, err := netip.ParseAddr(text)
		if err == nil && a.Is4() && a.String() == text {
			return text + "/32", nil
		}
		return "", ErrObservation
	}
	obj, ok := value.(map[string]any)
	if !ok || len(obj) != 1 {
		return "", ErrObservation
	}
	prefix, ok := obj["prefix"].(map[string]any)
	if !ok || len(prefix) != 2 {
		return "", ErrObservation
	}
	address, ok := prefix["addr"].(string)
	if !ok {
		return "", ErrObservation
	}
	bits, ok := unsigned(prefix["len"])
	if !ok || bits > 32 {
		return "", ErrObservation
	}
	text := address + "/" + strconv.FormatUint(bits, 10)
	p, err := netip.ParsePrefix(text)
	if err != nil || !p.Addr().Is4() || p.Masked().String() != text {
		return "", ErrObservation
	}
	return text, nil
}

func parsePorts(value any) (configpoc.PortRange, error) {
	if n, ok := unsigned(value); ok && n > 0 && n <= 65535 {
		return configpoc.PortRange{From: uint16(n), To: uint16(n)}, nil
	}
	obj, ok := value.(map[string]any)
	if !ok || len(obj) != 1 {
		return configpoc.PortRange{}, ErrObservation
	}
	rangeValues, ok := obj["range"].([]any)
	if !ok || len(rangeValues) != 2 {
		return configpoc.PortRange{}, ErrObservation
	}
	a, aok := unsigned(rangeValues[0])
	b, bok := unsigned(rangeValues[1])
	if !aok || !bok || a == 0 || a > 65535 || a > b || b > 65535 {
		return configpoc.PortRange{}, ErrObservation
	}
	return configpoc.PortRange{From: uint16(a), To: uint16(b)}, nil
}

// nft 1.1.3 removes redundant nfproto/l4proto guards implied by typed payload
// selectors. Only complete variants are accepted; all other expressions remain.
func sameObject(actual, expected object) bool {
	rule, ok := expected["rule"].(object)
	if !ok {
		return equalJSON(actual, expected)
	}
	expressions := rule["expr"].([]object)
	for mask := 0; mask < 4; mask++ {
		for variantBits := 0; variantBits < 4; variantBits++ {
			numeric := variantBits&1 != 0
			numericConntrack := variantBits&2 != 0
			variant := make([]object, 0, len(expressions))
			for i, expression := range expressions {
				if (i == 0 && mask&1 != 0) || (i == 5 && mask&2 != 0) {
					continue
				}
				if i == 5 && numeric {
					protocol := 6
					if expression["match"].(object)["right"] == "udp" {
						protocol = 17
					}
					expression = match(object{"meta": object{"key": "l4proto"}}, protocol)
				}
				if numericConntrack && (i == 8 || i == 9) {
					expression = numericConntrackMatch(expression)
				}
				variant = append(variant, expression)
			}
			candidate := make(object, len(rule))
			for key, value := range rule {
				candidate[key] = value
			}
			candidate["expr"] = variant
			if equalJSON(actual, object{"rule": candidate}) {
				return true
			}
		}
	}
	return false
}

// nft -y renders these conntrack enums numerically. Build a complete expected
// variant; do not normalize or discard any condition from the observation.
func numericConntrackMatch(expression object) object {
	m, ok := expression["match"].(object)
	if !ok {
		return expression
	}
	var right any
	switch {
	case equalJSON(m["left"], ct("direction")) && m["right"] == "original":
		right = 0
	case equalJSON(m["left"], ct("direction")) && m["right"] == "reply":
		right = 1
	case equalJSON(m["left"], ct("state")) && equalJSON(m["right"], []string{"established", "new"}):
		right = []int{2, 8}
	case equalJSON(m["left"], ct("state")) && m["right"] == "established":
		right = 2
	default:
		return expression
	}
	return object{"match": object{"op": m["op"], "left": m["left"], "right": right}}
}
