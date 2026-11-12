package routednft

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"

	"github.com/AsterG/andeiva/internal/nftengine"
)

type Counter struct {
	Rule    string `json:"rule"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}
type Observation struct {
	Revision Revision  `json:"revision"`
	Counters []Counter `json:"counters"`
}

// VerifyObservation compares every object, expression and order against a trusted
// complete revision. Only kernel handles, metadata and counter values may vary.
func VerifyObservation(data []byte, expected Revision) (Observation, error) {
	r, e := Canonical(expected.Policy)
	if e != nil || r.Hash != expected.Hash || len(data) == 0 || len(data) > MaxObservation || !nftengine.UniqueJSONFields(data) {
		return Observation{}, ErrObservation
	}
	var envelope struct {
		Objects []object `json:"nftables"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || len(envelope.Objects) > MaxRules*6+40 {
		return Observation{}, ErrObservation
	}
	objects := []object{}
	counters := []Counter{}
	for i, entry := range envelope.Objects {
		if len(entry) != 1 {
			return Observation{}, ErrObservation
		}
		if m, ok := entry["metainfo"]; ok {
			if i != 0 || !nftengine.ValidMetainfo(m) {
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
			if handle, ok := body["handle"]; ok {
				if _, e := unsigned(handle); e != nil {
					return Observation{}, ErrObservation
				}
				delete(body, "handle")
			}
			if key != "rule" {
				continue
			}
			exprs, ok := body["expr"].([]any)
			if !ok || len(exprs) > 20 {
				return Observation{}, ErrObservation
			}
			count := Counter{}
			found := false
			count.Rule, _ = body["comment"].(string)
			for _, raw := range exprs {
				expr, ok := raw.(map[string]any)
				if !ok {
					return Observation{}, ErrObservation
				}
				if rawCounter, exists := expr["counter"]; exists {
					c, ok := rawCounter.(map[string]any)
					if !ok || len(c) != 2 || found {
						return Observation{}, ErrObservation
					}
					var e error
					count.Packets, e = unsigned(c["packets"])
					if e != nil {
						return Observation{}, ErrObservation
					}
					count.Bytes, e = unsigned(c["bytes"])
					if e != nil {
						return Observation{}, ErrObservation
					}
					expr["counter"] = object{"packets": 0, "bytes": 0}
					found = true
				}
			}
			if !found {
				return Observation{}, ErrObservation
			}
			counters = append(counters, count)
		}
		objects = append(objects, entry)
	}
	wanted := policyObjects(r)
	if len(objects) != len(wanted) {
		return Observation{}, ErrObservation
	}
	for i := range wanted {
		if !sameObject(objects[i], wanted[i]) {
			return Observation{}, ErrObservation
		}
	}
	return Observation{Revision: r, Counters: counters}, nil
}

func unsigned(v any) (uint64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, ErrObservation
	}
	return strconv.ParseUint(n.String(), 10, 64)
}
func equal(a, b any) bool { x, _ := json.Marshal(a); y, _ := json.Marshal(b); return bytes.Equal(x, y) }

func sameObject(actual, expected object) bool {
	if equal(actual, expected) {
		return true
	}
	if equal(actual, nativeObject(expected)) {
		return true
	}
	// nft normalizes protocol symbols to numbers and may remove an nfproto
	// dependency implied by a typed IPv4 or ICMP selector. Accept only those exact
	// compiler-derived variants, never arbitrary omitted predicates.
	raw, ok := expected["rule"].(object)
	if !ok {
		return false
	}
	exprs := raw["expr"].([]object)
	for mask := 0; mask < 4; mask++ {
		variant := []object{}
		for _, expr := range exprs {
			encoded, _ := json.Marshal(expr)
			var clone object
			_ = json.Unmarshal(encoded, &clone)
			m, ok := clone["match"].(map[string]any)
			if ok {
				left, _ := m["left"].(map[string]any)
				sel, _ := left["meta"].(map[string]any)
				if mask&1 != 0 && sel["key"] == "nfproto" {
					continue
				}
				if mask&2 != 0 {
					switch m["right"] {
					case "tcp":
						m["right"] = 6
					case "udp":
						m["right"] = 17
					case "icmp":
						m["right"] = 1
					}
				}
			}
			variant = append(variant, clone)
		}
		candidate := object{}
		for k, v := range raw {
			candidate[k] = v
		}
		candidate["expr"] = variant
		if equal(actual, object{"rule": candidate}) {
			return true
		}
	}
	return false
}

// nativeObject reproduces only the complete normalization observed with Debian
// nft 1.1.3. IPv4 selectors, addresses/prefixes, marks, ports, verdicts and order
// are never relaxed. Protocol is bidirectional; the 8-bit identity mask and its
// redundant original direction disappear in netlink readback.
func nativeObject(expected object) object {
	data, _ := json.Marshal(expected)
	var result object
	_ = json.Unmarshal(data, &result)
	rule, ok := result["rule"].(map[string]any)
	if !ok {
		return result
	}
	exprs, _ := rule["expr"].([]any)
	typedICMP := false
	for _, raw := range exprs {
		expr, _ := raw.(map[string]any)
		m, _ := expr["match"].(map[string]any)
		left, _ := m["left"].(map[string]any)
		p, _ := left["payload"].(map[string]any)
		if p["protocol"] == "icmp" && p["field"] == "type" {
			typedICMP = true
		}
	}
	variant := []any{}
	for _, raw := range exprs {
		expr, _ := raw.(map[string]any)
		m, ok := expr["match"].(map[string]any)
		if ok {
			left, _ := m["left"].(map[string]any)
			selector, _ := left["meta"].(map[string]any)
			if selector["key"] == "nfproto" {
				continue
			}
			if selector["key"] == "l4proto" {
				if typedICMP && m["right"] == "icmp" {
					continue
				}
				switch m["right"] {
				case "tcp":
					m["right"] = 6
				case "udp":
					m["right"] = 17
				case "icmp":
					m["right"] = 1
				}
			}
			if equal(left, object{"&": []any{original("protocol"), 255}}) {
				m["left"] = ct("protocol")
			}
			c, _ := left["ct"].(map[string]any)
			switch c["key"] {
			case "direction":
				if m["right"] == "original" {
					m["right"] = 0
				}
				if m["right"] == "reply" {
					m["right"] = 1
				}
			case "state":
				if equal(m["right"], []string{"new", "established"}) {
					m["right"] = []int{2, 8}
				} else {
					switch m["right"] {
					case "related":
						m["right"] = 4
					case "established":
						m["right"] = 2
					}
				}
			}
		}
		variant = append(variant, raw)
	}
	rule["expr"] = variant
	return result
}
