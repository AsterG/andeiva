package localnft

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/nftengine"
)

type RuleCounter struct {
	ID      string `json:"id"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Observation struct {
	Revision     localpolicy.Revision `json:"revision"`
	Digest       string               `json:"digest"`
	ReadbackHash string               `json:"readback_hash"`
	Rules        []RuleCounter        `json:"rules"`
	Controls     []RuleCounter        `json:"controls"`
}

// VerifyObservation requires a full fixed-table listing, including all rules.
// Counters are published only after checking independently compiled semantics.
// ReadbackHash binds the exact verified bytes; counters are never inferred.
func VerifyObservation(data []byte, expected Artifact) (Observation, error) {
	if len(data) == 0 || len(data) > MaxObservation || !nftengine.UniqueJSONFields(data) {
		return Observation{}, ErrObservation
	}
	fresh, err := CompileWithNeighbors(expected.Revision.Config, expected.Neighbors)
	if err != nil || !equalJSON(fresh, expected) {
		return Observation{}, ErrObservation
	}
	entries, err := decodeObjects(data)
	if err != nil || len(entries) > MaxRules+MaxControlRules+3 {
		return Observation{}, ErrObservation
	}
	expectedObjects, err := createObjects(fresh.Create)
	if err != nil {
		return Observation{}, ErrObservation
	}
	observed := make([]object, 0, len(entries))
	counts := make([]RuleCounter, 0)
	for index, entry := range entries {
		if len(entry) != 1 {
			return Observation{}, ErrObservation
		}
		if meta, ok := entry["metainfo"]; ok {
			if index != 0 || !nftengine.ValidMetainfo(meta) {
				return Observation{}, ErrObservation
			}
			continue
		}
		for key, raw := range entry {
			if key != "table" && key != "chain" && key != "rule" {
				return Observation{}, ErrObservation
			}
			body, ok := raw.(object)
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
				count, err := normalizeCounter(body, false)
				if err != nil {
					return Observation{}, err
				}
				counts = append(counts, count)
			}
		}
		observed = append(observed, entry)
	}
	if len(observed) != len(expectedObjects) || len(counts) != len(fresh.Rules)+len(fresh.ControlIDs) {
		return Observation{}, ErrObservation
	}
	for i := range observed {
		if !sameObject(observed[i], expectedObjects[i]) {
			return Observation{}, ErrObservation
		}
	}
	result := Observation{Revision: fresh.Revision, Digest: fresh.Digest, ReadbackHash: hash(data), Rules: []RuleCounter{}, Controls: []RuleCounter{}}
	for i, count := range counts {
		if i < len(fresh.ControlIDs) {
			count.ID = fresh.ControlIDs[i]
			result.Controls = append(result.Controls, count)
		} else {
			count.ID = fresh.Rules[i-len(fresh.ControlIDs)].ID
			result.Rules = append(result.Rules, count)
		}
	}
	return result, nil
}

func decodeObjects(data []byte) ([]object, error) {
	var envelope struct {
		Objects []object `json:"nftables"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || envelope.Objects == nil {
		return nil, ErrObservation
	}
	return envelope.Objects, nil
}

func createObjects(data []byte) ([]object, error) {
	commands, err := decodeObjects(data)
	if err != nil {
		return nil, err
	}
	objects := make([]object, 0, len(commands))
	for _, command := range commands {
		add, ok := command["add"].(object)
		if !ok {
			return nil, ErrObservation
		}
		if raw, exists := add["rule"]; exists {
			body, ok := raw.(object)
			if !ok {
				return nil, ErrObservation
			}
			if _, err := normalizeCounter(body, true); err != nil {
				return nil, err
			}
		}
		objects = append(objects, add)
	}
	return objects, nil
}

func normalizeCounter(body object, expected bool) (RuleCounter, error) {
	exprs, ok := body["expr"].([]any)
	if !ok || len(exprs) < 6 || len(exprs) > 11 {
		return RuleCounter{}, ErrObservation
	}
	count := RuleCounter{}
	found := false
	for _, raw := range exprs {
		expr, ok := raw.(object)
		if !ok || len(expr) != 1 {
			return RuleCounter{}, ErrObservation
		}
		if rawCounter, exists := expr["counter"]; exists {
			if found {
				return RuleCounter{}, ErrObservation
			}
			found = true
			if !(expected && rawCounter == nil) {
				counter, ok := rawCounter.(object)
				if !ok || len(counter) != 2 {
					return RuleCounter{}, ErrObservation
				}
				var valid bool
				count.Packets, valid = unsigned(counter["packets"])
				if !valid {
					return RuleCounter{}, ErrObservation
				}
				count.Bytes, valid = unsigned(counter["bytes"])
				if !valid {
					return RuleCounter{}, ErrObservation
				}
			}
			expr["counter"] = object{"packets": 0, "bytes": 0}
		}
	}
	if !found {
		return RuleCounter{}, ErrObservation
	}
	return count, nil
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
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && bytes.Equal(left, right)
}

// Only redundant guards implied by typed IP/transport payloads may disappear
// during nft's round trip. Required payload predicates and their order remain.
func sameObject(actual, expected object) bool {
	rule, ok := expected["rule"].(object)
	if !ok {
		return equalJSON(actual, expected)
	}
	exprs, ok := rule["expr"].([]any)
	if !ok {
		return false
	}
	for mask := 0; mask < 4; mask++ {
		for _, numeric := range []bool{false, true} {
			for _, symbolicICMP := range []bool{false, true} {
				variant := make([]any, 0, len(exprs))
				for _, raw := range exprs {
					expr := raw.(object)
					comparison, isMatch := expr["match"].(object)
					if isMatch {
						left, _ := comparison["left"].(object)
						if meta, ok := left["meta"].(object); ok {
							key, _ := meta["key"].(string)
							if key == "nfproto" && mask&1 != 0 || key == "l4proto" && mask&2 != 0 {
								continue
							}
							if key == "l4proto" && numeric {
								protocols := map[string]int{"tcp": 6, "udp": 17, "ipv6-icmp": 58}
								if name, ok := comparison["right"].(string); ok {
									expr = match(left, protocols[name])
								}
							}
						}
						if p, ok := left["payload"].(object); ok && p["protocol"] == "icmpv6" && p["field"] == "type" && symbolicICMP {
							name := "nd-neighbor-solicit"
							if comparison["right"] == json.Number("136") {
								name = "nd-neighbor-advert"
							}
							expr = match(left, name)
						}
					}
					variant = append(variant, expr)
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
	}
	return false
}

// ControlID distinguishes infrastructure ND counters from service permissions.
func ControlID(id string) bool {
	return strings.HasPrefix(id, "andeiva-nd:") && len(id) == len("andeiva-nd:")+64
}
