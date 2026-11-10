package nftpoc

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftengine"
)

// DecodeObservation accepts the exact fixture semantics, preserving rule order.
// Comments identify candidate rules; comparison of every expression establishes
// their meaning. Kernel handles/metainfo and the documented redundant protocol
// dependency elision in nft 1.1.3 are normalized; payload selectors stay mandatory.
func DecodeObservation(data []byte) (configpoc.Revision, error) {
	if len(data) == 0 || len(data) > MaxObservation || !nftengine.UniqueJSONFields(data) {
		return configpoc.Revision{}, ErrObservation
	}
	var envelope struct {
		Objects []object `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || len(envelope.Objects) > 3+2*len(selectors) {
		return configpoc.Revision{}, ErrObservation
	}
	objects := make([]object, 0, len(envelope.Objects))
	for index, entry := range envelope.Objects {
		if len(entry) != 1 {
			return configpoc.Revision{}, ErrObservation
		}
		if meta, exists := entry["metainfo"]; exists {
			if index != 0 || !nftengine.ValidMetainfo(meta) {
				return configpoc.Revision{}, ErrObservation
			}
			continue
		}
		for key, value := range entry {
			if key != "table" && key != "chain" && key != "rule" {
				return configpoc.Revision{}, ErrObservation
			}
			body, ok := value.(map[string]any)
			if !ok {
				return configpoc.Revision{}, ErrObservation
			}
			if handle, exists := body["handle"]; exists {
				if number, ok := handle.(json.Number); !ok {
					return configpoc.Revision{}, ErrObservation
				} else if n, err := number.Int64(); err != nil || n < 0 {
					return configpoc.Revision{}, ErrObservation
				}
				delete(body, "handle")
			}
		}
		objects = append(objects, entry)
	}
	if len(objects) < 2 || (len(objects)-2)%2 != 0 {
		return configpoc.Revision{}, ErrObservation
	}
	config := DefaultConfig()
	for i := 2; i < len(objects); i += 2 {
		rule, ok := objects[i]["rule"].(map[string]any)
		if !ok {
			return configpoc.Revision{}, ErrObservation
		}
		comment, _ := rule["comment"].(string)
		prefix, suffix := CompilerVersion+":", ":f"
		if !strings.HasPrefix(comment, prefix) || !strings.HasSuffix(comment, suffix) {
			return configpoc.Revision{}, ErrObservation
		}
		id := strings.TrimSuffix(strings.TrimPrefix(comment, prefix), suffix)
		if _, err := lookup(id); err != nil {
			return configpoc.Revision{}, ErrObservation
		}
		expressions, ok := rule["expr"].([]any)
		if !ok || len(expressions) < 6 || len(expressions) > 8 {
			return configpoc.Revision{}, ErrObservation
		}
		verdict, ok := expressions[len(expressions)-1].(map[string]any)
		if !ok || len(verdict) != 1 {
			return configpoc.Revision{}, ErrObservation
		}
		action := ""
		if value, exists := verdict["accept"]; exists && value == nil {
			action = "allow"
		}
		if value, exists := verdict["drop"]; exists && value == nil {
			action = "deny"
		}
		if action == "" {
			return configpoc.Revision{}, ErrObservation
		}
		config.Rules = append(config.Rules, configpoc.Rule{ID: id, Action: action})
	}
	compiled, err := Compile(config)
	if err != nil {
		return configpoc.Revision{}, ErrObservation
	}
	expected := policyObjects(compiled.Revision)
	for i := range objects {
		if !sameObservedObject(objects[i], expected[i]) {
			return configpoc.Revision{}, ErrObservation
		}
	}
	return compiled.Revision, nil
}

func equalJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

// nft's delinearizer removes nfproto/l4proto dependencies when the exact typed
// payload expressions imply them (upstream v1.1.3 netlink_delinearize.c and
// tests/py/inet/meta.t.json.output). Match only complete expected rule variants;
// never discard arbitrary observed expressions or infer meaning from comments.
func sameObservedObject(actual, expected object) bool {
	rule, ok := expected["rule"].(object)
	if !ok {
		return equalJSON(actual, expected)
	}
	expressions := rule["expr"].([]object)
	for mask := 0; mask < 4; mask++ {
		for _, numeric := range []bool{false, true} {
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
