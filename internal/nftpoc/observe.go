package nftpoc

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// DecodeObservation accepts the exact fixture semantics, preserving rule order.
// Comments identify candidate rules; comparison of every expression establishes
// their meaning. Only kernel-assigned object handles and metainfo are ignored.
func DecodeObservation(data []byte) (configpoc.Revision, error) {
	if len(data) == 0 || len(data) > MaxObservation || !uniqueJSONFields(data) {
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
			if index != 0 || !validMetainfo(meta) {
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
		if !ok || len(expressions) != 8 {
			return configpoc.Revision{}, ErrObservation
		}
		verdict, ok := expressions[7].(map[string]any)
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
	actual, _ := json.Marshal(objects)
	expected, _ := json.Marshal(policyObjects(compiled.Revision))
	if !bytes.Equal(actual, expected) {
		return configpoc.Revision{}, ErrObservation
	}
	return compiled.Revision, nil
}

// Reject duplicate keys rather than letting the decoder silently select a value.
func uniqueJSONFields(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 24 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] || !walk(depth+1) {
					return false
				}
				seen[name] = true
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				if !walk(depth + 1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !walk(0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func validMetainfo(value any) bool {
	meta, ok := value.(map[string]any)
	if !ok || len(meta) > 3 {
		return false
	}
	for key, item := range meta {
		switch key {
		case "version", "release_name":
			if text, ok := item.(string); !ok || len(text) > 128 {
				return false
			}
		case "json_schema_version":
			if number, ok := item.(json.Number); !ok || number.String() != "1" {
				return false
			}
		default:
			return false
		}
	}
	return true
}
