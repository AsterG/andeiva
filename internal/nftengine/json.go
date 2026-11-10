package nftengine

import (
	"bytes"
	"encoding/json"
	"io"
)

// Reject duplicate keys rather than letting the decoder silently select a value.
func UniqueJSONFields(data []byte) bool {
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

func ValidMetainfo(value any) bool {
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
