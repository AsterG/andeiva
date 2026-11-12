package nftengine

import (
	"encoding/json"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

// Reject duplicate keys rather than letting the decoder silently select a value.
func UniqueJSONFields(data []byte) bool { return jsoncheck.UniqueFields(data) }

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
