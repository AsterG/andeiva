package routedactivation

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/nftengine"
	"github.com/AsterG/andeiva/internal/routednft"
)

// TablePresence accepts only a successful, complete table-list observation.
// Presence is not ownership: the full ruleset still requires engine readback.
func TablePresence(data []byte, table Table) (bool, error) {
	var name string
	switch table {
	case LegacyTable:
		name = firewallnft.TableName
	case RoutedTable:
		name = routednft.TableName
	case LocalTable:
		name = localnft.TableName
	default:
		return false, ErrState
	}
	if len(data) == 0 || len(data) > MaxBatch || !jsoncheck.UniqueControlFields(data) {
		return false, ErrState
	}
	var envelope struct {
		Objects []map[string]json.RawMessage `json:"nftables"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || envelope.Objects == nil || len(envelope.Objects) > 16 {
		return false, ErrState
	}
	seen := map[string]bool{}
	found := false
	for i, object := range envelope.Objects {
		if len(object) != 1 {
			return false, ErrState
		}
		if meta, ok := object["metainfo"]; ok && i == 0 {
			var metadata map[string]any
			decoder := json.NewDecoder(bytes.NewReader(meta))
			decoder.UseNumber()
			if decoder.Decode(&metadata) != nil || len(metadata) != 3 || !nftengine.ValidMetainfo(metadata) {
				return false, ErrState
			}
			continue
		}
		var descriptor map[string]json.RawMessage
		if raw, ok := object["table"]; !ok || json.Unmarshal(raw, &descriptor) != nil {
			return false, ErrState
		}
		var family, tableName string
		if json.Unmarshal(descriptor["family"], &family) != nil || json.Unmarshal(descriptor["name"], &tableName) != nil || len(tableName) == 0 || len(tableName) > 256 {
			return false, ErrState
		}
		switch family {
		case "inet", "ip", "ip6", "arp", "bridge", "netdev":
		default:
			return false, ErrState
		}
		key := family + ":" + tableName
		if seen[key] {
			return false, ErrState
		}
		seen[key] = true
		if family == "inet" && tableName == name {
			found = true
		}
	}
	return found, nil
}
