package routedactivation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/routednft"
)

func TestTablePresenceRequiresCompleteUniqueObservation(t *testing.T) {
	for table, name := range map[Table]string{LegacyTable: firewallnft.TableName, RoutedTable: routednft.TableName, LocalTable: localnft.TableName} {
		listing := []byte(fmt.Sprintf(`{"nftables":[{"metainfo":{"version":"fixture","release_name":"fixture","json_schema_version":1}},{"table":{"family":"inet","name":%q,"handle":1}}]}`, name))
		if found, err := TablePresence(listing, table); err != nil || !found {
			t.Fatal("complete presence rejected", table, err)
		}
		if found, err := TablePresence([]byte(`{"nftables":[]}`), table); err != nil || found {
			t.Fatal("successful absence rejected", table, err)
		}
		otherFamily := []byte(fmt.Sprintf(`{"nftables":[{"table":{"family":"ip","name":%q}}]}`, name))
		if found, err := TablePresence(otherFamily, table); err != nil || found {
			t.Fatal("different family became owned presence", table, err)
		}
	}
	for _, invalid := range []string{
		"", `{}`, `{"nftables":null}`, `{"nftables":[]} {}`, `{"NFTABLES":[]}`,
		`{"nftables":[],"nftables":[]}`, `{"nftables":[{"metainfo":{}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"a","name":"b"}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"a","Name":"b"}}]}`,
		`{"nftables":[{"table":{"family":"invented","name":"a"}}]}`,
		`{"nftables":[{"table":{"family":"inet","name":"a"}},{"table":{"family":"inet","name":"a"}}]}`,
		`{"nftables":[{"chain":{"family":"inet"}}]}`, strings.Repeat(" ", MaxBatch+1),
	} {
		if found, err := TablePresence([]byte(invalid), RoutedTable); err == nil || found {
			t.Fatal("invalid observation became absence or presence")
		}
	}
	if _, err := TablePresence([]byte(`{"nftables":[]}`), Table(255)); err == nil {
		t.Fatal("unknown table enum accepted")
	}
}
