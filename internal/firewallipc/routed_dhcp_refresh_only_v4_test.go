package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutedDHCPRefreshOnlyIsRenewalOnly(t *testing.T) {
	work, snapshot := strings.Repeat("b", 64), strings.Repeat("c", 64)
	for _, mode := range []bool{false, true} {
		p := RoutedDHCPRequestV3{Work: work, Snapshot: snapshot, RefreshOnly: mode}
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeRoutedDHCPRequestV3("dhcp_renew", raw)
		if err != nil || got != p {
			t.Fatal("closed-only refresh rejected", got, err)
		}
	}
	for _, verb := range []string{"dhcp_current", "dhcp_begin", "dhcp_retire", "dhcp_open", "dhcp_live", "dhcp_apply", "dhcp_verify", "dhcp_withdraw"} {
		raw := []byte(`{"work":"` + work + `","snapshot":"` + snapshot + `","refresh_only":true}`)
		if _, err := decodeRoutedDHCPRequestV3(verb, raw); err == nil {
			t.Fatal("flag accepted outside renewal", verb)
		}
	}
	for _, invalid := range []string{"null", `"true"`, "1", "{}"} {
		raw := []byte(`{"work":"` + work + `","snapshot":"` + snapshot + `","refresh_only":` + invalid + `}`)
		if _, err := decodeRoutedDHCPRequestV3("dhcp_renew", raw); err == nil {
			t.Fatal("invalid flag accepted", invalid)
		}
	}
	// An older exact decoder rejects the new optional member, before dispatch.
	var legacy struct{ Work, Snapshot string }
	raw := []byte(`{"work":"` + work + `","snapshot":"` + snapshot + `","refresh_only":true}`)
	if exactRoutedV3(raw, &legacy, []string{"work", "snapshot"}) == nil {
		t.Fatal("legacy peer accepted new flag")
	}
}
