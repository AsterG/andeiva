package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutedDHCPV3RequiresCapabilityAndRejectsAuthorityFields(t *testing.T) {
	h := NewRoutedHelloV3(strings.Repeat("a", 32), 22)
	h.RequiredFeatures = append(h.RequiredFeatures, RoutedIntegrityCapabilityV3, RoutedInventoryCapabilityV3, RoutedDHCPCapabilityV3)
	b, _ := json.Marshal(h)
	if _, err := DecodeRoutedHelloV3(b, false); err != nil {
		t.Fatal(err)
	}
	h.RequiredFeatures[3], h.RequiredFeatures[5] = h.RequiredFeatures[5], h.RequiredFeatures[3]
	b, _ = json.Marshal(h)
	if _, err := DecodeRoutedHelloV3(b, false); err == nil {
		t.Fatal("capability reorder accepted")
	}
	for _, verb := range []string{"dhcp_apply", "dhcp_open", "dhcp_withdraw", "dhcp_live"} {
		p := map[string]any{"work": strings.Repeat("b", 64)}
		wire := routedWireV3(t, verb, p)
		if _, _, err := DecodeRoutedRequestV3(wire, strings.Repeat("a", 32), 22, 6); err != nil {
			t.Fatal(verb, err)
		}
		for _, field := range []string{"owner", "owner_pid", "start_ticks", "epoch", "deadline_boot_ns", "route", "command", "namespace", "valid"} {
			p[field] = 1
			if _, _, err := DecodeRoutedRequestV3(routedWireV3(t, verb, p), strings.Repeat("a", 32), 22, 6); err == nil {
				t.Fatal("authority field accepted", verb, field)
			}
			delete(p, field)
		}
		if _, _, err := DecodeRoutedRequestV3(wire, strings.Repeat("a", 32), 22, 7); err == nil {
			t.Fatal("replay")
		}
	}
	for _, verb := range []string{"dhcp_begin", "dhcp_current", "dhcp_retire"} {
		if _, _, err := DecodeRoutedRequestV3(routedWireV3(t, verb, struct{}{}), strings.Repeat("a", 32), 22, 6); err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecodeRoutedRequestV3(routedWireV3(t, verb, map[string]bool{"valid": true}), strings.Repeat("a", 32), 22, 6); err == nil {
			t.Fatal("caller proof")
		}
	}
}
