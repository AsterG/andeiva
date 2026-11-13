package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutedRebootScopeV4NegotiatesSeparateProfile(t *testing.T) {
	for _, dhcp := range []bool{false, true} {
		h := NewRoutedHelloV3(strings.Repeat("a", 32), 200)
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedIntegrityCapabilityV3, RoutedInventoryCapabilityV3)
		if dhcp {
			h.RequiredFeatures = append(h.RequiredFeatures, RoutedDHCPCapabilityV3)
		}
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedRebootScopeCapabilityV4)
		raw, _ := json.Marshal(h)
		got, err := DecodeRoutedHelloV3(raw, false)
		if err != nil || !got.HasCapability(RoutedRebootScopeCapabilityV4) || got.HasCapability(RoutedFreshScopeCapabilityV3) {
			t.Fatal("v4 profile", err)
		}
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedFreshScopeCapabilityV3)
		raw, _ = json.Marshal(h)
		if _, err = DecodeRoutedHelloV3(raw, false); err == nil {
			t.Fatal("mixed v3/v4 profile accepted")
		}
	}
}

func TestRoutedRebootScopeV4RequestCannotSupplyBootOrProof(t *testing.T) {
	run := strings.Repeat("a", 32)
	for _, extra := range []string{"", `,"new_boot":true`, `,"old":{}`, `,"observed_at_new_boot_ns":1`, `,"evidence":{}`} {
		r := RoutedRequestV3{ProtocolVersion: 3, Run: run, Sequence: 1, Namespace: 200, Domain: "routed", Verb: "reboot_scope", Payload: json.RawMessage(`{"work":"` + strings.Repeat("b", 64) + `"` + extra + `}`)}
		raw, _ := json.Marshal(r)
		_, _, err := DecodeRoutedRequestV3(raw, run, 200, 0)
		if (err == nil) != (extra == "") {
			t.Fatal("unexpected request authority", extra, err)
		}
	}
}
