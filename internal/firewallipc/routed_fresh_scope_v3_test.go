package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRoutedFreshScopeV3NegotiationIsIndependentAndOrdered(t *testing.T) {
	for _, dhcp := range []bool{false, true} {
		h := NewRoutedHelloV3(strings.Repeat("a", 32), 200)
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedIntegrityCapabilityV3, RoutedInventoryCapabilityV3)
		if dhcp {
			h.RequiredFeatures = append(h.RequiredFeatures, RoutedDHCPCapabilityV3)
		}
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedFreshScopeCapabilityV3)
		raw, _ := json.Marshal(h)
		got, err := DecodeRoutedHelloV3(raw, false)
		if err != nil || !got.HasCapability(RoutedFreshScopeCapabilityV3) || got.HasCapability(RoutedDHCPCapabilityV3) != dhcp {
			t.Fatal("valid profile", err)
		}
		h.RequiredFeatures = append(h.RequiredFeatures, RoutedFreshScopeCapabilityV3)
		raw, _ = json.Marshal(h)
		if _, err = DecodeRoutedHelloV3(raw, false); err == nil {
			t.Fatal("duplicate capability accepted")
		}
	}
}

func TestRoutedFreshScopeV3RequestCarriesOnlySelectedWork(t *testing.T) {
	run := strings.Repeat("a", 32)
	for _, extra := range []string{"", `,"receipt_sha256":"` + strings.Repeat("b", 64) + `"`, `,"old":{}`, `,"new":{}`, `,"proved":true`, `,"deadline":1`} {
		payload := json.RawMessage(`{"work":"` + strings.Repeat("c", 64) + `"` + extra + `}`)
		request := RoutedRequestV3{ProtocolVersion: 3, Run: run, Sequence: 1, Namespace: 200, Domain: "routed", Verb: "fresh_scope", Payload: payload}
		raw, _ := json.Marshal(request)
		_, got, err := DecodeRoutedRequestV3(raw, run, 200, 0)
		if extra == "" {
			if err != nil || got.FreshScope.Work != strings.Repeat("c", 64) {
				t.Fatal("work reference rejected", err)
			}
		} else if err == nil {
			t.Fatal("request supplied authority")
		}
	}
}
