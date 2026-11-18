//go:build linux && andeiva_native_dhcp_diagnostics

package routedactivation

import "testing"

func TestNativeDHCPObservationV4FixedSeparateSlots(t *testing.T) {
	for _, stage := range []string{"network_generic", "acquisition_network", "table_legacy", "table_routed", "table_local", "listeners_or_context", "context"} {
		if nativeDHCPObservationFailureSlotV4(stage) != &nativeDHCPPredicateOnceV4 {
			t.Fatal("predicate slot escaped bound", stage)
		}
	}
	if nativeDHCPObservationFailureSlotV4("fence_selected") != &nativeDHCPFenceOnceV4 || nativeDHCPObservationFailureSlotV4("fence_selected") == nativeDHCPObservationFailureSlotV4("network_generic") {
		t.Fatal("fence and predicate share a slot")
	}
	if nativeDHCPObservationFailureSlotV4("") != nil || nativeDHCPObservationFailureSlotV4("unknown") != nil {
		t.Fatal("unbounded stage")
	}
}
