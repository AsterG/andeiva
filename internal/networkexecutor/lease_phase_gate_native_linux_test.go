//go:build linux && andeiva_native_dhcp_diagnostics

package networkexecutor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type noGateDiagnosticTextV4 struct{}

func (noGateDiagnosticTextV4) Error() string { panic("diagnostic inspected arbitrary error text") }

func TestNativeLeaseGateDiagnosticFixedAllowlistAndSlotsV4(t *testing.T) {
	got := nativeLeaseGateFaultCodesV4(errors.Join(noGateDiagnosticTextV4{}, ErrLeaseGateFenced, ErrLeaseGateFenceOperation, ErrObservation, context.DeadlineExceeded))
	want := []string{"fenced", "fence_operation", "observation", "context_deadline"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if nativeLeaseGateFaultCodesV4(errors.New(strings.Repeat("secret", 100000))) != nil {
		t.Fatal("arbitrary error text became a code")
	}
	for _, site := range []string{"create", "fail", "close_readback", "reject"} {
		if nativeLeaseGateFaultSlotV4(site) != &nativeLeaseGateFirstFenceV4 {
			t.Fatal("unbounded fence slot", site)
		}
	}
	for _, site := range []string{"ready", "state"} {
		if nativeLeaseGateFaultSlotV4(site) != &nativeLeaseGateFirstStageV4 {
			t.Fatal("unbounded stage slot", site)
		}
	}
	for _, site := range []string{"", "unknown", strings.Repeat("x", 10000)} {
		if nativeLeaseGateFaultSlotV4(site) != nil {
			t.Fatal("unknown site admitted")
		}
	}
	if nativeLeaseGateFaultSlotV4("fail") == nativeLeaseGateFaultSlotV4("ready") {
		t.Fatal("first stage error consumed by fence")
	}
}
