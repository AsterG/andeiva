//go:build !linux || !andeiva_native_dhcp_diagnostics

package networkexecutor

import "testing"

type noGateDiagnosticErrorV4 struct{}

func (noGateDiagnosticErrorV4) Error() string { panic("default diagnostic inspected error") }
func (noGateDiagnosticErrorV4) Is(error) bool { panic("default diagnostic classified error") }

func TestNativeLeaseGateDiagnosticDefaultIsNoop(t *testing.T) {
	for _, site := range []string{"create", "fail", "close_readback", "reject", "ready", "state", "unknown"} {
		nativeLeaseGateFaultV4(site, noGateDiagnosticErrorV4{}, nil)
	}
}
