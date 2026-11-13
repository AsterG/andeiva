//go:build !linux || !andeiva_native_dhcp_diagnostics

package firewallipc

import (
	"testing"
	"time"
)

type noDiagnosticWriterV1 struct{}

func (noDiagnosticWriterV1) Write([]byte) (int, error) { panic("default diagnostic performed I/O") }
func TestRoutedDHCPDiagnosticDefaultNoClockOrOutput(t *testing.T) {
	if !RoutedDHCPDiagnosticStartV1("dhcp_apply").IsZero() {
		t.Fatal("default diagnostic read clock")
	}
	RecordRoutedDHCPDiagnosticV1("client", "dhcp_apply", time.Now(), ErrChannel, nil)
	if err := FlushRoutedDHCPDiagnosticsV1(noDiagnosticWriterV1{}); err != nil {
		t.Fatal(err)
	}
}
