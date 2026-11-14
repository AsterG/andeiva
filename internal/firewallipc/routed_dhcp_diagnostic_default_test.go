//go:build !linux || !andeiva_native_dhcp_diagnostics

package firewallipc

import (
	"context"
	"testing"
	"time"
)

type noDiagnosticWriterV1 struct{}
type noDiagnosticContextV1 struct{ context.Context }

func (noDiagnosticContextV1) Err() error { panic("default diagnostic read context") }

func (noDiagnosticWriterV1) Write([]byte) (int, error) { panic("default diagnostic performed I/O") }
func TestRoutedDHCPDiagnosticDefaultNoClockOrOutput(t *testing.T) {
	if !RoutedDHCPDiagnosticStartV1("dhcp_apply").IsZero() {
		t.Fatal("default diagnostic read clock")
	}
	RecordRoutedDHCPDiagnosticV1("client", "dhcp_apply", time.Now(), ErrChannel, nil)
	RecordRoutedDHCPFailureV1("open_gate_stage", ErrChannel, noDiagnosticContextV1{})
	if KnownRoutedDHCPFailureStageV1("open_gate_stage") {
		t.Fatal("default enabled stage diagnostics")
	}
	if err := FlushRoutedDHCPDiagnosticsV1(noDiagnosticWriterV1{}); err != nil {
		t.Fatal(err)
	}
}
