//go:build linux && !andeiva_native_dhcp_diagnostics

package dhcpclient

import (
	"io"
	"testing"
)

func TestNativeDiagnosticDefaultDisabled(t *testing.T) {
	d, err := openClientDiagnostic()
	if err != nil || d != nil || d.stderr() != io.Discard {
		t.Fatal("ordinary build enabled native diagnostics")
	}
	d.event("event", "CARRIER", 0)
	d.leaseEvent(Event{})
	d.close()
}
