//go:build !linux || !andeiva_native_dhcp_diagnostics

package firewallipc

import (
	"io"
	"time"
)

func RoutedDHCPDiagnosticStartV1(string) time.Time                         { return time.Time{} }
func RecordRoutedDHCPDiagnosticV1(string, string, time.Time, error, error) {}
func FlushRoutedDHCPDiagnosticsV1(io.Writer) error                         { return nil }
