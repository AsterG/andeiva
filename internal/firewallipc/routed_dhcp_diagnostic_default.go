//go:build !linux || !andeiva_native_dhcp_diagnostics

package firewallipc

import (
	"context"
	"io"
	"time"
)

func RoutedDHCPDiagnosticStartV1(string) time.Time                         { return time.Time{} }
func RecordRoutedDHCPDiagnosticV1(string, string, time.Time, error, error) {}
func RecordRoutedDHCPFailureV1(string, error, context.Context)             {}
func KnownRoutedDHCPFailureStageV1(string) bool                            { return false }
func FlushRoutedDHCPDiagnosticsV1(io.Writer) error                         { return nil }
