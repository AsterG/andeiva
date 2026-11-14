//go:build linux && !andeiva_native_dhcp_diagnostics

package previewruntime

func registerNativeDHCPDiagnosticV4(*RoutedDHCPOwnerV3) {}
