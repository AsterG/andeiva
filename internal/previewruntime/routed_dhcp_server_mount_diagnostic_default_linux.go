//go:build linux && !andeiva_native_dhcp_diagnostics

package previewruntime

// Normal builds retain the original public error and emit no diagnostics.
func routedDHCPServerMountFailureV1(_ string, _ error, result error) error { return result }
