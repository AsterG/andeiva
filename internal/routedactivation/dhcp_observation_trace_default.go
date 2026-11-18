//go:build !linux || !andeiva_native_dhcp_diagnostics

package routedactivation

func nativeDHCPObservationFailureV4(string)     {}
func nativeDHCPObservationTableFailureV4(Table) {}
