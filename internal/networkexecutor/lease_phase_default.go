//go:build !linux || !andeiva_native_dhcp_diagnostics

package networkexecutor

// Native qualification has no emitter, mutable switch or periodic work in a
// regular appliance build.
func EnableNativeLeasePhaseEvidenceV4()        {}
func nativeLeasePhaseV4(string, uint64, int64) {}

func StartNativeLeaseSpanV4(string) func() { return nil }

func RecordNativeLeaseHookV4(uint64, int64, uint32) {}
