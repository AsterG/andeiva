//go:build linux && andeiva_native_dhcp_diagnostics

package routedactivation

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

var nativeDHCPPredicateOnceV4 atomic.Bool
var nativeDHCPFenceOnceV4 atomic.Bool

func nativeDHCPObservationFailureSlotV4(stage string) *atomic.Bool {
	switch stage {
	case "network_generic", "acquisition_network", "table_legacy", "table_routed", "table_local", "listeners_or_context", "context":
		return &nativeDHCPPredicateOnceV4
	case "fence_selected":
		return &nativeDHCPFenceOnceV4
	default:
		return nil
	}
}

func nativeDHCPObservationTableFailureV4(table Table) {
	switch table {
	case LegacyTable:
		nativeDHCPObservationFailureV4("table_legacy")
	case RoutedTable:
		nativeDHCPObservationFailureV4("table_routed")
	case LocalTable:
		nativeDHCPObservationFailureV4("table_local")
	}
}

// Two fixed frames after the first verified Open; no additional predicate read.
func nativeDHCPObservationFailureV4(stage string) {
	if !networkexecutor.NativeLeaseOpenedForDiagnosticsV4() {
		return
	}
	once := nativeDHCPObservationFailureSlotV4(stage)
	if once == nil || !once.CompareAndSwap(false, true) {
		return
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return
	}
	raw, err := json.Marshal(struct {
		PID    int    `json:"pid"`
		BootNS int64  `json:"boot_ns"`
		Stage  string `json:"stage"`
	}{os.Getpid(), now.Nano(), stage})
	if err == nil {
		_, _ = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_DHCP_OBSERVE_FAILURE_V4 %s\n", raw)
	}
}
