//go:build linux && andeiva_native_dhcp_diagnostics

package networkexecutor

import (
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

var nativeLeasePhasesEnabledV4 atomic.Bool
var nativeLeasePhaseCountV4 atomic.Uint32
var nativeLeaseSpanCountV4 atomic.Uint32
var nativeLeaseSpanClosedV4 atomic.Bool
var nativeLeaseHookEpochV4 atomic.Uint64

func RecordNativeLeaseHookV4(epoch uint64, hookBootNS int64, seconds uint32) {
	if !nativeLeasePhasesEnabledV4.Load() || epoch == 0 || hookBootNS <= 0 || seconds == 0 {
		return
	}
	for {
		last := nativeLeaseHookEpochV4.Load()
		if epoch <= last {
			return
		}
		if nativeLeaseHookEpochV4.CompareAndSwap(last, epoch) {
			break
		}
	}
	raw, err := json.Marshal(struct {
		PID          int    `json:"pid"`
		Epoch        uint64 `json:"epoch"`
		HookBootNS   int64  `json:"hook_boot_ns"`
		LeaseSeconds uint32 `json:"lease_seconds"`
	}{os.Getpid(), epoch, hookBootNS, seconds})
	if err == nil {
		_, _ = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_LEASE_HOOK_V4 %s\n", raw)
	}
}

// Enabled only by the native test factory in a diagnostic-tagged test binary.
// It grants no authority and never changes clocks, lease state or error paths.
func EnableNativeLeasePhaseEvidenceV4() { nativeLeasePhasesEnabledV4.Store(true) }

// Diagnostic-only nested spans. They neither authorize operations nor change
// their budgets. Count and names are fixed; absence/truncation invalidates data.
func StartNativeLeaseSpanV4(phase string) func() {
	if !nativeLeasePhasesEnabledV4.Load() {
		return nil
	}
	switch phase {
	case "renew_total", "runtime_close", "current_evidence", "selected_authority", "verify_owner", "refresh_evidence", "runtime_open", "gate_stage", "gate_open", "rpc_wait":
	default:
		return nil
	}
	// Routine live checks outside an interruption are not part of its phase
	// breakdown. Keep parent close/renew spans to include their leading edge.
	if phase != "runtime_close" && phase != "renew_total" && !nativeLeaseSpanClosedV4.Load() {
		return nil
	}
	id := nativeLeaseSpanCountV4.Add(1)
	if id > 1024 {
		return nil
	}
	var start unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &start) != nil {
		return nil
	}
	finish := func() {
		var end unix.Timespec
		if unix.ClockGettime(unix.CLOCK_BOOTTIME, &end) != nil {
			return
		}
		raw, err := json.Marshal(struct {
			PID       int    `json:"pid"`
			ID        uint32 `json:"id"`
			Phase     string `json:"phase"`
			Start     int64  `json:"start_boot_ns"`
			End       int64  `json:"end_boot_ns"`
			Truncated bool   `json:"truncated,omitempty"`
		}{os.Getpid(), id, phase, start.Nano(), end.Nano(), id == 1024})
		if err == nil {
			_, _ = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_LEASE_SPAN_V4 %s\n", raw)
		}
	}
	if id == 1024 {
		finish() // Publish truncation now, even if the measured call never returns.
		return nil
	}
	return finish
}

func nativeLeasePhaseV4(phase string, sequence uint64, conservativeFloor int64) {
	if !nativeLeasePhasesEnabledV4.Load() {
		return
	}
	switch phase {
	case "close_start", "closed", "open_start", "opened":
	default:
		return
	}
	if phase == "close_start" {
		nativeLeaseSpanClosedV4.Store(true)
	}
	if phase == "opened" {
		nativeLeaseSpanClosedV4.Store(false)
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return
	}
	if conservativeFloor > now.Nano() {
		conservativeFloor = 0
	}
	count := nativeLeasePhaseCountV4.Add(1)
	if count > 129 {
		return
	}
	if count == 129 {
		phase = "truncated"
	}
	raw, err := json.Marshal(struct {
		PID               int    `json:"pid"`
		BootNS            int64  `json:"boot_ns"`
		Phase             string `json:"phase"`
		Sequence          uint64 `json:"sequence"`
		ConservativeFloor int64  `json:"conservative_floor_boot_ns,omitempty"`
	}{os.Getpid(), now.Nano(), phase, sequence, conservativeFloor})
	if err == nil {
		_, _ = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_LEASE_PHASE_V4 %s\n", raw)
	}
}
