//go:build linux && andeiva_native_dhcp_diagnostics

package networkexecutor

import (
	"context"
	"encoding/json"
	"errors"
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
var nativeLeaseGateFirstFenceV4 atomic.Bool
var nativeLeaseGateFirstStageV4 atomic.Bool
var nativeLeaseWasOpenedV4 atomic.Bool
var nativeLeaseObservationRaceOnceV4 atomic.Bool

func NativeLeaseOpenedForDiagnosticsV4() bool {
	return nativeLeasePhasesEnabledV4.Load() && nativeLeaseWasOpenedV4.Load()
}

type nativeLeaseObservationRaceRecordV4 struct {
	PID            int    `json:"pid"`
	BootNS         int64  `json:"boot_ns"`
	Kind           string `json:"kind"`
	BeforeEpoch    uint64 `json:"before_epoch"`
	AfterEpoch     uint64 `json:"after_epoch"`
	BeforeSequence uint64 `json:"before_sequence"`
	AfterSequence  uint64 `json:"after_sequence"`
	SameOwner      bool   `json:"same_owner"`
	SameTuple      bool   `json:"same_tuple"`
	BeforeMargin   bool   `json:"before_margin"`
	AfterMargin    bool   `json:"after_margin"`
}

func nativeLeaseObservationRaceRecordForV4(before, after leaseObservationSnapshotV4) nativeLeaseObservationRaceRecordV4 {
	bOwner, aOwner := before.fact.Owner, after.fact.Owner
	if before.hasMargin {
		bOwner = before.margin.owner
	}
	if after.hasMargin {
		aOwner = after.margin.owner
	}
	// A margin hint is not a lease tuple; equality is reported only for grants.
	sameTuple := !before.hasMargin && !after.hasMargin && before.fact.DesiredHash == after.fact.DesiredHash && before.fact.WAN == after.fact.WAN && before.fact.Address == after.fact.Address && before.fact.Gateway == after.fact.Gateway
	return nativeLeaseObservationRaceRecordV4{Kind: "unstable_source", BeforeEpoch: before.epoch, AfterEpoch: after.epoch, BeforeSequence: before.fact.Sequence, AfterSequence: after.fact.Sequence, SameOwner: bOwner == aOwner, SameTuple: sameTuple, BeforeMargin: before.hasMargin, AfterMargin: after.hasMargin}
}

// Inspect only the two snapshots already consumed by the existing rejection.
func nativeLeaseObservationRaceV4(err error, before, after leaseObservationSnapshotV4) {
	if err != nil || before == after || !NativeLeaseOpenedForDiagnosticsV4() || !nativeLeaseObservationRaceOnceV4.CompareAndSwap(false, true) {
		return
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return
	}
	record := nativeLeaseObservationRaceRecordForV4(before, after)
	record.PID, record.BootNS = os.Getpid(), now.Nano()
	raw, marshalErr := json.Marshal(record)
	if marshalErr == nil {
		_, _ = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_LEASE_OBSERVATION_RACE_V4 %s\n", raw)
	}
}

func nativeLeaseGateFaultSlotV4(site string) *atomic.Bool {
	switch site {
	case "create", "fail", "close_readback", "reject":
		return &nativeLeaseGateFirstFenceV4
	case "ready", "state":
		return &nativeLeaseGateFirstStageV4
	default:
		return nil
	}
}

func nativeLeaseGateFaultCodesV4(cause error) []string {
	var codes []string
	for _, candidate := range []struct {
		err  error
		code string
	}{
		{ErrLeaseGate, "gate"}, {ErrLeaseGateUncertain, "closure_unproven"},
		{ErrLeaseGateCurrent, "current"}, {ErrLeaseGateSequence, "sequence"},
		{ErrLeaseGateAuthority, "authority"}, {ErrLeaseGateChanged, "changed"},
		{ErrLeaseGateRenewal, "renewal"}, {ErrLeaseGateMarginClosed, "margin"},
		{ErrLeaseGateExpired, "expired"}, {ErrLeaseGateDeadline, "deadline"},
		{ErrLeaseGateReady, "ready"}, {ErrLeaseGateState, "state"}, {ErrLeaseGateReadback, "readback"},
		{ErrLeaseGateContext, "context"}, {ErrLeaseGateLifetime, "lifetime"},
		{ErrLeaseGateDisposed, "disposed"}, {ErrLeaseGateFenced, "fenced"},
		{ErrLeaseGateFenceCreate, "fence_create"}, {ErrLeaseGateFenceClose, "fence_close"},
		{ErrLeaseGateFenceOperation, "fence_operation"}, {ErrLeaseGateFenceReject, "fence_reject"},
		{ErrLeaseGateFenceRecovery, "fence_recovery"}, {ErrScope, "scope"},
		{ErrObservation, "observation"}, {ErrUncertain, "uncertain"},
		{ErrLeaseUnavailable, "lease_unavailable"},
		{context.Canceled, "cancelled"}, {context.DeadlineExceeded, "context_deadline"},
	} {
		if errors.Is(cause, candidate.err) {
			codes = append(codes, candidate.code)
		}
	}
	return codes
}

// Separate reserved slots cannot be exhausted by routine RPCs or span records.
// Callers already hold the gate lock. Only fixed classifications and scalar
// state are emitted; the arbitrary error text and grant contents are never read.
func nativeLeaseGateFaultV4(site string, cause error, g *LeaseGate) {
	if !nativeLeasePhasesEnabledV4.Load() || g == nil {
		return
	}
	slot := nativeLeaseGateFaultSlotV4(site)
	if slot == nil || !slot.CompareAndSwap(false, true) {
		return
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return
	}
	raw, err := json.Marshal(struct {
		PID            int      `json:"pid"`
		BootNS         int64    `json:"boot_ns"`
		Site           string   `json:"site"`
		Codes          []string `json:"codes"`
		Seen           uint64   `json:"seen"`
		StagedSequence uint64   `json:"staged_sequence"`
		Initialized    bool     `json:"initialized"`
		Opened         bool     `json:"opened"`
		Fenced         bool     `json:"fenced"`
		Disposed       bool     `json:"disposed"`
	}{os.Getpid(), now.Nano(), site, nativeLeaseGateFaultCodesV4(errors.Join(cause, g.fenceReason)), g.seen, g.staged.Fact.Sequence, g.initialized, g.opened, g.fenced, g.disposed})
	if err == nil {
		_, _ = fmt.Fprintf(os.Stderr, "ANDEIVA_NATIVE_LEASE_GATE_FAULT_V4 %s\n", raw)
	}
}

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
	case "rule_hold_close", "rule_hold_replace", "rule_hold_release":
	default:
		return nil
	}
	// Routine live checks outside an interruption are not part of its phase
	// breakdown. Keep parent close/renew spans to include their leading edge.
	if phase != "runtime_close" && phase != "renew_total" && phase != "rule_hold_close" &&
		phase != "rule_hold_replace" && phase != "rule_hold_release" && !nativeLeaseSpanClosedV4.Load() {
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
		nativeLeaseWasOpenedV4.Store(true)
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
