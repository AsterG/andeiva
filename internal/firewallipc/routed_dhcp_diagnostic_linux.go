//go:build linux && andeiva_native_dhcp_diagnostics

package firewallipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

const routedDHCPDiagnosticCapacityV1 = 63

type routedDHCPDiagnosticRecordV1 struct {
	Side      string `json:"side,omitempty"`
	Verb      string `json:"verb,omitempty"`
	Stage     string `json:"stage,omitempty"`
	BootNS    int64  `json:"boot_ns,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	Context   string `json:"context,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Dropped   uint64 `json:"dropped,omitempty"`
}
type routedDHCPDiagnosticRecorderV1 struct {
	mu      sync.Mutex
	records [routedDHCPDiagnosticCapacityV1]routedDHCPDiagnosticRecordV1
	count   int
	closed  bool
	dropped atomic.Uint64
}

var routedDHCPDiagnosticsV1 routedDHCPDiagnosticRecorderV1

// Default artifacts do not read clocks or allocate a diagnostic recorder.
func RoutedDHCPDiagnosticStartV1(verb string) time.Time {
	if !RoutedDHCPVerbV3(verb) {
		return time.Time{}
	}
	return time.Now()
}

func routedDHCPDiagnosticClassV1(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, ErrChannel):
		return "channel"
	case errors.Is(err, ErrRoutedDHCPWaitingV1):
		return "initial_waiting_v1"
	case errors.Is(err, configpoc.ErrRecovery):
		return "recovery"
	case errors.Is(err, configpoc.ErrConflict):
		return "conflict"
	case errors.Is(err, configpoc.ErrStorage):
		return "storage"
	case errors.Is(err, networkexecutor.ErrLeaseUnavailable):
		return "lease_unavailable"
	case errors.Is(err, networkexecutor.ErrObservation):
		return "observation"
	case errors.Is(err, networkexecutor.ErrUncertain):
		return "uncertain"
	case errors.Is(err, networkexecutor.ErrScope):
		return "scope"
	default:
		return "other"
	}
}

// Record performs no I/O and never waits for the recorder. Arguments are local
// observations only; no protocol payload or caller-selected metadata is stored.
func RecordRoutedDHCPDiagnosticV1(side, verb string, started time.Time, err, ctxErr error) {
	routedDHCPDiagnosticsV1.record(side, verb, started, err, ctxErr)
}

// Stages describe local failure sites, not another request or a grant. Nested
// gate verification therefore carries no invented RPC verb.
func RecordRoutedDHCPFailureV1(stage string, err error, ctx context.Context) {
	if ctx == nil {
		return
	}
	routedDHCPDiagnosticsV1.failure(stage, err, ctx.Err())
}

func KnownRoutedDHCPFailureStageV1(stage string) bool {
	switch stage {
	case "open_state", "open_selected", "open_owner", "open_gate_stage", "open_gate_open", "open_forward",
		"withdraw_close", "withdraw_selected", "withdraw_build_gate", "withdraw_recover_gate", "withdraw_recover_lease", "withdraw_lease", "withdraw_verify",
		"authority_selected", "authority_owner", "authority_lease", "authority_policy", "authority_owner_after",
		"policy_ready", "policy_observe", "policy_state", "close_gate", "close_forward":
		return true
	}
	return false
}

func (d *routedDHCPDiagnosticRecorderV1) failure(stage string, err, ctxErr error) {
	if err == nil || !KnownRoutedDHCPFailureStageV1(stage) {
		return
	}
	d.append("helper_stage", "", stage, time.Now(), err, ctxErr)
}

func (d *routedDHCPDiagnosticRecorderV1) record(side, verb string, started time.Time, err, ctxErr error) {
	if (side != "client" && side != "helper") || !RoutedDHCPVerbV3(verb) || started.IsZero() {
		return
	}
	d.append(side, verb, "", started, err, ctxErr)
}

func (d *routedDHCPDiagnosticRecorderV1) append(side, verb, stage string, started time.Time, err, ctxErr error) {
	if !d.mu.TryLock() {
		d.dropped.Add(1)
		return
	}
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	if d.count == len(d.records) {
		d.dropped.Add(1)
		return
	}
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		d.dropped.Add(1)
		return
	}
	d.records[d.count] = routedDHCPDiagnosticRecordV1{Side: side, Verb: verb, Stage: stage, BootNS: now.Nano(), ElapsedMS: time.Since(started).Milliseconds(), Error: routedDHCPDiagnosticClassV1(err), Context: routedDHCPDiagnosticClassV1(ctxErr)}
	d.count++
}

// Flush is called only after the fixed native API/helper role returns. The
// native call site fixes stderr; neither production RPC nor an API calls it.
func FlushRoutedDHCPDiagnosticsV1(out io.Writer) error { return routedDHCPDiagnosticsV1.flush(out) }
func (d *routedDHCPDiagnosticRecorderV1) flush(out io.Writer) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	records, count := d.records, d.count
	d.closed = true
	dropped := d.dropped.Load()
	d.mu.Unlock()
	if out == nil {
		return ErrChannel
	}
	write := func(record routedDHCPDiagnosticRecordV1) error {
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		line := append([]byte("ANDEIVA_NATIVE_DHCP_RPC "), raw...)
		line = append(line, '\n')
		if len(line) > 512 {
			return ErrChannel
		}
		n, err := out.Write(line)
		if err == nil && n != len(line) {
			err = io.ErrShortWrite
		}
		return err
	}
	for i := 0; i < count; i++ {
		if err := write(records[i]); err != nil {
			return err
		}
	}
	if dropped != 0 {
		return write(routedDHCPDiagnosticRecordV1{Truncated: true, Dropped: dropped})
	}
	return nil
}
