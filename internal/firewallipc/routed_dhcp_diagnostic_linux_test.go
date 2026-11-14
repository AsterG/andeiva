//go:build linux && andeiva_native_dhcp_diagnostics

package firewallipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRoutedDHCPDiagnosticFixedBoundAndRedaction(t *testing.T) {
	d := &routedDHCPDiagnosticRecorderV1{}
	for i := 0; i < 100; i++ {
		d.record("helper", "dhcp_apply", time.Now(), errors.New("private path/address/payload"), context.DeadlineExceeded)
	}
	var out bytes.Buffer
	if err := d.flush(&out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 64 || out.Len() > 32<<10 || strings.Contains(out.String(), "private") {
		t.Fatal("unbounded or raw diagnostic")
	}
	for i, line := range lines {
		raw, ok := strings.CutPrefix(line, "ANDEIVA_NATIVE_DHCP_RPC ")
		if !ok || len(line)+1 > 512 {
			t.Fatal("record bound")
		}
		var r routedDHCPDiagnosticRecordV1
		if json.Unmarshal([]byte(raw), &r) != nil {
			t.Fatal("invalid record")
		}
		if i < 63 && (r.Side != "helper" || r.Verb != "dhcp_apply" || r.Error != "other" || r.Context != "deadline" || r.BootNS <= 0) {
			t.Fatal(r)
		}
		if i == 63 && (!r.Truncated || r.Dropped != 37 || r.Verb != "") {
			t.Fatal("missing drops", r)
		}
	}
	before := out.Len()
	if err := d.flush(&out); err != nil || out.Len() != before {
		t.Fatal("flush replayed")
	}
}

func TestRoutedDHCPDiagnosticTryLockAndEnums(t *testing.T) {
	d := &routedDHCPDiagnosticRecorderV1{}
	d.mu.Lock()
	// This call must return on the same goroutine while its mutex is held.
	d.record("client", "dhcp_open", time.Now(), nil, nil)
	d.mu.Unlock()
	d.record("private-side", "dhcp_open", time.Now(), nil, nil)
	d.record("client", "private-verb", time.Now(), nil, nil)
	d.record("client", "dhcp_open", time.Time{}, nil, nil)
	if d.count != 0 || d.dropped.Load() != 1 {
		t.Fatal("blocking or unvalidated recorder")
	}
	if !RoutedDHCPDiagnosticStartV1("private-verb").IsZero() {
		t.Fatal("unselected verb measured")
	}
	var out bytes.Buffer
	if err := d.flush(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "private") || !strings.Contains(out.String(), `"dropped":1`) {
		t.Fatal("contention not declared")
	}
}

func TestRoutedDHCPDiagnosticFailureStagesShareBound(t *testing.T) {
	d := &routedDHCPDiagnosticRecorderV1{}
	d.failure("private-stage", ErrChannel, nil)
	d.failure("open_state", nil, nil)
	if d.count != 0 {
		t.Fatal("unknown stage or successful check recorded")
	}
	d.mu.Lock()
	d.failure("open_gate_stage", ErrChannel, nil)
	d.mu.Unlock()
	for i := 0; i < 40; i++ {
		d.record("helper", "dhcp_open", time.Now(), ErrChannel, nil)
		d.failure("authority_policy", errors.New("private path/hash/address"), context.DeadlineExceeded)
	}
	var out bytes.Buffer
	if err := d.flush(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "\n") != 64 || out.Len() > 32<<10 || strings.Contains(out.String(), "private") || !strings.Contains(out.String(), `"dropped":18`) {
		t.Fatal("stage recorder escaped shared capacity/redaction")
	}
	if !strings.Contains(out.String(), `"side":"helper_stage","stage":"authority_policy"`) {
		t.Fatal("missing fixed failure stage")
	}
}

type blockedDiagnosticWriterV1 struct{ entered, release chan struct{} }

func (w blockedDiagnosticWriterV1) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(p), nil
}
func TestRoutedDHCPDiagnosticFlushIOOutsideRecorder(t *testing.T) {
	d := &routedDHCPDiagnosticRecorderV1{}
	d.record("client", "dhcp_begin", time.Now(), ErrRoutedDHCPWaitingV1, nil)
	w := blockedDiagnosticWriterV1{make(chan struct{}), make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- d.flush(w) }()
	<-w.entered
	if !d.mu.TryLock() {
		close(w.release)
		<-done
		t.Fatal("flush held recorder lock during blocked I/O")
	}
	d.mu.Unlock()
	d.record("client", "dhcp_apply", time.Now(), nil, nil)
	close(w.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d.count != 1 {
		t.Fatal("record accepted after flush")
	}
}

type shortDiagnosticWriterV1 struct{}

func (shortDiagnosticWriterV1) Write([]byte) (int, error) { return 0, nil }
func TestRoutedDHCPDiagnosticFlushFailure(t *testing.T) {
	d := &routedDHCPDiagnosticRecorderV1{}
	d.record("helper", "dhcp_apply", time.Now(), ErrChannel, nil)
	if err := d.flush(shortDiagnosticWriterV1{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("lost trace silently accepted", err)
	}
}

func TestRoutedDHCPDiagnosticRetainsFirstFailureAfterSaturation(t *testing.T) {
	for _, stage := range []bool{false, true} {
		d := &routedDHCPDiagnosticRecorderV1{}
		for i := 0; i < routedDHCPDiagnosticCapacityV1; i++ {
			d.record("helper", "dhcp_begin", time.Now(), ErrRoutedDHCPWaitingV1, nil)
		}
		d.record("helper", "dhcp_live", time.Now(), nil, nil)
		if stage {
			d.failure("policy_observe", ErrChannel, context.DeadlineExceeded)
		} else {
			d.record("helper", "dhcp_live", time.Now(), ErrChannel, context.DeadlineExceeded)
		}
		d.failure("close_gate", errors.New("later private failure"), nil)
		d.record("helper", "dhcp_live", time.Now(), nil, nil)
		if d.count != routedDHCPDiagnosticCapacityV1 || d.dropped.Load() != 4 {
			t.Fatal("changed capacity or lost eviction accounting", d.count, d.dropped.Load())
		}
		last := d.records[d.count-1]
		if last.Error != "channel" || last.Context != "deadline" || (stage && last.Stage != "policy_observe") || (!stage && last.Verb != "dhcp_live") {
			t.Fatal("first real failure lost", last)
		}
		for _, r := range d.records[:d.count-1] {
			if r.Error != "initial_waiting_v1" {
				t.Fatal("earlier trace overwritten", r)
			}
		}
	}
}

func TestRoutedDHCPDiagnosticDoesNotReplaceEarlierFailure(t *testing.T) {
	d := &routedDHCPDiagnosticRecorderV1{}
	d.failure("open_state", ErrChannel, nil)
	for i := 1; i < routedDHCPDiagnosticCapacityV1; i++ {
		d.record("helper", "dhcp_live", time.Now(), nil, nil)
	}
	d.failure("close_gate", context.Canceled, context.Canceled)
	if d.records[0].Stage != "open_state" || d.records[d.count-1].Error != "ok" || d.dropped.Load() != 1 {
		t.Fatal("later failure replaced original trace")
	}
}
