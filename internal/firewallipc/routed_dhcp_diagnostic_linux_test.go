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
