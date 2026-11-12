package previewnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type diagnosticFixture struct {
	fixture
	failAt  string
	cause   error
	calls   []string
	context context.Context
}

type diagnosticWriter func([]byte) (int, error)

func (w diagnosticWriter) Write(data []byte) (int, error) { return w(data) }

func TestLifecycleCleanupPrecedesBlockedOrFailedLog(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		t.Run(fmt.Sprint(blocked), func(t *testing.T) {
			cleaned, entered, release := make(chan struct{}), make(chan struct{}, 2), make(chan struct{})
			defer close(release)
			writer := diagnosticWriter(func([]byte) (int, error) {
				entered <- struct{}{}
				if blocked {
					<-release
				}
				return 0, syscall.EIO
			})
			var events []string
			failures := lifecycleFailures{emit: func(event string, data lifecycleDiagnostic) {
				events = append(events, event+":"+data.Code)
				_ = json.NewEncoder(writer).Encode(data)
			}}
			done := make(chan error, 1)
			go func() {
				result, cleanupErr := failures.finish("periodic_check", context.DeadlineExceeded, func() error { close(cleaned); return syscall.ENOSPC })
				failures.flush()
				if !errors.Is(result, context.DeadlineExceeded) || !errors.Is(result, syscall.ENOSPC) || !errors.Is(cleanupErr, syscall.ENOSPC) {
					done <- errors.New("logging changed original failures")
					return
				}
				done <- nil
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("log boundary not reached")
			}
			select {
			case <-cleaned:
			default:
				t.Fatal("logging preceded fixture cleanup")
			}
			if blocked {
				select {
				case <-done:
					t.Fatal("writer did not block")
				default:
				}
				// Release this writer without closing the channel a second time.
				release <- struct{}{}
				<-entered
				release <- struct{}{}
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("logging did not finish")
			}
			if !reflect.DeepEqual(events, []string{"failure:deadline", "cleanup_failure:storage_capacity"}) {
				t.Fatal(events)
			}
		})
	}
}

func (f *diagnosticFixture) check(ctx context.Context, name string) error {
	f.context = ctx
	f.calls = append(f.calls, name)
	if f.failAt == name {
		return f.cause
	}
	return nil
}
func (f *diagnosticFixture) CheckHost(ctx context.Context) error     { return f.check(ctx, "host") }
func (f *diagnosticFixture) CheckSentinel(ctx context.Context) error { return f.check(ctx, "sentinel") }
func (f *diagnosticFixture) CheckPreviewListeners(ctx context.Context) error {
	return f.check(ctx, "listeners")
}

func TestLifecycleHealthDiagnosticsPreserveCheckOrderAndCause(t *testing.T) {
	for i, check := range []string{"host", "sentinel", "listeners"} {
		t.Run(check, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := fmt.Errorf("private diagnostic content: %w", context.DeadlineExceeded)
			f := &diagnosticFixture{failAt: check, cause: cause}
			err := checkRuntimeHealth(ctx, f)
			if !errors.Is(err, cause) || !errors.Is(err, context.DeadlineExceeded) || f.context != ctx || !reflect.DeepEqual(f.calls, []string{"host", "sentinel", "listeners"}[:i+1]) {
				t.Fatal("check semantics changed", err, f.calls)
			}
			d := diagnosticFor("periodic_check", err)
			if d.Phase != "periodic_check" || d.Check != check || d.Code != "deadline" || err.Error() != ErrRuntime.Error() {
				t.Fatal("missing safe stage", d, err)
			}
			data, _ := json.Marshal(d)
			if strings.Contains(string(data), "private") {
				t.Fatal("raw error escaped")
			}
		})
	}
	f := &diagnosticFixture{}
	if err := checkRuntimeHealth(context.Background(), f); err != nil || len(f.calls) != 3 {
		t.Fatal("healthy check changed", err)
	}
}

func TestLifecycleDiagnosticsAreAllowlistedAndBounded(t *testing.T) {
	for _, sample := range []struct {
		err  error
		code string
	}{
		{context.Canceled, "canceled"}, {ErrRecovery, "recovery_required"}, {syscall.ENOSPC, "storage_capacity"}, {syscall.EDQUOT, "storage_capacity"},
		{&fixtureFailure{check: "host", cause: errors.New("ANDEIVA_NFT_HOST_BASELINE_CHANGED: private-route-key")}, "baseline_changed"},
		{&fixtureFailure{check: "/private/path", cause: errors.New("secret")}, "rejected"},
	} {
		d := diagnosticFor("untrusted-phase-secret", sample.err)
		if d.Phase != "unknown" || d.Code != sample.code {
			t.Fatal(d)
		}
		data, _ := json.Marshal(d)
		if strings.Contains(string(data), "secret") || strings.Contains(string(data), "private") {
			t.Fatal("unbounded diagnostic", string(data))
		}
	}
	var events []string
	f := lifecycleFailures{emit: func(event string, d lifecycleDiagnostic) { events = append(events, event+":"+d.Code) }}
	f.primary("periodic_check", &fixtureFailure{check: "host", cause: context.DeadlineExceeded})
	f.cleanup(syscall.ENOSPC)
	f.primary("cleanup", errors.Join(context.DeadlineExceeded, syscall.ENOSPC))
	f.cleanup(syscall.ENOSPC)
	f.flush()
	f.flush()
	if !reflect.DeepEqual(events, []string{"failure:deadline", "cleanup_failure:storage_capacity"}) {
		t.Fatal("primary replaced or unbounded events", events)
	}
	events = nil
	f = lifecycleFailures{emit: func(event string, d lifecycleDiagnostic) { events = append(events, event) }}
	f.primary("control_accept", nil)
	f.cleanup(syscall.ENOSPC)
	f.primary("control_accept", syscall.ENOSPC)
	f.flush()
	if !reflect.DeepEqual(events, []string{"cleanup_failure"}) {
		t.Fatal("cleanup fabricated primary", events)
	}
}
