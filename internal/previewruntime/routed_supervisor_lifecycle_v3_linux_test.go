//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRoutedSupervisorV3RetriesBeforeHandoffWithNoChild(t *testing.T) {
	for _, tc := range []struct {
		name       string
		recover    bool
		firstDelay time.Duration
	}{{"exhausted across budget window", false, 65 * time.Second}, {"recovered", true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				helperDone := make(chan struct{})
				apiDone := make(chan struct{})
				close(apiDone)
				var times []time.Time
				var diagnostic strings.Builder
				result := make(chan error, 1)
				go func() {
					result <- keepRoutedSupervisorV3(ctx, helperDone, func() <-chan struct{} { return apiDone }, func(context.Context) error {
						times = append(times, time.Now())
						apiDone = nil // startChild failed; there is no replacement writer.
						if len(times) == 1 {
							time.Sleep(tc.firstDelay)
						}
						if tc.recover && len(times) == 2 {
							apiDone = make(chan struct{})
							return nil
						}
						return errRoutedAPIStartRetryableV3
					}, &diagnostic)
				}()
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				select {
				case err := <-result:
					t.Fatal("retry stopped the helper parent", err)
				default:
				}
				cancel()
				if err := <-result; err != nil {
					t.Fatal(err)
				}
				wantAttempts, wantDiagnostic := 3, "ANDEIVA_GROUPED_API_RECOVERY_REQUIRED\n"
				if tc.recover {
					wantAttempts, wantDiagnostic = 2, ""
				}
				if len(times) != wantAttempts || diagnostic.String() != wantDiagnostic {
					t.Fatalf("attempts=%d diagnostic=%q", len(times), diagnostic.String())
				}
				for i := 1; i < len(times); i++ {
					if times[i].Sub(times[i-1]) < 3*time.Second {
						t.Fatal("retry bypassed the existing backoff")
					}
				}
			})
		})
	}
}

func TestRoutedSupervisorV3APIFailureKeepsGuardianParentAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		helperDone := make(chan struct{})
		apiDone := make(chan struct{})
		close(apiDone)
		var attempts atomic.Int32
		result := make(chan error, 1)
		go func() {
			result <- keepRoutedSupervisorV3(ctx, helperDone, func() <-chan struct{} { return apiDone }, func(context.Context) error { attempts.Add(1); return ErrUnavailable }, io.Discard)
		}()
		time.Sleep(31 * time.Second)
		if attempts.Load() != 1 {
			t.Fatal("failed writer recovery was retried tightly", attempts.Load())
		}
		select {
		case err := <-result:
			t.Fatal("API failure terminated guardian parent", err)
		default:
		}
		close(helperDone)
		if err := <-result; !errors.Is(err, ErrUnavailable) {
			t.Fatal("helper loss not reported", err)
		}
	})
}

func TestRoutedSupervisorV3RestartBudgetDegradesWithoutStoppingHelper(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		helperDone := make(chan struct{})
		apiDone := make(chan struct{})
		close(apiDone)
		var attempts atomic.Int32
		result := make(chan error, 1)
		go func() {
			result <- keepRoutedSupervisorV3(ctx, helperDone, func() <-chan struct{} { return apiDone }, func(context.Context) error { attempts.Add(1); return nil }, io.Discard)
		}()
		time.Sleep(90 * time.Second)
		if attempts.Load() != 3 {
			t.Fatal("restart budget did not latch degraded state", attempts.Load())
		}
		select {
		case err := <-result:
			t.Fatal("exhaustion killed helper parent", err)
		default:
		}
		cancel()
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
}
