//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

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
