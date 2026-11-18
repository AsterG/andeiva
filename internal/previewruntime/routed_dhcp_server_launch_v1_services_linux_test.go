//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRoutedDHCPServerServiceDestroyCanceledBeforeAttemptV1(t *testing.T) {
	for _, mode := range []string{"canceled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
			if mode == "expired" {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				cancel()
			}
			defer cancel()
			// No kernel capability is supplied: a pre-canceled invocation must
			// return before consulting or mutating any retirement resources.
			s := &RoutedDHCPServerServiceSetV1{}
			if err := s.DestroyV1(ctx); !errors.Is(err, ctx.Err()) || s.retiring || s.retireErr != nil {
				t.Fatalf("canceled invocation changed retirement: %v retiring=%t cached=%v", err, s.retiring, s.retireErr)
			}
			assertServerServiceFreshAttemptV1(t, s)
		})
	}
}

func assertServerServiceFreshAttemptV1(t *testing.T, s *RoutedDHCPServerServiceSetV1) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// A fresh invocation must reach the existing drain validation. A zero-value
	// owner deliberately lacks a real slot; this is not a native cleanup proof.
	err := s.DestroyV1(ctx)
	if !errors.Is(err, ErrIdentity) || !errors.Is(err, ErrUnavailable) || !s.retiring || s.retireErr != err {
		t.Fatalf("fresh retirement attempt was poisoned: %v retiring=%t cached=%v", err, s.retiring, s.retireErr)
	}
	canceled, stop := context.WithTimeout(context.Background(), time.Second)
	stop()
	if got := s.DestroyV1(canceled); got != err || s.retireErr != err {
		t.Fatal("an actual failed drain attempt lost its terminal result", got)
	}
}

func TestRoutedDHCPServerServiceDestroyCancelWhileWaitingMutexV1(t *testing.T) {
	s := &RoutedDHCPServerServiceSetV1{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	id := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		var own [256]byte
		line := strings.Fields(string(own[:runtime.Stack(own[:], false)]))
		id <- line[1]
		done <- s.DestroyV1(ctx)
	}()
	worker := <-id
	if _, err := strconv.ParseUint(worker, 10, 64); err != nil {
		t.Fatal(err)
	}
	// Wait for this specific worker to be blocked inside Destroy's mutex. This
	// rejects a guard placed only before Lock, without scheduling sleeps.
	deadline := time.Now().Add(3 * time.Second)
	var stacks [1 << 20]byte
	for {
		blocked := false
		for _, block := range strings.Split(string(stacks[:runtime.Stack(stacks[:], true)]), "\n\n") {
			if strings.HasPrefix(block, "goroutine "+worker+" ") && strings.Contains(block, ".DestroyV1(") && strings.Contains(block, "sync.Mutex.Lock") {
				blocked = true
			}
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not reach Destroy's mutex")
		}
		runtime.Gosched()
	}
	cancel()
	s.mu.Unlock()
	locked = false
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || s.retiring || s.retireErr != nil {
			t.Fatalf("cancellation while waiting changed retirement: %v %t %v", err, s.retiring, s.retireErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled retirement did not return")
	}
	assertServerServiceFreshAttemptV1(t, s)
}

func TestRoutedDHCPServerServiceDestroyRetainsTerminalObservationV1(t *testing.T) {
	for _, cached := range []error{nil, ErrUnavailable} {
		s := &RoutedDHCPServerServiceSetV1{retiring: true, retireErr: cached}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		cancel()
		if err := s.DestroyV1(ctx); err != cached || !s.retiring || s.retireErr != cached {
			t.Fatal("cancellation changed an already-terminal observation", err)
		}
	}
}
