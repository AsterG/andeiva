//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type nativeDHCPB2ObservationContextV2 struct {
	context.Context
	checked func()
}

func (c nativeDHCPB2ObservationContextV2) Err() error {
	err := c.Context.Err()
	c.checked()
	return err
}

func TestNativeDHCPB2ObserverV2QueuesAndChecksCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{
		{name: "observes_after_busy_holder"},
		{name: "canceled_wait_skips_observation", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent, cancel := context.WithCancel(t.Context())
			defer cancel()
			checked := make(chan struct{})
			ctx := nativeDHCPB2ObservationContextV2{parent, sync.OnceFunc(func() { close(checked) })}
			controller := &RoutedDHCPControllerV3{}
			controller.mu.Lock()
			unlock := sync.OnceFunc(controller.mu.Unlock)
			defer unlock()

			type observation struct {
				fresh bool
				err   error
				calls int
			}
			result := make(chan observation, 1)
			want := errors.New("first Live failed")
			go func() {
				calls := 0
				fresh, err := nativeDHCPB2ObserveControllerV2(ctx, controller, func() (bool, error) {
					calls++
					if controller.mu.TryLock() {
						controller.mu.Unlock()
						return false, errors.New("observation ran without the controller mutex")
					}
					return true, want
				})
				result <- observation{fresh, err, calls}
			}()
			select {
			case <-checked:
			case <-time.After(5 * time.Second):
				t.Fatal("observer never started")
			}
			select {
			case got := <-result:
				t.Fatalf("observer skipped the occupied lane: %+v", got)
			case <-time.After(20 * time.Millisecond):
			}
			if tc.cancel {
				cancel()
			}
			unlock()
			select {
			case got := <-result:
				if tc.cancel {
					if got.fresh || !errors.Is(got.err, context.Canceled) || got.calls != 0 {
						t.Fatalf("canceled waiter observed the controller: %+v", got)
					}
				} else if !got.fresh || !errors.Is(got.err, want) || got.calls != 1 {
					t.Fatalf("queued observation lost the first Live result: %+v", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("observer did not return after the lane was released")
			}
			if !controller.mu.TryLock() {
				t.Fatal("observation kept the controller mutex")
			}
			controller.mu.Unlock()
		})
	}
}

func TestNativeDHCPB2ObserverV2SkipsAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	fresh, err := nativeDHCPB2ObserveControllerV2(ctx, &RoutedDHCPControllerV3{}, func() (bool, error) {
		t.Fatal("already canceled observer entered the lane")
		return true, nil
	})
	if fresh || !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled observer returned fresh=%v err=%v", fresh, err)
	}
}
