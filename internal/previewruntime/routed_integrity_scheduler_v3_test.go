package previewruntime

import (
	"context"
	"testing"
	"time"
)

func TestRoutedIntegrityV3SchedulerCoalescesAndWaitsAfterFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time, 1)
	publications := make(chan struct{}, 1)
	calls := make(chan int, 3)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n := 0
		runRoutedIntegritySchedulerV3(ctx, ticks, publications, func(context.Context) error {
			n++
			calls <- n
			if n == 1 {
				return ErrUnavailable
			}
			return nil
		})
	}()
	publications <- struct{}{}
	if n := <-calls; n != 1 {
		t.Fatal(n)
	}
	publications <- struct{}{}
	// The next synthetic minute is the only retry trigger after failure.
	ticks <- time.Now()
	if n := <-calls; n != 2 {
		t.Fatal("unexpected event retry", n)
	}
	cancel()
	<-done
	select {
	case n := <-calls:
		t.Fatal("extra inspection", n)
	default:
	}
}
func TestRoutedIntegrityV3SchedulerCancellationDrains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 1)
	entered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runRoutedIntegritySchedulerV3(ctx, ticks, nil, func(call context.Context) error { close(entered); <-call.Done(); return call.Err() })
	}()
	ticks <- time.Now()
	<-entered
	cancel()
	<-done
}
