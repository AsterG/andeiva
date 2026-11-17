//go:build linux

package previewruntime

import (
	"context"
	"sync"
	"testing"
	"time"
)

type ownerPreflightContextV4 struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *ownerPreflightContextV4) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestRoutedDHCPV4OwnerCancelledBeforeRequestKeepsLiveChannel(t *testing.T) {
	for _, mode := range []string{"already-cancelled", "expired-deadline", "gate-contention"} {
		t.Run(mode, func(t *testing.T) {
			x := newRoutedDeferredTestV4(t)
			_, lease := routedDeferredFixtureV4(t)
			x.send(t, 1, "activate", nil)
			event := x.event(t, "acquiring")
			x.send(t, 2, "confirm", event.Acquisition)
			x.event(t, "active")
			first, err := x.reader.Current(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			requests := x.reader.reader.request
			for range 32 {
				ctx, cancel := context.WithCancel(context.Background())
				if mode == "expired-deadline" {
					cancel()
					ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				}
				done := make(chan error, 1)
				if mode == "gate-contention" {
					x.reader.reader.gate <- struct{}{}
					observed := &ownerPreflightContextV4{Context: ctx, checked: make(chan struct{})}
					go func() { _, err := x.reader.Current(observed); done <- err }()
					<-observed.checked // Initial Err was sampled while the parent was live.
					cancel()
					<-x.reader.reader.gate
				} else {
					cancel()
					go func() { _, err := x.reader.Current(ctx); done <- err }()
				}
				if err := <-done; err == nil {
					t.Fatal("cancelled call supplied authority")
				}
				if x.reader.reader.dead || x.reader.reader.request != requests {
					t.Fatal("preflight cancellation closed the live owner or consumed a frame")
				}
			}
			lease.Epoch++
			lease.Event.BootNS += int64(time.Second)
			x.now.Add(int64(time.Second))
			x.source.set(lease, nil)
			next, err := x.reader.Current(context.Background())
			if err != nil || next.Epoch != lease.Epoch || next.Fact.Sequence <= first.Fact.Sequence || x.reader.reader.request != requests+1 {
				t.Fatal("fresh evidence unavailable after preflight cancellation", err)
			}
			x.send(t, 3, "stop", nil)
			x.event(t, "stopped")
			x.finish(t, true)
		})
	}
}
