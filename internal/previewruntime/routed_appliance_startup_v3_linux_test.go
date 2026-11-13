//go:build linux

package previewruntime

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestRoutedLaunchV3StartupInspectionWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		child := &routedLaunchChildV3{events: make(chan routedLaunchEventV3, 1), done: make(chan struct{})}
		start := time.Now()
		// Model a delayed child factory: longer than the previous readiness
		// window, but within a full integrity scan plus bounded startup overhead.
		go func() {
			time.Sleep(16 * time.Second)
			child.events <- routedLaunchEventV3{Event: "api_ready", Epoch: 7}
		}()
		if err := child.waitEvent(context.Background(), "api_ready", 7); err != nil {
			t.Fatal("full inspection was constrained by effect timing", err)
		}
		if elapsed := time.Since(start); elapsed != 16*time.Second {
			t.Fatal(elapsed)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		child := &routedLaunchChildV3{events: make(chan routedLaunchEventV3), done: make(chan struct{})}
		start := time.Now()
		if err := child.waitEvent(context.Background(), "helper_ready", 0); err == nil || time.Since(start) != 45*time.Second {
			t.Fatal("startup wait is unbounded", err, time.Since(start))
		}
	})
}
