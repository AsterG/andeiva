//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRoutedEffectiveContextWhileCoordinatorBusy(t *testing.T) {
	service, binding, _, _ := serviceV2Fixture(t, "admin")
	service.coordinator.store.mu.Lock()
	defer service.coordinator.store.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := service.RoutedEffective(ctx, binding); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("contention ignored context", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("read remained blocked after deadline")
	}
}
