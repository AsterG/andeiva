package previewruntime

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type integrityWakeServiceV4 struct {
	publications chan struct{}
	inspect      func(context.Context) error
}

func (s *integrityWakeServiceV4) IntegrityPublicationsV1() <-chan struct{}   { return s.publications }
func (s *integrityWakeServiceV4) InspectRuntimeV1(ctx context.Context) error { return s.inspect(ctx) }

func TestRoutedIntegrityWakeV4BypassesSuppressionAndDrainsShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		service := &integrityWakeServiceV4{publications: make(chan struct{}, 1), inspect: func(context.Context) error { calls.Add(1); return ErrUnavailable }}
		scheduler := startRoutedIntegritySchedulerV3(service)
		service.publications <- struct{}{}
		synctest.Wait()
		for range 100 {
			select {
			case service.publications <- struct{}{}:
			default:
			}
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("failed publications created an inspection loop")
		}
		if !scheduler.WakeV4() {
			t.Fatal("active scheduler refused proof wake")
		}
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("proof wake did not bypass suppression")
		}
		scheduler.Close()
		if scheduler.WakeV4() || calls.Load() != 2 {
			t.Fatal("shutdown accepted work")
		}
	})
}

func TestRoutedIntegrityWakeV4DuringInspectionCoalesces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		service := &integrityWakeServiceV4{publications: make(chan struct{}, 1)}
		service.inspect = func(ctx context.Context) error {
			if calls.Add(1) == 1 {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
			return ErrUnavailable
		}
		scheduler := startRoutedIntegritySchedulerV3(service)
		defer scheduler.Close()
		service.publications <- struct{}{}
		<-entered
		for range 100 {
			if !scheduler.WakeV4() {
				t.Fatal("active scheduler refused wake")
			}
		}
		close(release)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("wake during inspection was lost or not coalesced", calls.Load())
		}
	})
}
