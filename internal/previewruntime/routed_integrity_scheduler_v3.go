package previewruntime

import (
	"context"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type routedIntegrityScheduledServiceV3 interface {
	InspectRuntimeV1(context.Context) error
	IntegrityPublicationsV1() <-chan struct{}
}
type routedIntegritySchedulerV3 struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func startRoutedIntegritySchedulerV3(service routedIntegrityScheduledServiceV3) *routedIntegritySchedulerV3 {
	return startRoutedIntegrityCallbackV4(service, service.InspectRuntimeV1)
}
func startRoutedIntegrityCallbackV4(service routedIntegrityScheduledServiceV3, inspect func(context.Context) error) *routedIntegritySchedulerV3 {
	ctx, cancel := context.WithCancel(context.Background())
	s := &routedIntegritySchedulerV3{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(configpoc.IntegrityInspectionIntervalV1)
		defer ticker.Stop()
		runRoutedIntegritySchedulerV3(ctx, ticker.C, service.IntegrityPublicationsV1(), inspect)
	}()
	return s
}
func runRoutedIntegritySchedulerV3(ctx context.Context, ticks <-chan time.Time, publications <-chan struct{}, inspect func(context.Context) error) {
	suppress := false
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-ticks:
			if !ok {
				return
			}
			suppress = false
		case _, ok := <-publications:
			if !ok {
				publications = nil
				continue
			}
			if suppress {
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		// Coalesce only events queued before inspection. An event published after
		// the writer releases its barrier must not be lost as an already-scanned one.
		for publications != nil {
			select {
			case _, ok := <-publications:
				if !ok {
					publications = nil
				}
			default:
				goto drained
			}
		}
	drained:
		if ctx.Err() != nil {
			return
		}
		suppress = inspect(ctx) != nil
	}
}
func (s *routedIntegritySchedulerV3) Close() {
	if s != nil {
		s.cancel()
		<-s.done
	}
}
