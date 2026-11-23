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
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	wakes  chan struct{}
}

func startRoutedIntegritySchedulerV3(service routedIntegrityScheduledServiceV3) *routedIntegritySchedulerV3 {
	return startRoutedIntegrityCallbackV4(service, service.InspectRuntimeV1)
}
func startRoutedIntegrityCallbackV4(service routedIntegrityScheduledServiceV3, inspect func(context.Context) error) *routedIntegritySchedulerV3 {
	ctx, cancel := context.WithCancel(context.Background())
	s := &routedIntegritySchedulerV3{ctx: ctx, cancel: cancel, done: make(chan struct{}), wakes: make(chan struct{}, 1)}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(configpoc.IntegrityInspectionIntervalV1)
		defer ticker.Stop()
		runRoutedIntegrityWakeV4(ctx, ticker.C, service.IntegrityPublicationsV1(), s.wakes, inspect)
	}()
	return s
}
func runRoutedIntegritySchedulerV3(ctx context.Context, ticks <-chan time.Time, publications <-chan struct{}, inspect func(context.Context) error) {
	runRoutedIntegrityWakeV4(ctx, ticks, publications, nil, inspect)
}

// WakeV4 queues work, never readiness. Duplicate queued requests coalesce; the
// controller separately limits requests to one per authenticated fresh proof.
func (s *routedIntegritySchedulerV3) WakeV4() bool {
	if s == nil || s.ctx.Err() != nil {
		return false
	}
	select {
	case <-s.ctx.Done():
		return false
	case s.wakes <- struct{}{}:
	default:
	}
	return true
}

func runRoutedIntegrityWakeV4(ctx context.Context, ticks <-chan time.Time, publications, wakes <-chan struct{}, inspect func(context.Context) error) {
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
				select {
				case _, ok := <-wakes:
					if !ok {
						wakes = nil
						continue
					}
				default:
					continue
				}
			}
		case _, ok := <-wakes:
			if !ok {
				wakes = nil
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		// Drain at most the one wake already queued before this inspection.
		// A wake arriving during the callback remains pending for a later pass.
		select {
		case _, ok := <-wakes:
			if !ok {
				wakes = nil
			}
		default:
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
