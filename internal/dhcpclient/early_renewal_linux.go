//go:build linux

package dhcpclient

import (
	"context"
	"sync"
	"syscall"
	"time"
)

// ADR-072: these are policy budgets, not measured RTT or dispatch guarantees.
const (
	earlyTokenMargin = 3 * time.Second
	earlyResponse    = 5 * time.Second
	earlyDispatch    = time.Second
	earlyMinimum     = time.Second
	earlyWindow      = earlyTokenMargin + 2*earlyResponse + earlyDispatch
)

type earlyRenewal struct {
	mu              sync.Mutex
	wake            chan struct{}
	done            chan struct{}
	completedEpoch  uint64
	completedBootNS int64
	responseBy      int64
	pendingEpoch    uint64
}

func newEarlyRenewal() *earlyRenewal {
	return &earlyRenewal{wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func (c *Client) notifyEarlyRenewal() {
	if c.early != nil {
		select {
		case c.early.wake <- struct{}{}:
		default:
		}
	}
}

// Acceptance time is scheduler metadata, never the lower bound of a grant.
// The lock makes it coherent with the lease without changing accept semantics.
func (c *Client) acceptEvent(e Event, now int64) error {
	if c.early == nil {
		return c.accept(e, now)
	}
	c.early.mu.Lock()
	defer c.early.mu.Unlock()
	at, err := bootNow()
	if err != nil || c.early.responseBy != 0 && at >= c.early.responseBy {
		c.failAt("early_response_timeout")
		return ErrUnavailable
	}
	if err := c.accept(e, now); err != nil {
		return err
	}
	at, err = bootNow()
	if err != nil || c.early.responseBy != 0 && at >= c.early.responseBy {
		c.failAt("early_response_timeout")
		return ErrUnavailable
	}
	if granting(e.Reason) && c.early.responseBy != 0 {
		// Preserve completion of this request across later unsolicited hooks.
		c.early.completedEpoch = c.early.pendingEpoch
		c.early.completedBootNS = at
		c.early.responseBy = 0
	}
	if granting(e.Reason) {
		c.mu.Lock()
		_, safe := earlyRenewalDue(at, c.lease.DeadlineBootNS)
		c.mu.Unlock()
		if !safe {
			c.failAt("early_short_lease")
			return ErrUnavailable
		}
	}
	return nil
}

type earlyRenewalObservation struct {
	AcquisitionObservation
	completedEpoch  uint64
	completedBootNS int64
}

func (c *Client) observeEarlyRenewal(now int64) (earlyRenewalObservation, error) {
	c.early.mu.Lock()
	defer c.early.mu.Unlock()
	o, err := c.observationWithEarlyLocked(now)
	return earlyRenewalObservation{o, c.early.completedEpoch, c.early.completedBootNS}, err
}

func (c *Client) observationWithEarlyLocked(now int64) (AcquisitionObservation, error) {
	fresh, err := bootNow()
	if err != nil {
		c.failAt("early_clock")
		return AcquisitionObservation{}, ErrUnavailable
	}
	if fresh > now {
		now = fresh
	}
	if c.early.responseBy != 0 && now >= c.early.responseBy {
		c.failAt("early_response_timeout")
		return AcquisitionObservation{}, ErrUnavailable
	}
	return c.observationLeaseAt(now)
}

// No clamp-up: a short lease or a late wake must close rather than send late.
func earlyRenewalDue(now, deadline int64) (int64, bool) {
	if now <= 0 || deadline <= now || deadline-now <= int64(earlyWindow) {
		return 0, false
	}
	interval := (deadline - now - int64(earlyWindow)) / 2
	if interval < int64(earlyMinimum) {
		return 0, false
	}
	return now + interval, true
}

type earlyRenewalCycle struct {
	epoch, sentEpoch uint64
	due, responseBy  int64
}

// next returns a strictly positive delay, zero to send, or a terminal failure.
// A negative delay means there is no grant and no feature timer may run.
func (s *earlyRenewalCycle) next(o earlyRenewalObservation, now int64) (time.Duration, string) {
	if now <= 0 {
		return 0, "early_clock"
	}
	if o.State != AcquisitionGranted {
		s.due, s.responseBy = 0, 0
		return -1, ""
	}
	l := o.Lease
	if l.Epoch == 0 || l.Epoch != o.ObservedEpoch || l.DeadlineBootNS <= now || l.Epoch < s.epoch {
		return 0, "early_evidence"
	}
	if l.Epoch != s.epoch {
		if s.responseBy != 0 && (o.completedEpoch != s.sentEpoch || o.completedBootNS <= 0 || o.completedBootNS >= s.responseBy) {
			return 0, "early_response_timeout"
		}
		s.epoch, s.responseBy = l.Epoch, 0
		var ok bool
		s.due, ok = earlyRenewalDue(now, l.DeadlineBootNS)
		if !ok {
			return 0, "early_short_lease"
		}
	}
	if s.sentEpoch == l.Epoch {
		if s.responseBy <= now {
			return 0, "early_response_timeout"
		}
		return time.Duration(s.responseBy - now), ""
	}
	if s.due > now {
		return time.Duration(s.due - now), ""
	}
	if s.due <= 0 || now-s.due > int64(earlyDispatch) || l.DeadlineBootNS-now <= int64(earlyTokenMargin+2*earlyResponse) {
		return 0, "early_dispatch_late"
	}
	return 0, ""
}

// Only the fixed producer is signalled. Holding mu makes epoch validation and
// dispatch indivisible with respect to accepted hooks. Neither mutates a lease.
func (c *Client) requestEarlyRenewal(epoch uint64, due int64) (int64, error) {
	c.early.mu.Lock()
	defer c.early.mu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return 0, ErrUnavailable
	}
	if c.lease.Epoch != epoch {
		return 0, nil // A newer valid hook won the race; observe it before sending.
	}
	if c.early.responseBy != 0 {
		return 0, ErrUnavailable
	}
	now, err := bootNow()
	if err != nil || now < due || now-due > int64(earlyDispatch) || c.lease.DeadlineBootNS-now <= int64(earlyTokenMargin+2*earlyResponse) {
		return 0, ErrUnavailable
	}
	c.early.responseBy = now + int64(earlyResponse)
	c.early.pendingEpoch = epoch
	c.early.completedEpoch, c.early.completedBootNS = 0, 0
	if err := c.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		c.early.responseBy = now
		return 0, err
	}
	return now, nil
}

func (c *Client) runEarlyRenewal(ctx context.Context) {
	defer close(c.early.done)
	runEarlyRenewal(ctx, c.early.wake, c.done, bootNow, c.observeEarlyRenewal, c.requestEarlyRenewal, c.failAt, newEarlyBootTimer)
}

// A single worker and one timer exist only for the explicit V4 profile. An
// unanswered request revokes evidence through the existing owner watcher (B2);
// it never manufactures a hook, epoch, EXPIRE or replacement acquisition.
func runEarlyRenewal(ctx context.Context, wake, ownerDone <-chan struct{}, clock func() (int64, error), observe func(int64) (earlyRenewalObservation, error), send func(uint64, int64) (int64, error), revoke func(string), newTimer func() (earlyRenewalTimer, error)) {
	var cycle earlyRenewalCycle
	var timer earlyRenewalTimer
	defer func() {
		if timer != nil {
			timer.close()
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		now, err := clock()
		if err != nil {
			revoke("early_clock")
			return
		}
		o, err := observe(now)
		if err != nil {
			return // Already unavailable; never restart or signal a dead owner.
		}
		delay, failure := cycle.next(o, now)
		if failure != "" {
			revoke(failure)
			return
		}
		if delay == 0 {
			sent, err := send(cycle.epoch, cycle.due)
			if err != nil {
				revoke("early_signal")
				return
			}
			if sent != 0 {
				cycle.sentEpoch, cycle.responseBy = cycle.epoch, sent+int64(earlyResponse)
			}
			continue
		}
		var tick <-chan error
		if delay > 0 {
			if timer == nil {
				timer, err = newTimer()
				if err != nil {
					revoke("early_timer")
					return
				}
			}
			if timer.arm(now+int64(delay)) != nil {
				revoke("early_timer")
				return
			}
			tick = timer.wait()
		} else if timer != nil {
			timer.close()
			timer = nil
		}
		select {
		case <-ctx.Done():
			return
		case <-ownerDone:
			return
		case <-wake:
		case err := <-tick:
			if err != nil {
				revoke("early_timer")
				return
			}
		}
	}
}
