package nftguardian

import (
	"context"
	"sync"
	"time"
)

// leaseCore is the single timer, receipt and CAS implementation shared by the
// legacy revision authority and the typed routed group authority. Callers hold mu
// and validate their own typed payloads before invoking these private mechanics.
type leaseCore struct {
	mu                 sync.Mutex
	state              State
	deadline           time.Time
	timer              *time.Timer
	closed, restricted bool
	maxTTL             time.Duration
}

func (c *leaseCore) armLocked(id, previous, target string, receipt, monotonic time.Time, delay time.Duration, expire func()) {
	c.deadline = monotonic
	c.state = State{Phase: "armed", ID: id, Previous: previous, Target: target, Deadline: receipt}
	c.timer = time.AfterFunc(delay, func() { c.mu.Lock(); defer c.mu.Unlock(); expire() })
}

func (c *leaseCore) armUntilLocked(id, previous, target string, deadline time.Time, prepare func(), expire func()) error {
	now := time.Now()
	remaining := deadline.Sub(now)
	if remaining < 500*time.Millisecond || remaining > c.maxTTL {
		return ErrLease
	}
	prepare()
	monotonic := now.Add(remaining)
	c.armLocked(id, previous, target, deadline, monotonic, time.Until(monotonic), expire)
	return nil
}

func (c *leaseCore) exactLeaseLocked(expected State) bool {
	return !c.closed && expected.ID != "" && c.state.ID == expected.ID && c.state.Previous == expected.Previous && c.state.Target == expected.Target && !expected.Deadline.IsZero() && c.state.Deadline.Equal(expected.Deadline)
}

func (c *leaseCore) expireLocked(restore func() error) {
	if (c.state.Phase == "armed" || c.state.Phase == "pending") && !time.Now().Before(c.deadline) {
		_ = restore()
	}
}

func (c *leaseCore) applyLocked(ctx context.Context, hash, previous, target string, current func() string, apply func(context.Context) error, expire func(), restore func() error) error {
	expire()
	if c.state.Phase == "blocked" || c.state.Phase == "bootstrap" {
		return ErrLease
	}
	if c.state.Phase == "expired" {
		if hash == previous && current() == hash {
			return nil
		}
		return ErrLease
	}
	if c.state.Phase == "armed" || c.state.Phase == "pending" {
		if previous == target && hash == target && current() == hash {
			c.state.Phase = "pending"
			return nil
		}
		if hash == previous {
			if c.timer != nil {
				c.timer.Stop()
			}
			return restore()
		}
		if hash != target || c.state.Phase == "pending" {
			return ErrLease
		}
		bounded, cancel := context.WithDeadline(ctx, c.deadline)
		err := apply(bounded)
		cancel()
		if err != nil || !time.Now().Before(c.deadline) {
			_ = restore()
			return ErrLease
		}
		c.state.Phase = "pending"
		return nil
	}
	if c.restricted && hash != current() && hash != previous {
		return ErrLease
	}
	if hash != c.state.Target {
		c.state = State{Phase: "idle"}
	}
	return apply(ctx)
}

func (c *leaseCore) confirmLocked(id, hash, target string, current func() string, expire func()) error {
	expire()
	if !c.closed && c.state.Phase == "idle" && c.state.ID == id && id != "" && c.state.Target == hash && current() == hash {
		return nil
	}
	if c.closed || c.state.Phase != "pending" || c.state.ID != id || target != hash || current() != hash {
		return ErrLease
	}
	if !time.Now().Before(c.deadline) {
		expire()
		return ErrLease
	}
	c.timer.Stop()
	c.state.Phase = "idle"
	return nil
}

func (c *leaseCore) recoveryLeaseLocked(expected State) bool {
	if c.closed || expected.ID == "" || len(expected.ID) > 64 || expected.Deadline.IsZero() || !c.exactLeaseLocked(expected) || !c.deadline.Equal(expected.Deadline) {
		return false
	}
	return c.state.Phase == "armed" || c.state.Phase == "pending" || c.state.Phase == "expired"
}

func (c *leaseCore) recoverPreviousLocked(restore func() error) error {
	if c.closed {
		return ErrLease
	}
	if c.state.Phase == "idle" {
		return nil
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	if err := restore(); err != nil {
		return err
	}
	c.state = State{Phase: "idle"}
	return nil
}

func (c *leaseCore) closeLocked(restore func() error) error {
	if c.closed {
		return nil
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	var err error
	if c.state.Phase != "idle" {
		err = restore()
	}
	c.closed = true
	return err
}

func (c *leaseCore) snapshotLocked(hash string, verifiedUnconfigured bool) (State, string, error) {
	s := c.state
	switch s.Phase {
	case "bootstrap":
		if s.ID != "" || s.Previous != "" || s.Target != "" || !s.Deadline.IsZero() || hash != "" {
			return State{}, "", ErrLease
		}
	case "idle", "armed", "pending", "expired":
		if hash == "" && !verifiedUnconfigured {
			return State{}, "", ErrLease
		}
		if (s.Phase == "armed" || s.Phase == "pending") && !time.Now().Before(c.deadline) {
			return State{}, "", ErrLease
		}
	default:
		return State{}, "", ErrLease
	}
	return s, hash, nil
}
