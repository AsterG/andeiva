package nftguardian

import (
	"context"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// ArmUntil keeps the caller's exact receipt and a separate monotonic expiry.
// Slow readback consumes the remaining interval rather than extending it.
func (g *Guardian) ArmUntil(id string, previous, target configpoc.Revision, deadline time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.state.Phase != "idle" || len(id) < 1 || len(id) > 64 || !valid(previous) || !valid(target) || deadline.IsZero() || deadline.Location() != time.UTC || deadline.Sub(time.Now()) > g.maxTTL || g.engine.Current() != previous.Hash {
		return ErrLease
	}
	now := time.Now()
	remaining := deadline.Sub(now)
	if remaining < 500*time.Millisecond || remaining > g.maxTTL {
		return ErrLease
	}
	g.previous, _ = configpoc.Canonical(previous.Config)
	g.target, _ = configpoc.Canonical(target.Config)
	g.deadline = now.Add(remaining)
	g.state = State{Phase: "armed", ID: id, Previous: previous.Hash, Target: target.Hash, Deadline: deadline}
	g.timer = time.AfterFunc(time.Until(g.deadline), func() { g.mu.Lock(); defer g.mu.Unlock(); g.expire() })
	return nil
}

func (g *Guardian) exactLeaseLocked(expected State) bool {
	return !g.closed && expected.ID != "" && g.state.ID == expected.ID && g.state.Previous == expected.Previous && g.state.Target == expected.Target && !expected.Deadline.IsZero() && g.state.Deadline.Equal(expected.Deadline)
}

// ApplyLease and ConfirmLease compare scope and act under the same mutex.
func (g *Guardian) ApplyLease(ctx context.Context, revision configpoc.Revision, expected State) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.exactLeaseLocked(expected) || revision.Hash != expected.Target || g.state.Phase != "armed" {
		return ErrLease
	}
	err := g.applyLocked(ctx, revision)
	if err == nil && !time.Now().Before(g.deadline) {
		g.expire()
		return ErrLease
	}
	return err
}

func (g *Guardian) ConfirmLease(expected State) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.exactLeaseLocked(expected) {
		return ErrLease
	}
	return g.confirmLocked(expected.ID, expected.Target)
}
