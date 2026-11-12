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
	return g.armUntilLocked(id, previous.Hash, target.Hash, deadline, func() {
		g.previous, _ = configpoc.Canonical(previous.Config)
		g.target, _ = configpoc.Canonical(target.Config)
	}, g.expire)
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
