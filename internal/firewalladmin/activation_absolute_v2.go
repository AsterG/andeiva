package firewalladmin

import (
	"context"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// AbsoluteLeaseAuthority must compare the entire receipt inside the helper.
// Relative-only authorities intentionally cannot construct this adapter.
type AbsoluteLeaseAuthority interface {
	ArmUntil(context.Context, string, configpoc.Revision, configpoc.Revision, time.Time) error
	ApplyLease(context.Context, configpoc.Revision, LeaseState) error
	ConfirmLease(context.Context, LeaseState) error
	RecoverScoped(context.Context, LeaseState) error
	Current(context.Context) (string, error)
	State(context.Context) (LeaseState, error)
}

type PreparedAbsoluteGuardedEngine struct {
	mu        sync.Mutex
	engine    configpoc.Engine
	authority AbsoluteLeaseAuthority
	receipt   LeaseState
}

func NewPreparedAbsoluteGuardedEngine(engine configpoc.Engine, authority AbsoluteLeaseAuthority) (*PreparedAbsoluteGuardedEngine, error) {
	if engine == nil || authority == nil {
		return nil, configpoc.ErrInvalid
	}
	return &PreparedAbsoluteGuardedEngine{engine: engine, authority: authority}, nil
}
func (g *PreparedAbsoluteGuardedEngine) Name() string    { return g.engine.Name() }
func (g *PreparedAbsoluteGuardedEngine) Current() string { return g.engine.Current() }
func (g *PreparedAbsoluteGuardedEngine) Validate(c configpoc.Config) error {
	return g.engine.Validate(c)
}
func (g *PreparedAbsoluteGuardedEngine) Arm(ctx context.Context, id string, p, t configpoc.Revision, ttl time.Duration) error {
	if ttl < 500*time.Millisecond || ttl > 120*time.Second {
		return configpoc.ErrInvalid
	}
	return g.ArmUntil(ctx, id, p, t, time.Now().UTC().Add(ttl))
}
func sameAbsoluteReceipt(a, b LeaseState) bool {
	return a.ID == b.ID && a.Previous == b.Previous && a.Target == b.Target && !a.Deadline.IsZero() && a.Deadline.Equal(b.Deadline)
}
func (g *PreparedAbsoluteGuardedEngine) ArmUntil(ctx context.Context, id string, p, t configpoc.Revision, deadline time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if id == "" || len(id) > 64 || !guardRevision(p) || !guardRevision(t) || deadline.IsZero() || deadline.Location() != time.UTC {
		return configpoc.ErrInvalid
	}
	expected := LeaseState{ID: id, Previous: p.Hash, Target: t.Hash, Deadline: deadline}
	s, err := g.authority.State(ctx)
	if err != nil {
		return configpoc.ErrRecovery
	}
	if sameAbsoluteReceipt(s, expected) && (s.Phase == "armed" || s.Phase == "pending" || s.Phase == "idle") {
		current, e := g.authority.Current(ctx)
		if e != nil || current != g.engine.Current() || (current != p.Hash && current != t.Hash) || (s.Phase != "idle" && !time.Now().Before(deadline)) {
			return configpoc.ErrRecovery
		}
		g.receipt = expected
		return nil
	}
	if s.Phase != "idle" || s.ID != "" && (s.ID == id || !time.Now().Before(deadline)) {
		return configpoc.ErrRecovery
	}
	remaining := time.Until(deadline)
	if remaining < 500*time.Millisecond || remaining > 120*time.Second {
		return configpoc.ErrExpired
	}
	_ = g.authority.ArmUntil(ctx, id, p, t, deadline)
	s, err = g.authority.State(ctx)
	current, e := g.authority.Current(ctx)
	if err != nil || e != nil || s.Phase != "armed" || !sameAbsoluteReceipt(s, expected) || current != p.Hash || g.engine.Current() != p.Hash || !time.Now().Before(deadline) {
		return configpoc.ErrRecovery
	}
	g.receipt = expected
	return nil
}
func (g *PreparedAbsoluteGuardedEngine) Apply(ctx context.Context, target configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.receipt.ID == "" || !guardRevision(target) || target.Hash != g.receipt.Target || !time.Now().Before(g.receipt.Deadline) {
		return configpoc.ErrRecovery
	}
	// A lost reply is reconciled only against this exact surviving receipt.
	_ = g.authority.ApplyLease(ctx, target, g.receipt)
	s, err := g.authority.State(ctx)
	current, e := g.authority.Current(ctx)
	if err != nil || e != nil || s.Phase != "pending" || !sameAbsoluteReceipt(s, g.receipt) || current != target.Hash || g.engine.Current() != target.Hash || !time.Now().Before(g.receipt.Deadline) {
		return configpoc.ErrRecovery
	}
	return nil
}
func (g *PreparedAbsoluteGuardedEngine) Confirm(ctx context.Context, id, hash string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if id == "" || id != g.receipt.ID || hash != g.receipt.Target {
		return configpoc.ErrRecovery
	}
	_ = g.authority.ConfirmLease(ctx, g.receipt)
	s, err := g.authority.State(ctx)
	current, e := g.authority.Current(ctx)
	if err != nil || e != nil || s.Phase != "idle" || !sameAbsoluteReceipt(s, g.receipt) || current != hash || g.engine.Current() != hash {
		return configpoc.ErrRecovery
	}
	return nil
}
func (g *PreparedAbsoluteGuardedEngine) RecoverPrevious(ctx context.Context, id string, p, t configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !guardRevision(p) || !guardRevision(t) || id == "" || id != g.receipt.ID || p.Hash != g.receipt.Previous || t.Hash != g.receipt.Target {
		return configpoc.ErrRecovery
	}
	return g.recoverUntilLocked(ctx, id, p, t, g.receipt.Deadline)
}

// RecoverPreviousUntil can reconstruct only a caller's durable exact receipt.
// It never adopts a helper-selected replacement deadline after restart.
func (g *PreparedAbsoluteGuardedEngine) RecoverPreviousUntil(ctx context.Context, id string, p, t configpoc.Revision, deadline time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !guardRevision(p) || !guardRevision(t) || id == "" || len(id) > 64 || deadline.IsZero() || deadline.Location() != time.UTC {
		return configpoc.ErrInvalid
	}
	return g.recoverUntilLocked(ctx, id, p, t, deadline)
}
func (g *PreparedAbsoluteGuardedEngine) recoverUntilLocked(ctx context.Context, id string, p, t configpoc.Revision, deadline time.Time) error {
	expected := LeaseState{ID: id, Previous: p.Hash, Target: t.Hash, Deadline: deadline}
	if g.receipt.ID != "" && !sameAbsoluteReceipt(g.receipt, expected) {
		return configpoc.ErrRecovery
	}
	s, err := g.authority.State(ctx)
	current, e := g.authority.Current(ctx)
	if err != nil || e != nil || current != g.engine.Current() {
		return configpoc.ErrRecovery
	}
	if s.Phase == "idle" && s.ID == "" && s.Previous == "" && s.Target == "" && s.Deadline.IsZero() && current == p.Hash {
		g.receipt = LeaseState{}
		return nil
	}
	if !sameAbsoluteReceipt(s, expected) || (s.Phase != "armed" && s.Phase != "pending" && s.Phase != "expired") || (current != p.Hash && current != t.Hash) {
		return configpoc.ErrRecovery
	}
	if err := g.authority.RecoverScoped(ctx, expected); err != nil {
		return configpoc.ErrRecovery
	}
	s, err = g.authority.State(ctx)
	current, e = g.authority.Current(ctx)
	if err != nil || e != nil || s.Phase != "idle" || s.ID != "" || current != p.Hash || g.engine.Current() != p.Hash {
		return configpoc.ErrRecovery
	}
	g.receipt = LeaseState{}
	return nil
}
