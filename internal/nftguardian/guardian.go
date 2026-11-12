// Package nftguardian owns a bounded laboratory rollback lease independently of the controller.
package nftguardian

import (
	"context"
	"errors"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

var ErrLease = errors.New("ANDEIVA_NFT_LEASE_REJECTED")

type Engine interface {
	Apply(context.Context, configpoc.Revision) error
	Current() string
}

type State struct {
	Phase    string    `json:"phase"`
	ID       string    `json:"id"`
	Previous string    `json:"previous"`
	Target   string    `json:"target"`
	Deadline time.Time `json:"deadline"`
}

type Guardian struct {
	leaseCore
	engine           Engine
	previous, target configpoc.Revision
}

func New(engine Engine) *Guardian {
	return &Guardian{engine: engine, leaseCore: leaseCore{state: State{Phase: "idle"}, maxTTL: 30 * time.Second}}
}

// NewRestricted is for the authenticated administration boundary. It requires
// one trusted bootstrap and an independent lease for subsequent activations.
func NewRestricted(engine Engine) *Guardian {
	return &Guardian{engine: engine, leaseCore: leaseCore{state: State{Phase: "bootstrap"}, restricted: true, maxTTL: 120 * time.Second}}
}
func (g *Guardian) Bootstrap(ctx context.Context, r configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || !g.restricted || g.state.Phase != "bootstrap" || !valid(r) {
		return ErrLease
	}
	if err := g.engine.Apply(ctx, r); err != nil || g.engine.Current() != r.Hash {
		return ErrLease
	}
	g.state = State{Phase: "idle"}
	return nil
}

func valid(r configpoc.Revision) bool {
	c, err := configpoc.Canonical(r.Config)
	return err == nil && c.Hash == r.Hash
}

func (g *Guardian) Arm(id string, previous, target configpoc.Revision, ttl time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.state.Phase != "idle" || len(id) < 1 || len(id) > 64 || !valid(previous) || !valid(target) || ttl < 500*time.Millisecond || ttl > g.maxTTL || g.engine.Current() != previous.Hash {
		return ErrLease
	}
	g.previous, _ = configpoc.Canonical(previous.Config)
	g.target, _ = configpoc.Canonical(target.Config)
	deadline := time.Now().Add(ttl)
	g.armLocked(id, previous.Hash, target.Hash, deadline.UTC(), deadline, ttl, g.expire)
	return nil
}

// restore uses an independent deadline so cancellation cannot skip compensation.
func (g *Guardian) restore() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := g.engine.Apply(ctx, g.previous); err != nil || g.engine.Current() != g.previous.Hash {
		g.state.Phase = "blocked"
		return ErrLease
	}
	g.state.Phase = "expired"
	return nil
}

func (g *Guardian) expire() {
	g.expireLocked(g.restore)
}

func (g *Guardian) Apply(ctx context.Context, r configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.applyLocked(ctx, r)
}

func (g *Guardian) applyLocked(ctx context.Context, r configpoc.Revision) error {
	if g.closed || !valid(r) {
		return ErrLease
	}
	return g.leaseCore.applyLocked(ctx, r.Hash, g.previous.Hash, g.target.Hash, g.engine.Current, func(ctx context.Context) error { return g.engine.Apply(ctx, r) }, g.expire, g.restore)
}

func (g *Guardian) Confirm(id, hash string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.confirmLocked(id, hash)
}

func (g *Guardian) confirmLocked(id, hash string) error {
	return g.leaseCore.confirmLocked(id, hash, g.target.Hash, g.engine.Current, g.expire)
}

// RecoverPrevious never accepts a caller-selected replacement policy.
func (g *Guardian) RecoverPrevious() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.recoverPreviousLocked()
}

// RecoverLease compares the observed lease and its original deadline while
// holding the same lock that restores it. A stale observer cannot recover a
// replacement lease, even when its ID and policy hashes were reused.
func (g *Guardian) RecoverLease(id, previous, target string, deadline time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.previous.Hash != previous || g.target.Hash != target {
		return ErrLease
	}
	if !g.recoveryLeaseLocked(State{ID: id, Previous: previous, Target: target, Deadline: deadline}) {
		return ErrLease
	}
	return g.recoverPreviousLocked()
}

func (g *Guardian) recoverPreviousLocked() error {
	return g.leaseCore.recoverPreviousLocked(g.restore)
}

func (g *Guardian) Status() State { g.mu.Lock(); defer g.mu.Unlock(); g.expire(); return g.state }

func (g *Guardian) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closeLocked(g.restore)
}
