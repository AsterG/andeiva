// Package nftguardian owns a bounded laboratory rollback lease independently of the controller.
package nftguardian

import (
	"context"
	"errors"
	"sync"
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
	mu               sync.Mutex
	engine           Engine
	state            State
	previous, target configpoc.Revision
	deadline         time.Time
	timer            *time.Timer
	closed           bool
}

func New(engine Engine) *Guardian { return &Guardian{engine: engine, state: State{Phase: "idle"}} }

func valid(r configpoc.Revision) bool {
	c, err := configpoc.Canonical(r.Config)
	return err == nil && c.Hash == r.Hash
}

func (g *Guardian) Arm(id string, previous, target configpoc.Revision, ttl time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.state.Phase != "idle" || len(id) < 1 || len(id) > 64 || !valid(previous) || !valid(target) || ttl < 500*time.Millisecond || ttl > 30*time.Second || g.engine.Current() != previous.Hash {
		return ErrLease
	}
	g.previous, _ = configpoc.Canonical(previous.Config)
	g.target, _ = configpoc.Canonical(target.Config)
	g.deadline = time.Now().Add(ttl)
	g.state = State{Phase: "armed", ID: id, Previous: previous.Hash, Target: target.Hash, Deadline: g.deadline.UTC()}
	g.timer = time.AfterFunc(ttl, func() { g.mu.Lock(); defer g.mu.Unlock(); g.expire() })
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
	if (g.state.Phase == "armed" || g.state.Phase == "pending") && !time.Now().Before(g.deadline) {
		_ = g.restore()
	}
}

func (g *Guardian) Apply(ctx context.Context, r configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || !valid(r) {
		return ErrLease
	}
	g.expire()
	if g.state.Phase == "blocked" {
		return ErrLease
	}
	if g.state.Phase == "expired" {
		if r.Hash == g.previous.Hash && g.engine.Current() == r.Hash {
			return nil
		}
		return ErrLease
	}
	if g.state.Phase == "armed" || g.state.Phase == "pending" {
		if r.Hash == g.previous.Hash {
			if g.timer != nil {
				g.timer.Stop()
			}
			return g.restore()
		}
		if r.Hash != g.target.Hash {
			return ErrLease
		}
		// A second activation could be a restarted coordinator replaying a
		// durable confirm that never reached this authority. Keep its lease
		// barrier intact; only a pending journal may restore the previous policy.
		if g.state.Phase == "pending" {
			return ErrLease
		}
		bounded, cancel := context.WithDeadline(ctx, g.deadline)
		err := g.engine.Apply(bounded, r)
		cancel()
		if err != nil || !time.Now().Before(g.deadline) {
			_ = g.restore()
			return ErrLease
		}
		g.state.Phase = "pending"
		return nil
	}
	if r.Hash != g.state.Target {
		g.state = State{Phase: "idle"}
	}
	return g.engine.Apply(ctx, r)
}

func (g *Guardian) Confirm(id, hash string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.expire()
	// Retain the exact confirmed lease for lost-ack reconciliation. An idle
	// phase alone is not proof that this transaction was confirmed.
	if !g.closed && g.state.Phase == "idle" && g.state.ID == id && id != "" && g.state.Target == hash && g.engine.Current() == hash {
		return nil
	}
	if g.closed || g.state.Phase != "pending" || g.state.ID != id || g.target.Hash != hash || g.engine.Current() != hash {
		return ErrLease
	}
	if !time.Now().Before(g.deadline) {
		g.expire()
		return ErrLease
	}
	g.timer.Stop()
	g.state.Phase = "idle"
	return nil
}

// RecoverPrevious never accepts a caller-selected replacement policy.
func (g *Guardian) RecoverPrevious() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return ErrLease
	}
	if g.state.Phase == "idle" {
		return nil
	}
	if g.timer != nil {
		g.timer.Stop()
	}
	if err := g.restore(); err != nil {
		return err
	}
	g.state = State{Phase: "idle"}
	return nil
}

func (g *Guardian) Status() State { g.mu.Lock(); defer g.mu.Unlock(); g.expire(); return g.state }

func (g *Guardian) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	if g.timer != nil {
		g.timer.Stop()
	}
	var err error
	if g.state.Phase != "idle" {
		err = g.restore()
	}
	g.closed = true
	return err
}
