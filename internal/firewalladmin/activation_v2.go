package firewalladmin

import (
	"context"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// PreparedGuardedEngine binds the existing engine and independently leased
// authority. It is not wired to a runtime or an administrative activation flag.
type PreparedGuardedEngine struct {
	mu               sync.Mutex
	engine           configpoc.Engine
	authority        LeaseAuthority
	recoverLease     func(context.Context, LeaseState) error
	id               string
	previous, target configpoc.Revision
}

func NewPreparedGuardedEngine(engine configpoc.Engine, authority LeaseAuthority, recoverLease func(context.Context, LeaseState) error) (*PreparedGuardedEngine, error) {
	if engine == nil || authority == nil || recoverLease == nil {
		return nil, configpoc.ErrInvalid
	}
	return &PreparedGuardedEngine{engine: engine, authority: authority, recoverLease: recoverLease}, nil
}
func (g *PreparedGuardedEngine) Name() string { return g.engine.Name() }
func (g *PreparedGuardedEngine) Validate(config configpoc.Config) error {
	return g.engine.Validate(config)
}
func (g *PreparedGuardedEngine) Current() string { return g.engine.Current() }

func exactGuardScope(state LeaseState, id string, previous, target configpoc.Revision) bool {
	return state.ID == id && state.Previous == previous.Hash && state.Target == target.Hash
}
func guardRevision(revision configpoc.Revision) bool {
	canonical, err := configpoc.Canonical(revision.Config)
	return err == nil && canonical.Hash == revision.Hash
}
func (g *PreparedGuardedEngine) Arm(ctx context.Context, id string, previous, target configpoc.Revision, ttl time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if id == "" || len(id) > 64 || !guardRevision(previous) || !guardRevision(target) || ttl <= 0 || ttl > 120*time.Second {
		return configpoc.ErrInvalid
	}
	state, err := g.authority.State(ctx)
	if err != nil {
		return configpoc.ErrRecovery
	}
	now := time.Now()
	// Rebind a durable pending lease or exact completed receipt after restart;
	// this never rearms an active lease or changes its original deadline.
	if exactGuardScope(state, id, previous, target) && (state.Phase == "armed" || state.Phase == "pending" || state.Phase == "idle") {
		current, err := g.authority.Current(ctx)
		if err != nil || (current != previous.Hash && current != target.Hash) || g.engine.Current() != current {
			return configpoc.ErrRecovery
		}
		if state.Phase != "idle" && (!now.Before(state.Deadline) || state.Deadline.After(now.Add(120*time.Second))) {
			return configpoc.ErrRecovery
		}
		g.id, g.previous, g.target = id, previous, target
		return nil
	}
	if state.Phase != "idle" {
		return configpoc.ErrRecovery
	}
	if ttl < 500*time.Millisecond {
		return configpoc.ErrExpired
	}
	// Arm may succeed remotely despite a lost reply. Only the exact observed
	// receipt and unchanged previous revision can reconcile that ambiguity.
	_ = g.authority.Arm(ctx, id, previous, target, ttl)
	state, err = g.authority.State(ctx)
	current, currentErr := g.authority.Current(ctx)
	if err != nil || currentErr != nil || state.Phase != "armed" || !exactGuardScope(state, id, previous, target) || !time.Now().Before(state.Deadline) || state.Deadline.After(time.Now().Add(ttl)) || current != previous.Hash || g.engine.Current() != previous.Hash {
		return configpoc.ErrRecovery
	}
	g.id, g.previous, g.target = id, previous, target
	return nil
}
func (g *PreparedGuardedEngine) Apply(ctx context.Context, target configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, err := g.authority.State(ctx)
	if err != nil || g.id == "" || target.Hash != g.target.Hash || !guardRevision(target) || state.Phase != "armed" || !exactGuardScope(state, g.id, g.previous, g.target) || !time.Now().Before(state.Deadline) {
		return configpoc.ErrRecovery
	}
	return g.engine.Apply(ctx, target)
}
func (g *PreparedGuardedEngine) Confirm(ctx context.Context, id, hash string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if id == "" || id != g.id || hash != g.target.Hash {
		return configpoc.ErrRecovery
	}
	state, err := g.authority.State(ctx)
	current, currentErr := g.authority.Current(ctx)
	if err != nil || currentErr != nil || !exactGuardScope(state, id, g.previous, g.target) || current != hash || g.engine.Current() != hash || (state.Phase != "pending" && state.Phase != "idle") {
		return configpoc.ErrRecovery
	}
	_ = g.authority.Confirm(ctx, id, hash)
	state, err = g.authority.State(ctx)
	current, currentErr = g.authority.Current(ctx)
	if err != nil || currentErr != nil || state.Phase != "idle" || !exactGuardScope(state, id, g.previous, g.target) || current != hash || g.engine.Current() != hash {
		return configpoc.ErrRecovery
	}
	return nil
}

// RecoverPrevious requires an authority-scoped compare-and-recover operation.
// The callback must compare ID, hashes and deadline atomically with recovery;
// the existing unscoped IPC Recovered operation is not a compatible binding.
func (g *PreparedGuardedEngine) RecoverPrevious(ctx context.Context, id string, previous, target configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if id == "" || len(id) > 64 || !guardRevision(previous) || !guardRevision(target) {
		return configpoc.ErrInvalid
	}
	state, err := g.authority.State(ctx)
	current, currentErr := g.authority.Current(ctx)
	if err != nil || currentErr != nil || g.engine.Current() != current {
		return configpoc.ErrRecovery
	}
	if state.Phase == "idle" && exactGuardScope(state, id, previous, target) && current == target.Hash {
		return configpoc.ErrRecovery
	}
	if state.Phase == "idle" && current == previous.Hash {
		// No reset is performed: readback proves that the exact previous policy
		// is still effective, regardless of whether Arm ever reached the helper.
		return nil
	}
	if !exactGuardScope(state, id, previous, target) || (state.Phase != "armed" && state.Phase != "pending" && state.Phase != "expired") || (current != previous.Hash && current != target.Hash) {
		return configpoc.ErrRecovery
	}
	if state.Deadline.IsZero() {
		return configpoc.ErrRecovery
	}
	if err := g.recoverLease(ctx, state); err != nil {
		return configpoc.ErrRecovery
	}
	state, err = g.authority.State(ctx)
	current, currentErr = g.authority.Current(ctx)
	if err != nil || currentErr != nil || state.Phase != "idle" || current != previous.Hash || g.engine.Current() != previous.Hash {
		return configpoc.ErrRecovery
	}
	g.id = ""
	return nil
}
