package firewalladmin

import (
	"context"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// PreparedStartupEngine adds only the existing, trusted one-time bootstrap
// operation. It does not register an IPC verb or enable a runtime.
type PreparedStartupEngine struct {
	*PreparedGuardedEngine
	bootstrap func(context.Context, configpoc.Revision) error
}

func NewPreparedStartupEngine(engine configpoc.Engine, authority LeaseAuthority, recovered func(context.Context) error, bootstrap func(context.Context, configpoc.Revision) error) (*PreparedStartupEngine, error) {
	if bootstrap == nil {
		return nil, configpoc.ErrInvalid
	}
	guard, err := NewPreparedGuardedEngine(engine, authority, recovered)
	if err != nil {
		return nil, err
	}
	return &PreparedStartupEngine{PreparedGuardedEngine: guard, bootstrap: bootstrap}, nil
}

func (g *PreparedStartupEngine) BootstrapStartup(ctx context.Context, id string, target configpoc.Revision) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if id == "" || len(id) > 64 || !guardRevision(target) {
		return configpoc.ErrInvalid
	}
	state, err := g.authority.State(ctx)
	if err != nil || state.Phase != "bootstrap" || state.ID != "" || state.Previous != "" || state.Target != "" || !state.Deadline.IsZero() {
		return configpoc.ErrRecovery
	}
	// A lost response is resolved only by effective state after the one-time
	// authority action; no guessed success or reset of a foreign lease.
	_ = g.bootstrap(ctx, target)
	state, err = g.authority.State(ctx)
	current, readErr := g.authority.Current(ctx)
	if err != nil || readErr != nil || state.Phase != "idle" || state.ID != "" || state.Previous != "" || state.Target != "" || !state.Deadline.IsZero() || current != target.Hash || g.engine.Current() != target.Hash {
		return configpoc.ErrRecovery
	}
	return nil
}

func (g *PreparedStartupEngine) ConfirmStartup(ctx context.Context, id string, previous, target configpoc.Revision) error {
	if id == "" || len(id) > 64 || !guardRevision(previous) || !guardRevision(target) {
		return configpoc.ErrInvalid
	}
	g.mu.Lock()
	state, err := g.authority.State(ctx)
	current, readErr := g.authority.Current(ctx)
	if err != nil || readErr != nil || current != target.Hash || g.engine.Current() != target.Hash {
		g.mu.Unlock()
		return configpoc.ErrRecovery
	}
	// Bootstrap has no activation lease. Its exact idle state is already
	// read back; an active or foreign lease cannot take this branch.
	bootstrapped := state.Phase == "idle" && state.ID == "" && state.Previous == "" && state.Target == "" && state.Deadline.IsZero()
	g.mu.Unlock()
	if bootstrapped {
		return nil
	}
	if !exactGuardScope(state, id, previous, target) {
		return configpoc.ErrRecovery
	}
	if err := g.Arm(ctx, id, previous, target, 10*time.Second); err != nil {
		return err
	}
	return g.Confirm(ctx, id, target.Hash)
}
