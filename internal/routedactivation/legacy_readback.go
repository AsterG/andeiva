package routedactivation

import (
	"context"

	"github.com/AsterG/andeiva/internal/firewallnft"
)

// ObserveLegacy describes this table only, not group readiness or a lease.
// Revisions come from trusted initial/selected plans, never kernel comments.
func (e *Engine) ObserveLegacy(ctx context.Context) (firewallnft.Observation, bool, uint64, error) {
	if e == nil || ctx == nil || ctx.Err() != nil {
		return firewallnft.Observation{}, false, 0, ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || e.legacyExhausted || e.kernel == nil {
		return firewallnft.Observation{}, false, 0, ErrState
	}
	data, present, err := e.kernel.Observe(ctx, LegacyTable)
	if err != nil || ctx.Err() != nil || len(data) > MaxBatch {
		return firewallnft.Observation{}, false, 0, ErrState
	}
	if !present {
		if len(data) != 0 {
			return firewallnft.Observation{}, false, 0, ErrState
		}
		return firewallnft.Observation{}, false, e.legacyEpoch, nil
	}
	candidates := []TableStateV1{e.initial[0]}
	if e.selected {
		candidates = []TableStateV1{e.prepared.Before.LegacyFirewall, e.prepared.Target.LegacyFirewall}
	}
	for _, candidate := range candidates {
		if candidate.Presence != Present || candidate.Revision == nil {
			continue
		}
		observation, err := firewallnft.VerifyObservation(data, *candidate.Revision)
		if err == nil && ctx.Err() == nil {
			return observation, true, e.legacyEpoch, nil
		}
	}
	return firewallnft.Observation{}, false, 0, ErrState
}
