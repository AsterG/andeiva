package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/adminauth"
)

type RoutedEffectiveV2 struct {
	SchemaVersion int    `json:"schema_version"`
	Generation    uint64 `json:"generation,string"`
	Running       string `json:"running_revision"`
	Observed      string `json:"observed_revision,omitempty"`
	Phase         string `json:"phase"`
	Consistent    bool   `json:"consistent"`
}

func (s *ServiceV2) RoutedEffective(ctx context.Context, binding adminauth.SessionBinding) (RoutedEffectiveV2, error) {
	p, err := s.principal(binding)
	if err != nil {
		return RoutedEffectiveV2{}, err
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked || c.options.Routed == nil || !hasFeatureV2(c.store.state, v2RoutedFeature) {
		return RoutedEffectiveV2{}, errV2Unavailable
	}
	if !c.store.principalV2Locked(p) || p.Role != RoleAdmin && p.Role != RoleViewer {
		return RoutedEffectiveV2{}, ErrDenied
	}
	if ctx == nil || ctx.Err() != nil {
		return RoutedEffectiveV2{}, ErrInterrupted
	}
	receipt, hash, err := c.options.Routed.Observe(ctx)
	if err != nil || ctx.Err() != nil || hash != "" && !validHash(hash) {
		return RoutedEffectiveV2{}, ErrRecovery
	}
	switch receipt.Phase {
	case "bootstrap", "armed", "pending", "idle", "expired", "blocked":
	default:
		return RoutedEffectiveV2{}, ErrRecovery
	}
	running := c.store.state.Configuration.Running.Hash
	cfg := c.store.state.Configuration
	return RoutedEffectiveV2{SchemaVersion: 1, Generation: c.store.state.Generation, Running: running, Observed: hash, Phase: receipt.Phase, Consistent: cfg.Intent == nil && !cfg.RecoveryRequired && hash == running && (receipt.Phase == "idle" || receipt.Phase == "pending")}, nil
}
