package routedactivation

import (
	"context"
	"encoding/json"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localnft"
)

// PrepareColdBoot is read-only trusted assembly for a newly manager-owned
// namespace. The selected Boot/SystemBundle must become durable before Apply.
// BeforeOwned is actual absence, never the prospective saved schema-4 baseline.
func (e *Engine) PrepareColdBoot(ctx context.Context, target, saved configpoc.RoutedActivationBundleV1) (PreparationV1, error) {
	if e == nil || ctx == nil {
		return PreparationV1{}, ErrState
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || e.selected || e.preview != nil || e.kernel == nil || e.network == nil || e.listeners == nil || ctx.Err() != nil {
		return PreparationV1{}, ErrState
	}
	target, err := configpoc.CanonicalRoutedActivationBundleV1(target)
	if err != nil || target.Firewall.Config.SchemaVersion != 6 || target.LocalServices.Config.LocalServices == nil || localnft.ValidateManaged(*target.LocalServices.Config.LocalServices) != nil {
		return PreparationV1{}, ErrState
	}
	saved, err = configpoc.CanonicalRoutedActivationBundleV1(saved)
	if err != nil || saved.Firewall.Config.SchemaVersion != 4 || saved.Firewall.Hash != e.options.Legacy.Hash {
		return PreparationV1{}, ErrState
	}
	if local := saved.LocalServices.Config.LocalServices; local != nil {
		for _, service := range local.Services {
			if service.Enabled {
				return PreparationV1{}, ErrState
			}
		}
	}
	network := target.Firewall.Config.Routed.Network
	snapshot, err := e.network.Prepare(ctx, network)
	if err != nil {
		return PreparationV1{}, err
	}
	deps, err := CanonicalDependencies(DependenciesV1{Version: 1, Network: network, Prepared: snapshot, LocalInterfaces: target.LocalServices.Config.LocalServices.Interfaces, Neighbors: e.options.Neighbors})
	if err != nil {
		return PreparationV1{}, err
	}
	before, err := CanonicalOwned(OwnedV1{Version: 1, Network: snapshot, NetworkState: Baseline, LegacyFirewall: TableStateV1{Presence: Absent}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}})
	if err != nil || !e.matches(ctx, before, deps) {
		return PreparationV1{}, ErrState
	}
	after, err := CanonicalOwned(OwnedV1{Version: 1, Network: snapshot, NetworkState: Configured, LegacyFirewall: TableStateV1{Presence: Absent}, RoutedFirewall: TableStateV1{Presence: Present, Revision: &target.Firewall}, LocalServices: TableStateV1{Presence: Present, Revision: &target.LocalServices}})
	if err != nil {
		return PreparationV1{}, err
	}
	deny, err := denyTablesFor(target, deps)
	if err != nil {
		return PreparationV1{}, err
	}
	for _, change := range [][2][3]TableStateV1{{tables(before), deny}, {deny, tables(after)}, {deny, tables(before)}} {
		if _, err := e.compileChange(change[0], change[1], deps); err != nil {
			return PreparationV1{}, err
		}
	}
	prepared := PreparationV1{Before: before, Target: after, Dependencies: deps}
	data, err := json.Marshal(prepared)
	if err != nil {
		return PreparationV1{}, err
	}
	var detached PreparationV1
	if json.Unmarshal(data, &detached) != nil {
		return PreparationV1{}, ErrState
	}
	e.preview = &detached
	return prepared, nil
}
