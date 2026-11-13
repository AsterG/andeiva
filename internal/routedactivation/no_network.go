package routedactivation

import (
	"context"
	"encoding/json"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

type observedNetwork interface {
	PrepareObserved(context.Context, []networkplan.Binding) (networkexecutor.ObservedSnapshot, error)
	VerifyObserved(context.Context, networkexecutor.ObservedSnapshot) error
}

func emptyBundleLocal(bundle configpoc.RoutedActivationBundleV1) bool {
	local := bundle.LocalServices.Config.LocalServices
	if local == nil {
		return false
	}
	for _, service := range local.Services {
		if service.Enabled {
			return false
		}
	}
	return true
}

func (e *Engine) recoverNetwork(ctx context.Context, deps DependenciesV1, original networkexecutor.OwnedNamespaceIdentity) error {
	if deps.Version == 2 {
		recovery, ok := e.network.(interface {
			RecoverObserved(context.Context, networkexecutor.ObservedSnapshot, networkexecutor.OwnedNamespaceIdentity) error
		})
		if !ok || deps.Observed == nil {
			return ErrState
		}
		return recovery.RecoverObserved(ctx, *deps.Observed, original)
	}
	recovery, ok := e.network.(interface {
		RecoverPrepared(context.Context, networkplan.Revision, networkexecutor.PreparedSnapshot, networkexecutor.OwnedNamespaceIdentity) error
	})
	if !ok {
		return ErrState
	}
	return recovery.RecoverPrepared(ctx, deps.Network, deps.Prepared, original)
}

// prepareNoNetworkBoot is called under e.mu. It captures only authenticated
// inventory and actual absence; it neither configures L3 nor provisions tables.
func (e *Engine) prepareNoNetworkBoot(ctx context.Context, target, saved configpoc.RoutedActivationBundleV1) (PreparationV1, error) {
	if !emptyBundleLocal(target) || saved.Composite.Hash != target.Composite.Hash || saved.Firewall.Hash != e.options.Legacy.Hash {
		return PreparationV1{}, ErrState
	}
	observer, ok := e.network.(observedNetwork)
	if !ok || len(e.options.ObservedBindings) != 2 {
		return PreparationV1{}, ErrState
	}
	snapshot, err := observer.PrepareObserved(ctx, e.options.ObservedBindings)
	if err != nil {
		return PreparationV1{}, err
	}
	deps, err := CanonicalDependencies(DependenciesV1{Version: 2, NetworkMode: "none", Observed: &snapshot})
	if err != nil {
		return PreparationV1{}, err
	}
	before, err := CanonicalOwned(OwnedV1{Version: 2, NetworkState: NoNetwork, Observed: &snapshot, LegacyFirewall: TableStateV1{Presence: Absent}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}})
	if err != nil || !e.matches(ctx, before, deps) {
		return PreparationV1{}, ErrState
	}
	after := before
	after.LegacyFirewall = TableStateV1{Presence: Present, Revision: &target.Firewall}
	return e.previewNoNetwork(ctx, target, before, after, deps)
}

func (e *Engine) prepareNoNetworkEdit(ctx context.Context, target configpoc.RoutedActivationBundleV1, before OwnedV1) (PreparationV1, error) {
	if !emptyBundleLocal(target) || before.NetworkState != NoNetwork || before.Observed == nil {
		return PreparationV1{}, ErrState
	}
	deps, err := CanonicalDependencies(DependenciesV1{Version: 2, NetworkMode: "none", Observed: before.Observed})
	if err != nil || !e.matches(ctx, before, deps) {
		return PreparationV1{}, ErrState
	}
	after := before
	after.LegacyFirewall = TableStateV1{Presence: Present, Revision: &target.Firewall}
	return e.previewNoNetwork(ctx, target, before, after, deps)
}

func (e *Engine) previewNoNetwork(ctx context.Context, target configpoc.RoutedActivationBundleV1, before, after OwnedV1, deps DependenciesV1) (PreparationV1, error) {
	before, err := CanonicalOwned(before)
	if err != nil {
		return PreparationV1{}, err
	}
	after, err = CanonicalOwned(after)
	if err != nil {
		return PreparationV1{}, err
	}
	deps, err = CanonicalDependencies(deps)
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
	if err != nil || ctx.Err() != nil {
		return PreparationV1{}, ErrState
	}
	var detached PreparationV1
	if json.Unmarshal(data, &detached) != nil {
		return PreparationV1{}, ErrState
	}
	e.preview = &detached
	return prepared, nil
}

func (e *Engine) inverseMatches(ctx context.Context, previous *configpoc.RoutedActivationBundleV1, target configpoc.RoutedActivationBundleV1, after OwnedV1, deps DependenciesV1) bool {
	if previous == nil || previous.Firewall.Config.SchemaVersion != 6 || target.Firewall.Config.SchemaVersion != 4 {
		return true
	}
	baseline, err := e.resolveBaseline(ctx, target)
	return err == nil && sameArtifact(after, baseline.Owned) && configpoc.RoutedOwnershipMatchesDependencies(baseline.Owned, deps)
}
