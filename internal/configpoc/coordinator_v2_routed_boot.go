package configpoc

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const v2RoutedBootFeature = "configuration.routed-boot.v1"

func routedBootPreparationV2(input RoutedPreparationV1, baseline RoutedBaselineV1, target RoutedActivationBundleV1, previous v2Configuration, load func(string, any) error) (RoutedPreparationV1, error) {
	if target.Firewall.Config.SchemaVersion == 4 {
		return routedNoNetworkBootPreparationV2(input, baseline, target, previous, load)
	}
	before, e1 := CanonicalOwned(input.Before)
	after, e2 := CanonicalOwned(input.Target)
	deps, e3 := CanonicalDependencies(input.Dependencies)
	saved, e4 := CanonicalRoutedActivationBundleV1(baseline.Saved)
	planned, e5 := CanonicalOwned(baseline.Owned)
	baselineDeps, e6 := CanonicalDependencies(baseline.Dependencies)
	if !RoutedOwnershipMatchesDependencies(before, deps) || !RoutedOwnershipMatchesDependencies(after, deps) {
		return RoutedPreparationV1{}, ErrRecovery
	}
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || saved.Firewall.Config.SchemaVersion != 4 || saved.LocalServices.Hash != target.LocalServices.Hash || target.Firewall.Config.Routed == nil || deps.Network.Hash != target.Firewall.Config.Routed.Network.Hash || before.NetworkState != Baseline || before.RoutedFirewall.Presence != Absent || before.Network.Hash != deps.Prepared.Hash || after.Network.Hash != deps.Prepared.Hash || after.NetworkState != Configured || after.LegacyFirewall.Presence != Absent || after.RoutedFirewall.Revision == nil || after.RoutedFirewall.Revision.Hash != target.Firewall.Hash || after.LocalServices.Revision == nil || after.LocalServices.Revision.Hash != target.LocalServices.Hash {
		return RoutedPreparationV1{}, ErrRecovery
	}
	if before.LegacyFirewall.Revision != nil && before.LegacyFirewall.Revision.Hash != saved.Firewall.Hash {
		return RoutedPreparationV1{}, ErrRecovery
	}
	if before.LocalServices.Revision != nil {
		if before.LocalServices.Revision.Hash != saved.LocalServices.Hash {
			return RoutedPreparationV1{}, ErrRecovery
		}
	} else {
		for _, service := range saved.LocalServices.Config.LocalServices.Services {
			if service.Enabled {
				return RoutedPreparationV1{}, ErrRecovery
			}
		}
	}
	expected := clone(before)
	expected.LegacyFirewall = TableStateV1{Presence: Present, Revision: &saved.Firewall}
	_, want, err := v2Canonical(expected)
	_, actual, other := v2Canonical(planned)
	_, d1, _ := v2Canonical(deps)
	_, d2, _ := v2Canonical(baselineDeps)
	if err != nil || other != nil || want != actual || d1 != d2 || routedHistoricalWitnessV2(previous, saved.Composite.Hash, load) != nil {
		return RoutedPreparationV1{}, ErrRecovery
	}
	return RoutedPreparationV1{Before: before, Target: after, Dependencies: deps}, nil
}

func routedNoNetworkBootPreparationV2(input RoutedPreparationV1, baseline RoutedBaselineV1, target RoutedActivationBundleV1, previous v2Configuration, load func(string, any) error) (RoutedPreparationV1, error) {
	before, e1 := CanonicalOwned(input.Before)
	after, e2 := CanonicalOwned(input.Target)
	deps, e3 := CanonicalDependencies(input.Dependencies)
	planned, e4 := CanonicalOwned(baseline.Owned)
	saved, e5 := CanonicalRoutedActivationBundleV1(baseline.Saved)
	baseDeps, e6 := CanonicalDependencies(baseline.Dependencies)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || deps.Version != 2 || before.Version != 2 || after.Version != 2 || before.LegacyFirewall.Presence != Absent || after.LegacyFirewall.Revision == nil || after.LegacyFirewall.Revision.Hash != target.Firewall.Hash || saved.Composite.Hash != target.Composite.Hash || !RoutedOwnershipMatchesDependencies(before, deps) || !RoutedOwnershipMatchesDependencies(after, deps) {
		return RoutedPreparationV1{}, ErrRecovery
	}
	for _, service := range target.LocalServices.Config.LocalServices.Services {
		if service.Enabled {
			return RoutedPreparationV1{}, ErrRecovery
		}
	}
	_, a, _ := v2Canonical(after)
	_, b, _ := v2Canonical(planned)
	_, d1, _ := v2Canonical(deps)
	_, d2, _ := v2Canonical(baseDeps)
	if a != b || d1 != d2 || routedHistoricalWitnessV2(previous, saved.Composite.Hash, load) != nil {
		return RoutedPreparationV1{}, ErrRecovery
	}
	return RoutedPreparationV1{Before: before, Target: after, Dependencies: deps}, nil
}

func routedHistoricalWitnessV2(state v2Configuration, hash string, load func(string, any) error) error {
	if !validHash(hash) || load == nil {
		return errV2Unavailable
	}
	if hash == state.Startup.Hash {
		// Saved Startup is authoritative even when imported Running differs.
		// This proves saved provenance, not that Startup was already effective.
		var audit v2CoordinatorAudit
		if load(state.AuditTip, &audit) != nil || audit.Format != v2Format || audit.Sequence != state.AuditSequence || audit.Startup != hash || audit.Running != state.Running.Hash {
			return errV2Unavailable
		}
		return nil
	}
	root := state.VerifiedIndex
	for depth := 0; root != "" && depth <= v2VerifiedDepthLimit; depth++ {
		var node v2VerifiedNode
		if load(root, &node) != nil || !validVerifiedNodeV2(node, depth, hash[:depth]) {
			return errV2Unavailable
		}
		if node.Kind == "branch" {
			root = node.Children[strings.IndexByte("0123456789abcdef", hash[depth])]
			continue
		}
		for _, entry := range node.Entries {
			if entry.Revision == hash {
				var audit v2CoordinatorAudit
				if load(entry.Audit, &audit) != nil || audit.Format != v2Format || audit.Operation != entry.Operation || audit.Running != hash || audit.Sequence > state.AuditSequence || audit.Result != "verified" && audit.Result != "applied" {
					return errV2Unavailable
				}
				return nil
			}
		}
		return errV2Unavailable
	}
	return errV2Unavailable
}

func routedBootRecordMatchesV2(plan RoutedSelectedPlanV1, record v2RecoveryRecord) bool {
	return plan.work.Kind == v2BootKind && plan.bootRecord != nil && validRecoveryRecordV2(record, plan.work.Lineage) && record.Kind == v2BootKind && reserveRecoveryFingerprintV2(record) == reserveRecoveryFingerprintV2(*plan.bootRecord) && record.Started.Add(10*time.Second).Equal(plan.Deadline())
}

func routedBootHistoryV2(plan RoutedSelectedPlanV1, state v2State, load func(string, any) error) error {
	if plan.work.Kind != v2BootKind {
		return nil
	}
	if state.Configuration == nil || load == nil {
		return errV2Unavailable
	}
	root, hash := state.Configuration.RecoveryIndex, checkpointDigest([]byte(plan.work.Operation))
	for depth := 0; root != "" && depth <= v2VerifiedDepthLimit; depth++ {
		var node v2VerifiedNode
		if load(root, &node) != nil || !validVerifiedNodeV2(node, depth, hash[:depth]) {
			return errV2Unavailable
		}
		if node.Kind == "branch" {
			root = node.Children[strings.IndexByte("0123456789abcdef", hash[depth])]
			continue
		}
		for _, entry := range node.Entries {
			if entry.Revision == hash {
				var record v2RecoveryRecord
				if entry.Operation != plan.work.Operation || load(entry.Audit, &record) != nil || !routedBootRecordMatchesV2(plan, record) {
					return errV2Unavailable
				}
				return nil
			}
		}
		return errV2Unavailable
	}
	return errV2Unavailable
}

func (c *v2Coordinator) publishRoutedBootWorkV2(ctx context.Context, record v2RecoveryRecord, previous, target v2Configuration, intent *v2CoordinatorIntent) error {
	if c.options.Routed == nil || c.store.reserves == nil || !validRoutedIdentityV1(c.options.RoutedIdentity) || record.BootID == nil || string(*record.BootID) != c.options.RoutedIdentity.BootID || !c.now().Before(record.Started.Add(10*time.Second)) {
		return ErrRecovery
	}
	applied, err := bundleFromConfigurationV2(target)
	if err != nil {
		return err
	}
	var saved RoutedActivationBundleV1
	if applied.Firewall.Config.SchemaVersion == 4 {
		saved = applied
	} else if previous.Firewall.Running.Config.SchemaVersion == 4 {
		saved, err = bundleFromConfigurationV2(previous)
	} else if active := c.store.state.RoutedActive; active != nil {
		var original RoutedSelectedPlanV1
		original, err = loadRoutedWorkV2(active.Work, c.store.state.Lineage, c.store.readObject)
		if err == nil {
			saved = original.Baseline().Saved
		}
	} else {
		return ErrRecovery
	}
	if err != nil || routedHistoricalWitnessV2(previous, saved.Composite.Hash, c.store.readObject) != nil {
		return fmt.Errorf("routed startup provenance: %w", ErrRecovery)
	}
	prepared, err := c.options.Routed.PrepareBoot(ctx, applied, saved)
	if err != nil {
		return fmt.Errorf("routed boot preparation: %w", err)
	}
	receipt, current, err := c.options.Routed.Observe(ctx)
	if err != nil || receipt.Phase != "bootstrap" || current != "" {
		return fmt.Errorf("routed boot initial observation: %w", ErrRecovery)
	}
	planned := clone(prepared.Before)
	planned.LegacyFirewall = TableStateV1{Presence: Present, Revision: &saved.Firewall}
	baseline := RoutedBaselineV1{Saved: saved, Owned: planned, Dependencies: prepared.Dependencies}
	prepared, err = routedBootPreparationV2(prepared, baseline, applied, previous, c.store.readObject)
	if err != nil {
		return fmt.Errorf("routed boot preparation validation: %w", err)
	}
	if c.bootFreshScope != nil || c.bootRebootScope != nil {
		proof, valid := compareScopeV4(c.bootFreshScope, c.bootRebootScope)
		_, beforeHash, e1 := v2Canonical(prepared.Before)
		_, depsHash, e2 := v2Canonical(prepared.Dependencies)
		if !valid || e1 != nil || e2 != nil || proof.before != beforeHash || proof.dependencies != depsHash || proof.next != c.options.RoutedIdentity {
			return ErrRecovery
		}
	}
	original, err := c.store.object(record)
	if err != nil {
		return err
	}
	work := v2RoutedWork{Version: 1, Kind: v2BootKind, BootRecord: original, BootBaseline: &baseline, Lineage: c.store.state.Lineage, Operation: record.ID, Generation: intent.TargetGeneration, Lease: record.ID, Deadline: record.Started.Add(10 * time.Second), Cold: true, Transition: RoutedTransitionV1{Version: 1, Operation: record.ID, Previous: intent.Previous, Target: intent.Target}}
	work.Scope = RoutedWorkScopeV1{Version: 1, Identity: c.options.RoutedIdentity, Lineage: work.Lineage, Generation: work.Generation}
	work.FreshScope = clone(c.bootFreshScope)
	work.RebootScope = clone(c.bootRebootScope)
	if c.bootBoundary != nil {
		work.Boundary = clone(c.bootBoundary)
	}
	intent.RoutedWork, err = c.publishRoutedObjectsV2(work, prepared)
	return err
}

func (c *v2Coordinator) applyRoutedBootV2(ctx context.Context, record v2RecoveryRecord, target v2Configuration) error {
	if _, err := c.bootRemainingV2(record); err != nil {
		return err
	}
	plan, err := c.selectedRoutedPlanV2()
	if err != nil || plan.work.Kind != v2BootKind || !routedBootRecordMatchesV2(plan, record) {
		return fmt.Errorf("routed boot selected work: %w", ErrRecovery)
	}
	if err = c.options.Routed.Bootstrap(ctx, plan, record.Started); err != nil {
		return fmt.Errorf("routed boot application: %w", err)
	}
	if _, err = c.bootRemainingV2(record); err != nil {
		return err
	}
	if !c.readback(target) {
		return fmt.Errorf("routed boot application readback: %w", ErrRecovery)
	}
	if err = c.options.Routed.Confirm(ctx, plan); err != nil {
		return fmt.Errorf("routed boot confirmation: %w", err)
	}
	if _, err = c.bootRemainingV2(record); err != nil {
		return err
	}
	if !c.readback(target) {
		return ErrRecovery
	}
	return nil
}
