package configpoc

import (
	"context"
	"time"
)

func routedPreparationV2(input RoutedPreparationV1, previous, target RoutedActivationBundleV1, cold bool) (RoutedPreparationV1, error) {
	before, err := CanonicalOwned(input.Before)
	if err != nil {
		return RoutedPreparationV1{}, err
	}
	after, err := CanonicalOwned(input.Target)
	if err != nil {
		return RoutedPreparationV1{}, err
	}
	deps, err := CanonicalDependencies(input.Dependencies)
	if err != nil || !RoutedOwnershipMatchesDependencies(before, deps) || !RoutedOwnershipMatchesDependencies(after, deps) {
		return RoutedPreparationV1{}, ErrRecovery
	}
	if target.Firewall.Config.SchemaVersion == 4 {
		if cold || (after.NetworkState != Baseline && after.NetworkState != NoNetwork) || after.RoutedFirewall.Presence != Absent || after.LegacyFirewall.Revision == nil || after.LegacyFirewall.Revision.Hash != target.Firewall.Hash || after.LocalServices.Revision != nil && after.LocalServices.Revision.Hash != target.LocalServices.Hash {
			return RoutedPreparationV1{}, ErrRecovery
		}
		if previous.Firewall.Config.SchemaVersion == 4 {
			if deps.Version != 2 || before.NetworkState != NoNetwork || after.NetworkState != NoNetwork {
				return RoutedPreparationV1{}, ErrRecovery
			}
		} else if previous.Firewall.Config.Routed == nil || deps.Network.Hash != previous.Firewall.Config.Routed.Network.Hash {
			return RoutedPreparationV1{}, ErrRecovery
		}
		if after.LocalServices.Presence == Absent {
			for _, service := range target.LocalServices.Config.LocalServices.Services {
				if service.Enabled {
					return RoutedPreparationV1{}, ErrRecovery
				}
			}
		}
	} else if target.Firewall.Config.Routed == nil || deps.Network.Hash != target.Firewall.Config.Routed.Network.Hash || after.NetworkState != Configured || after.LegacyFirewall.Presence != Absent || after.RoutedFirewall.Revision == nil || after.RoutedFirewall.Revision.Hash != target.Firewall.Hash || after.LocalServices.Revision == nil || after.LocalServices.Revision.Hash != target.LocalServices.Hash {
		return RoutedPreparationV1{}, ErrRecovery
	}
	if previous.Firewall.Config.SchemaVersion == 4 {
		if (before.NetworkState != Baseline && before.NetworkState != NoNetwork) || before.RoutedFirewall.Presence != Absent || (before.LegacyFirewall.Revision != nil && before.LegacyFirewall.Revision.Hash != previous.Firewall.Hash) || (before.LocalServices.Revision != nil && before.LocalServices.Revision.Hash != previous.LocalServices.Hash) {
			return RoutedPreparationV1{}, ErrRecovery
		}
		if before.LegacyFirewall.Presence == Absent && len(previous.Firewall.Config.Rules) != 0 {
			return RoutedPreparationV1{}, ErrRecovery
		}
		if before.LocalServices.Presence == Absent {
			for _, service := range previous.LocalServices.Config.LocalServices.Services {
				if service.Enabled {
					return RoutedPreparationV1{}, ErrRecovery
				}
			}
		}
	} else if cold || previous.Firewall.Config.SchemaVersion != 6 || before.NetworkState != Configured || before.LegacyFirewall.Presence != Absent || before.RoutedFirewall.Revision == nil || before.RoutedFirewall.Revision.Hash != previous.Firewall.Hash || before.LocalServices.Revision == nil || before.LocalServices.Revision.Hash != previous.LocalServices.Hash {
		return RoutedPreparationV1{}, ErrRecovery
	}
	return RoutedPreparationV1{Before: before, Target: after, Dependencies: deps}, nil
}

func bundleFromConfigurationV2(state v2Configuration) (RoutedActivationBundleV1, error) {
	bundle, err := NewRoutedActivationBundleV1(state.Firewall.Running, state.LocalServices.Running)
	if err != nil || bundle.Composite.Hash != state.Running.Hash {
		return RoutedActivationBundleV1{}, ErrRecovery
	}
	return bundle, nil
}

func (c *v2Coordinator) publishRoutedWorkV2(ctx context.Context, op v2Operation, previous, target v2Configuration, intent *v2CoordinatorIntent) error {
	if op.Domain != "routed" || metadataOperationV2(op.Request.Kind) {
		return nil
	}
	if c.options.Routed == nil || c.store.reserves == nil || intent == nil || !validRoutedIdentityV1(c.options.RoutedIdentity) {
		return ErrRecovery
	}
	if op.Request.Kind == OpConfirm {
		if previous.Pending == nil {
			return ErrRecovery
		}
		origin, err := c.store.lookupRetained(op.Subject, previous.Pending.OriginCommit)
		if err != nil || origin.Reserve == nil || origin.Reserve.PlanIntent == nil || !validHash(origin.Reserve.PlanIntent.RoutedWork) {
			return ErrRecovery
		}
		intent.RoutedWork = origin.Reserve.PlanIntent.RoutedWork
		return nil
	}
	if target.Pending == nil || target.Pending.OriginCommit != op.ID || !c.now().Before(target.Pending.Deadline) {
		return ErrRecovery
	}
	prior, err := bundleFromConfigurationV2(previous)
	if err != nil {
		return err
	}
	applied, err := bundleFromConfigurationV2(target)
	if err != nil {
		return err
	}
	var baseline *RoutedBaselineV1
	if c.store.state.RoutedActive != nil {
		_, baseline, err = c.routedBaselineV2()
		if err != nil {
			return err
		}
	}
	prepared, err := c.options.Routed.Prepare(ctx, applied, baseline)
	if err != nil {
		return err
	}
	receipt, hash, err := c.options.Routed.Observe(ctx)
	if err != nil {
		return ErrRecovery
	}
	cold := receipt.Phase == "bootstrap" && hash == "" && previous.Firewall.Running.Config.SchemaVersion == 4
	if !cold && (receipt.Phase != "idle" || hash != previous.Running.Hash) {
		return ErrRecovery
	}
	prepared, err = routedPreparationV2(prepared, prior, applied, cold)
	if err != nil {
		return err
	}
	work := v2RoutedWork{Version: 1, Lineage: c.store.state.Lineage, Operation: op.ID, Subject: op.Subject, Generation: intent.TargetGeneration, Lease: target.Pending.Lease, Deadline: target.Pending.Deadline, Cold: cold, Transition: RoutedTransitionV1{Version: 1, Operation: op.ID, Previous: intent.Previous, Target: intent.Target}}
	work.Scope = RoutedWorkScopeV1{Version: 1, Identity: c.options.RoutedIdentity, Lineage: work.Lineage, Generation: work.Generation}
	if hasFeatureV2(c.store.state, v2RoutedNoNetworkFeature) {
		work.Kind = op.Request.Kind
	}
	if !cold {
		baselineHash, _, err := c.routedBaselineV2()
		if err != nil {
			return err
		}
		work.Baseline = baselineHash
	}
	intent.RoutedWork, err = c.publishRoutedObjectsV2(work, prepared)
	return err
}

func (c *v2Coordinator) publishRoutedObjectsV2(work v2RoutedWork, prepared RoutedPreparationV1) (string, error) {
	var err error
	work.Transition.BeforeOwned, err = c.store.object(v2RoutedOwned{1, work.Lineage, work.Operation, "before", prepared.Before})
	if err != nil {
		return "", err
	}
	work.Transition.TargetOwned, err = c.store.object(v2RoutedOwned{1, work.Lineage, work.Operation, "target", prepared.Target})
	if err != nil {
		return "", err
	}
	work.Transition.Dependencies, err = c.store.object(v2RoutedDependencies{1, work.Lineage, work.Operation, prepared.Dependencies})
	if err != nil {
		return "", err
	}
	return c.store.object(work)
}

// loadRoutedWorkV2 validates typed payloads without accessing engines or pools.
// G1 uses its bounded reader; effects add selected-selector/reservation checks.
func loadRoutedWorkV2(hash, lineage string, load func(string, any) error) (RoutedSelectedPlanV1, error) {
	return loadRoutedWorkDepthV2(hash, lineage, load, false)
}

func loadRoutedWorkDepthV2(hash, lineage string, load func(string, any) error, original bool) (RoutedSelectedPlanV1, error) {
	var plan RoutedSelectedPlanV1
	if !validHash(hash) || load == nil || load(hash, &plan.work) != nil {
		return plan, errV2Unavailable
	}
	work := plan.work
	if original && (!work.Cold || work.Baseline != "") || work.Cold && work.Baseline != "" || !work.Cold && !validHash(work.Baseline) {
		return plan, errV2Unavailable
	}
	boot := work.Kind == v2BootKind
	if work.Boundary != nil && !boot {
		return plan, errV2Unavailable
	}
	if work.Kind != "" && work.Kind != OpCommit && work.Kind != OpRollback && !boot || boot && (work.Subject != "" || !work.Cold || !validHash(work.BootRecord) || work.Lease != work.Operation || work.BootBaseline == nil) || !boot && (work.Subject == "" || work.BootRecord != "" || work.BootBaseline != nil) {
		return plan, errV2Unavailable
	}
	if work.Version != 1 || work.Lineage != lineage || work.Operation == "" || work.Generation == 0 || work.Lease == "" || work.Deadline.IsZero() || work.Deadline.Location() != time.UTC || !work.Transition.ValidShape() || work.Transition.Operation != work.Operation || work.Scope.Version != 1 || work.Scope.Lineage != lineage || work.Scope.Generation != work.Generation || !validRoutedIdentityV1(work.Scope.Identity) {
		return plan, errV2Unavailable
	}
	var before, target v2Configuration
	if load(work.Transition.Previous, &before) != nil || load(work.Transition.Target, &target) != nil || !validV2Configuration(&before) || !validV2Configuration(&target) || before.Intent != nil || target.Intent != nil {
		return plan, errV2Unavailable
	}
	var err error
	plan.previous, err = bundleFromConfigurationV2(before)
	if err != nil {
		return plan, errV2Unavailable
	}
	plan.target, err = bundleFromConfigurationV2(target)
	if err != nil {
		return plan, errV2Unavailable
	}
	if boot {
		if boundary := work.Boundary; boundary != nil {
			source, _, e := routedBootBoundarySourceV2(*boundary, lineage, load)
			_, expected, e1 := v2Canonical(routedBootBoundaryProjectionV2(source))
			if e != nil || e1 != nil || expected != work.Transition.Previous || boundary.NewOperation != work.Operation || boundary.NewIdentity != work.Scope.Identity || boundary.CompletedBoot != "" || boundary.Resolution != "" {
				return plan, errV2Unavailable
			}
		}
		var record v2RecoveryRecord
		if load(work.BootRecord, &record) != nil || !validRecoveryRecordV2(record, lineage) || record.Kind != v2BootKind || record.State != "pending" || record.Reserve != nil || record.ID != work.Operation || record.Previous != work.Transition.Previous || record.Target != work.Transition.Target || record.BootID == nil || string(*record.BootID) != work.Scope.Identity.BootID || !record.Started.Add(10*time.Second).Equal(work.Deadline) || !validBootTargetV2(before, target) {
			return plan, errV2Unavailable
		}
		plan.bootRecord = &record
	} else if target.Pending == nil || target.Pending.OriginCommit != work.Operation || target.Pending.Owner != work.Subject || target.Pending.Lease != work.Lease || target.Pending.Domain != "routed" || !target.Pending.Deadline.Equal(work.Deadline) || target.Pending.Previous != work.Transition.Previous {
		return plan, errV2Unavailable
	}
	var priorOwned, targetOwned v2RoutedOwned
	var dependencies v2RoutedDependencies
	if load(work.Transition.BeforeOwned, &priorOwned) != nil || load(work.Transition.TargetOwned, &targetOwned) != nil || load(work.Transition.Dependencies, &dependencies) != nil || priorOwned.Version != 1 || targetOwned.Version != 1 || dependencies.Version != 1 || priorOwned.Lineage != lineage || targetOwned.Lineage != lineage || dependencies.Lineage != lineage || priorOwned.Operation != work.Operation || targetOwned.Operation != work.Operation || dependencies.Operation != work.Operation || priorOwned.Role != "before" || targetOwned.Role != "target" {
		return plan, errV2Unavailable
	}
	physicalPrevious := plan.previous
	if boot {
		physicalPrevious, err = CanonicalRoutedActivationBundleV1(work.BootBaseline.Saved)
		if err != nil {
			return plan, errV2Unavailable
		}
	}
	if boot {
		plan.preparation, err = routedBootPreparationV2(RoutedPreparationV1{priorOwned.Value, targetOwned.Value, dependencies.Value}, *work.BootBaseline, plan.target, before, load)
	} else {
		plan.preparation, err = routedPreparationV2(RoutedPreparationV1{priorOwned.Value, targetOwned.Value, dependencies.Value}, physicalPrevious, plan.target, work.Cold)
	}
	if err != nil {
		return plan, errV2Unavailable
	}
	if work.Baseline != "" {
		baseline, err := loadRoutedWorkDepthV2(work.Baseline, lineage, load, true)
		if err != nil || baseline.work.Scope.Identity != work.Scope.Identity || baseline.work.Generation >= work.Generation {
			return plan, errV2Unavailable
		}
		plan.baseline = baseline.Baseline()
	} else {
		plan.baseline = &RoutedBaselineV1{Saved: physicalPrevious, Owned: plan.preparation.Before, Dependencies: plan.preparation.Dependencies}
		if boot {
			plan.baseline = clone(work.BootBaseline)
		}
	}
	if !routedBaselineDependenciesMatchV2(plan.preparation.Dependencies, plan.baseline.Dependencies) {
		return plan, errV2Unavailable
	}
	if plan.target.Firewall.Config.SchemaVersion == 4 && !(work.Kind == OpCommit && plan.preparation.Dependencies.Version == 2) {
		_, expected, e1 := v2Canonical(plan.baseline.Owned)
		_, actual, e2 := v2Canonical(plan.preparation.Target)
		if e1 != nil || e2 != nil || expected != actual || plan.target.Composite.Hash != plan.baseline.Saved.Composite.Hash {
			return plan, errV2Unavailable
		}
	}
	return plan, nil
}

func (c *v2Coordinator) routedBaselineV2() (string, *RoutedBaselineV1, error) {
	active := c.store.state.RoutedActive
	if active == nil {
		return "", nil, ErrRecovery
	}
	plan, err := loadRoutedWorkV2(active.Work, c.store.state.Lineage, c.store.readObject)
	if err != nil || plan.Scope().Identity != c.options.RoutedIdentity {
		return "", nil, ErrRecovery
	}
	hash := plan.work.Baseline
	if plan.work.Cold {
		hash = active.Work
	}
	return hash, plan.Baseline(), nil
}

func (c *v2Coordinator) selectedRoutedPlanV2() (RoutedSelectedPlanV1, error) {
	s := c.store
	intent := s.state.Configuration.Intent
	if intent == nil || intent.Domain != "routed" || c.options.Routed == nil || s.reserves == nil || s.reserves.verifySelected(s) != nil {
		return RoutedSelectedPlanV1{}, ErrRecovery
	}
	data, err := checkpointRead(s.root, "selected.json", 4096)
	var selected v2Selector
	if err != nil || checkpointDecode(data, &selected) != nil || selected != s.selector {
		return RoutedSelectedPlanV1{}, ErrRecovery
	}
	plan, err := loadRoutedWorkV2(intent.RoutedWork, s.state.Lineage, s.readObject)
	if err != nil {
		return plan, err
	}
	if err = validateRoutedWorkIntentV2(intent, plan, s.readObject); err != nil {
		return plan, err
	}
	if plan.work.Scope.Identity != c.options.RoutedIdentity {
		return plan, ErrRecovery
	}
	if routedWorkUsesNoNetworkV2(plan) && !hasFeatureV2(s.state, v2RoutedNoNetworkFeature) {
		return plan, ErrRecovery
	}
	if plan.work.Kind == v2BootKind {
		var record v2RecoveryRecord
		if c.store.readObject(c.store.state.Configuration.LastRecovery, &record) != nil || !routedBootRecordMatchesV2(plan, record) {
			return plan, ErrRecovery
		}
	}
	if intent.Recovery {
		plan.resolution = "recovery-before"
	}
	return plan, nil
}

func validateRoutedWorkIntentV2(intent *v2CoordinatorIntent, plan RoutedSelectedPlanV1, load func(string, any) error) error {
	if intent == nil || intent.Domain != "routed" || !plan.Valid() {
		return ErrRecovery
	}
	if intent.Kind == v2BootKind {
		if !validBootIntentV2(intent) || plan.work.Kind != v2BootKind || intent.Operation != plan.work.Operation || intent.Previous != plan.work.Transition.Previous || intent.Target != plan.work.Transition.Target || intent.TargetGeneration != plan.work.Generation || string(*intent.BootID) != plan.work.Scope.Identity.BootID {
			return ErrRecovery
		}
		return nil
	}
	if !intent.Recovery && intent.Kind != OpConfirm && plan.work.Kind != "" && plan.work.Kind != intent.Kind {
		return ErrRecovery
	}
	if intent.Kind == OpConfirm || intent.Recovery {
		if intent.Recovery && (intent.OriginCommit != plan.work.Operation || intent.Lease != plan.work.Lease) {
			return ErrRecovery
		}
		var before v2Configuration
		if load(intent.Previous, &before) != nil || before.Pending == nil || before.Pending.OriginCommit != plan.work.Operation || before.Pending.Owner != plan.work.Subject || before.Pending.Lease != plan.work.Lease || !before.Pending.Deadline.Equal(plan.work.Deadline) || intent.Subject != plan.work.Subject {
			return ErrRecovery
		}
		expected := clone(before)
		expected.Intent, expected.Pending = nil, nil
		if expected.Firewall.Generation == ^uint64(0) {
			return ErrRecovery
		}
		expected.Firewall.Generation++
		if intent.Recovery {
			var original v2Configuration
			if load(plan.work.Transition.Previous, &original) != nil || !validV2Configuration(&original) {
				return ErrRecovery
			}
			localChanged := expected.LocalServices.Running.Hash != original.LocalServices.Running.Hash || expected.LocalServices.LastGood.Hash != original.LocalServices.LastGood.Hash || expected.LocalServices.Candidate != nil
			expected.Firewall.Running, expected.Firewall.LastGood, expected.Firewall.Candidate = original.Firewall.Running, original.Firewall.LastGood, nil
			expected.LocalServices.Running, expected.LocalServices.LastGood, expected.LocalServices.Candidate = original.LocalServices.Running, original.LocalServices.LastGood, nil
			expected.Candidate, expected.CandidateGroup, expected.RecoveryRequired = nil, nil, false
			if localChanged {
				if expected.LocalServices.Generation == ^uint64(0) {
					return ErrRecovery
				}
				expected.LocalServices.Generation++
			}
		} else {
			localChanged := expected.LocalServices.LastGood.Hash != expected.LocalServices.Running.Hash
			expected.Firewall.LastGood, expected.LocalServices.LastGood = expected.Firewall.Running, expected.LocalServices.Running
			if localChanged {
				if expected.LocalServices.Generation == ^uint64(0) {
					return ErrRecovery
				}
				expected.LocalServices.Generation++
			}
		}
		if expected.refresh() != nil {
			return ErrRecovery
		}
		_, hash, err := v2Canonical(expected)
		if err != nil || hash != intent.Target {
			return ErrRecovery
		}
	} else if intent.Operation != plan.work.Operation || intent.Subject != plan.work.Subject || intent.TargetGeneration != plan.work.Generation || intent.Previous != plan.work.Transition.Previous || intent.Target != plan.work.Transition.Target {
		return ErrRecovery
	}
	return nil
}
