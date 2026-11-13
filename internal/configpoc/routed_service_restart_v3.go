package configpoc

import (
	"context"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"reflect"
)

// Readonly assembly metadata, never permission to apply. The helper still
// authenticates the retirement FD and selected plan before any effect.
type RoutedServiceRestartViewV3 struct {
	Target, Saved RoutedActivationBundleV1
	Work          string
	old           networkexecutor.OwnedNamespaceIdentity
}

// Old must come from the authenticated root receipt, not an API parameter.
// This returns assembly metadata only. Selected effect authority is separate.
func (r *RoutedSelectionReaderV2) PrepareServiceRestartViewV3(ctx context.Context, old networkexecutor.OwnedNamespaceIdentity) (RoutedServiceRestartViewV3, error) {
	if r == nil || r.options.Policy != SelectionFullHistoryV2 {
		return RoutedServiceRestartViewV3{}, ErrRecovery
	}
	view, err := r.PrepareCurrentView(ctx)
	if err != nil || !validRoutedIdentityV1(old) || view.ServiceRestart == nil || view.ServiceRestart.old != old {
		return RoutedServiceRestartViewV3{}, ErrRecovery
	}
	return clone(*view.ServiceRestart), nil
}

func addServiceRestartViewV3(store *v2Store, identity networkexecutor.OwnedNamespaceIdentity, view *RoutedPrepareViewV2) error {
	cfg := store.state.Configuration
	work := ""
	if in := cfg.Intent; in != nil && in.Kind == v2BootKind && in.Domain == "routed" {
		work = in.RoutedWork
	} else if pending := cfg.Pending; pending != nil && pending.Domain == "routed" {
		op, err := store.lookupRetained(pending.Owner, pending.OriginCommit)
		if err != nil || op.Reserve == nil || op.Reserve.PlanIntent == nil {
			return ErrRecovery
		}
		work = op.Reserve.PlanIntent.RoutedWork
	} else if active := store.state.RoutedActive; active != nil {
		work = active.Work
	}
	if work == "" {
		return nil
	}
	var old v2RoutedWork
	if store.readObject(work, &old) != nil {
		return ErrRecovery
	}
	id := old.Scope.Identity
	if id.BootID != identity.BootID || id == identity {
		return nil
	}
	if id.RunID == identity.RunID || id.Namespace == identity.Namespace || id.Host != identity.Host || id.UID != identity.UID || id.GID != identity.GID {
		return ErrRecovery
	}
	target, err := serviceRestartTargetV3(*cfg, store.readObject)
	if err != nil {
		return err
	}
	r := &RoutedServiceRestartViewV3{Work: work, old: id}
	r.Target, err = bundleFromConfigurationV2(target)
	if err != nil {
		return err
	}
	switch {
	case r.Target.Firewall.Config.SchemaVersion == 4:
		r.Saved = r.Target
	case view.Current.Firewall.Config.SchemaVersion == 4:
		r.Saved = view.Current
	case view.Baseline != nil:
		r.Saved = view.Baseline.Saved
	default:
		return ErrRecovery
	}
	if routedHistoricalWitnessV2(*cfg, r.Saved.Composite.Hash, store.readObject) != nil {
		return ErrRecovery
	}
	view.ServiceRestart = r
	return nil
}

// A service restart is not an OS boot. Keep the exact selected source so
// recovery/history readers can derive its target without trusting a mode flag.
type v3RoutedServiceRestart struct {
	Source string                     `json:"source_configuration"`
	Scope  RoutedFreshScopeEvidenceV3 `json:"scope"`
}

func serviceRestartScopeV3(record v2RecoveryRecord) *RoutedFreshScopeEvidenceV3 {
	if record.ServiceRestart == nil {
		return nil
	}
	return &record.ServiceRestart.Scope
}

func serviceRestartTargetV3(source v2Configuration, load func(string, any) error) (v2Configuration, error) {
	if !validV2Configuration(&source) || source.Running.Config.SchemaVersion != 7 || source.RecoveryRequired || source.Firewall.Generation == ^uint64(0) {
		return v2Configuration{}, ErrRecovery
	}
	target := routedBootBoundaryProjectionV2(source)
	if pending := source.Pending; pending != nil {
		var previous v2Configuration
		if source.Intent != nil || pending.Domain != "routed" || load == nil || load(pending.Previous, &previous) != nil || !validV2Configuration(&previous) || previous.Intent != nil || previous.Pending != nil || previous.RecoveryRequired {
			return v2Configuration{}, ErrRecovery
		}
		target.Firewall.Running, target.Firewall.LastGood = previous.Firewall.Running, previous.Firewall.LastGood
		target.Firewall.Candidate = nil
		changed := target.LocalServices.Running.Hash != previous.LocalServices.Running.Hash || target.LocalServices.LastGood.Hash != previous.LocalServices.LastGood.Hash || target.LocalServices.Candidate != nil
		if changed && target.LocalServices.Generation == ^uint64(0) {
			return v2Configuration{}, ErrRecovery
		}
		target.LocalServices.Running, target.LocalServices.LastGood = previous.LocalServices.Running, previous.LocalServices.LastGood
		target.LocalServices.Candidate, target.Candidate, target.CandidateGroup = nil, nil, nil
		if changed {
			target.LocalServices.Generation++
		}
	} else if source.Intent != nil && (source.Intent.Kind != v2BootKind || source.Intent.Domain != "routed") {
		return v2Configuration{}, ErrRecovery
	}
	target.Firewall.Generation++
	if err := target.refresh(); err != nil {
		return v2Configuration{}, err
	}
	return target, nil
}

func validRecoveryBootTargetV3(record v2RecoveryRecord, previous, target v2Configuration, load func(string, any) error) bool {
	if record.ServiceRestart == nil {
		return validBootTargetV2(previous, target)
	}
	r := record.ServiceRestart
	if record.Kind != v2BootKind || record.BootID == nil || !ValidRoutedFreshScopeEvidenceV3(r.Scope) || r.Scope.New.BootID != string(*record.BootID) || !validHash(r.Source) || load == nil {
		return false
	}
	var source v2Configuration
	if load(r.Source, &source) != nil || !reflect.DeepEqual(routedBootBoundaryProjectionV2(source), previous) {
		return false
	}
	// Full G1/R2 walks the old work separately. Do not recursively reload its
	// entire history here while validating each recovery record.
	var old v2RoutedWork
	var oldTarget v2Configuration
	if load(r.Scope.Work, &old) != nil || old.Scope.Identity != r.Scope.Old || old.Lineage != record.Lineage || !old.Transition.ValidShape() || load(old.Transition.Target, &oldTarget) != nil || !validV2Configuration(&oldTarget) {
		return false
	}
	if pending := source.Pending; pending != nil {
		if pending.Domain != "routed" || pending.OriginCommit != old.Operation || pending.Owner != old.Subject || pending.Previous != old.Transition.Previous || pending.Target != oldTarget.Running.Hash || !pending.Deadline.Equal(old.Deadline) {
			return false
		}
	} else if in := source.Intent; in != nil {
		if in.Kind != v2BootKind || in.Domain != "routed" || in.RoutedWork != r.Scope.Work || in.Operation != old.Operation {
			return false
		}
	} else if source.Running.Hash != oldTarget.Running.Hash {
		return false
	}
	expected, err := serviceRestartTargetV3(source, load)
	return err == nil && validV2Configuration(&target) && reflect.DeepEqual(expected, target)
}
