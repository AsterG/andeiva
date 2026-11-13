package configpoc

import "context"

// RoutedColdAnchorV1 is in-process provenance captured from a selected header.
// Its private fields cannot be reconstructed from a wire tuple. It never proves
// full history integrity, current physical state or permission for new work.
type RoutedColdAnchorV1 struct {
	reader            *RoutedSelectionReaderV2
	reference         SelectionReferenceV2
	configuration     v2Configuration
	configurationHash string
}

func (a RoutedColdAnchorV1) Reference() SelectionReferenceV2 { return a.reference }

func (r *RoutedSelectionReaderV2) CaptureColdAnchorV1(ctx context.Context) (RoutedColdAnchorV1, error) {
	if r == nil || ctx == nil {
		return RoutedColdAnchorV1{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return RoutedColdAnchorV1{}, err
	}
	var anchor RoutedColdAnchorV1
	_, err := r.readWithGateV2(ctx, func(v *selectedViewV2) error {
		ref, e := selectedReferenceV2(v.store)
		if e != nil {
			return e
		}
		data, hash, e := v2Canonical(*v.store.state.Configuration)
		if e != nil || len(data) > reserveMetadataObjectLimitV2 {
			return ErrRecovery
		}
		if e = r.revalidate(ctx, v); e != nil {
			return e
		}
		if e = v.graph.closeSelectedV2(); e != nil {
			return e
		}
		anchor = RoutedColdAnchorV1{reader: r, reference: ref, configuration: clone(*v.store.state.Configuration), configurationHash: hash}
		return errInspectionHeaderV1
	})
	if ctx.Err() != nil {
		return RoutedColdAnchorV1{}, ctx.Err()
	}
	if err != errInspectionHeaderV1 {
		return RoutedColdAnchorV1{}, err
	}
	return anchor, nil
}

// ResolveColdContinuationV1 revalidates current action authority and only then
// relates it to the selection captured at attach. It cannot authorize a new
// ordinary Arm/Apply. The caller retains the writer barrier and guardian CAS.
func (r *RoutedSelectionReaderV2) ResolveColdContinuationV1(ctx context.Context, anchor RoutedColdAnchorV1, expected RoutedWorkReferenceV1, purpose RoutedSelectionPurposeV2) (out RoutedSelectedPlanV1, resultErr error) {
	if r == nil || ctx == nil || anchor.reader != r || !validHash(anchor.configurationHash) || !validHash(expected.Work) || expected.Lineage != anchor.reference.Lineage || expected.Generation == 0 {
		return out, ErrInvalid
	}
	if purpose == SelectionArmV2 || purpose == SelectionApplyV2 {
		return out, ErrDenied
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// A separate local reader policy selects the existing bounded action closure;
	// it never changes this reader's full-inspection policy or shares a cache.
	action := &RoutedSelectionReaderV2{area: r.area, options: r.options}
	action.options.Policy = SelectionActionAuthorityV2
	v, err := action.read(ctx)
	if err != nil {
		return out, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = RoutedSelectedPlanV1{}
			resultErr = ErrRecovery
		}
	}()
	var anchoredState v2State
	var anchoredSelection v2Selection
	if v.store.readObject(anchor.reference.Selection, &anchoredSelection) != nil || !v2ValidSelection(anchoredSelection) || anchoredSelection.State != anchor.reference.State || anchoredSelection.Sequence != anchor.reference.Sequence || anchoredSelection.Lineage != anchor.reference.Lineage || anchoredSelection.Previous != anchor.reference.Previous || v.store.readObject(anchor.reference.State, &anchoredState) != nil || !v2ValidState(anchoredState) || anchoredState.Generation != anchor.reference.Generation || anchoredState.Configuration == nil || !coldSameConfigurationV1(*anchoredState.Configuration, anchor.configuration) {
		return out, ErrRecovery
	}
	if v.ref.Lineage != anchor.reference.Lineage || v.ref.Sequence < anchor.reference.Sequence || v.ref.Generation < anchor.reference.Generation || v.ref.WorkHash != expected.Work {
		return out, ErrConflict
	}
	var plan RoutedSelectedPlanV1
	switch v.ref.Mode {
	case "intent":
		plan, err = selectedRoutedPlanFromStoreV2(v.store, r.options.Identity)
	case "pending":
		plan, _, err = selectedPendingReadbackV2(v.store)
	case "active":
		if v.store.state.Configuration.RecoveryRequired {
			return out, ErrRecovery
		}
		plan, err = loadRoutedWorkV2(v.ref.WorkHash, v.ref.Lineage, v.store.readObject)
		if err == nil {
			plan.resolution = v.store.state.RoutedActive.Side
		}
	default:
		return out, ErrDenied
	}
	if err != nil {
		return out, err
	}
	if plan.Reference() != expected || plan.Scope().Identity != r.options.Identity {
		return out, ErrConflict
	}
	if !selectedPurposeV2(v.store, plan, purpose) || (!coldContinuationLinkedV1(anchor, plan, purpose) && !coldCompletedPredecessorV1(v, anchor, plan, purpose)) {
		return out, ErrDenied
	}
	if err = action.revalidate(ctx, v); err != nil {
		return out, err
	}
	return plan, nil
}

func coldContinuationLinkedV1(anchor RoutedColdAnchorV1, plan RoutedSelectedPlanV1, purpose RoutedSelectionPurposeV2) bool {
	cfg := anchor.configuration
	if anchor.reference.WorkHash != "" && plan.Reference().Work == anchor.reference.WorkHash {
		if cfg.Intent != nil {
			// The selected work is immutable, including original receipt/deadline.
			return cfg.Intent.RoutedWork == plan.Reference().Work
		}
		if p := cfg.Pending; p != nil {
			return p.Domain == "routed" && p.OriginCommit == plan.work.Operation && p.Owner == plan.work.Subject && p.Lease == plan.Lease() && p.Deadline.Equal(plan.Deadline()) && p.Previous == plan.work.Transition.Previous && p.Target == plan.target.Composite.Hash
		}
		return anchor.reference.Mode == "active" && !cfg.RecoveryRequired && (purpose == SelectionResumeV2 || purpose == SelectionMatchBeforeV2 || purpose == SelectionMatchTargetV2)
	}
	if plan.work.Kind != v2BootKind || !plan.Cold() || plan.bootRecord == nil || !routedBootRecordMatchesV2(plan, *plan.bootRecord) {
		return false
	}
	if purpose != SelectionBootstrapV2 && purpose != SelectionConfirmV2 && purpose != SelectionResumeV2 && purpose != SelectionMatchBeforeV2 && purpose != SelectionMatchTargetV2 {
		return false
	}
	if boundary := plan.work.Boundary; boundary != nil {
		// The ordinary work loader has already validated the complete boundary,
		// including original scope, origin record, projection and fresh identity.
		if boundary.Source != anchor.configurationHash || boundary.OldWork != anchor.reference.WorkHash {
			return false
		}
		if cfg.Pending != nil {
			return boundary.Origin != nil && boundary.Origin.ID == cfg.Pending.OriginCommit
		}
		return cfg.Intent != nil && cfg.Intent.Kind == v2BootKind && boundary.OldBoot != nil && boundary.OldBoot.ID == cfg.Intent.Operation && boundary.OldBoot.Object == cfg.LastRecovery
	}
	// A fresh bootstrap can use only the exact quiescent configuration captured
	// at attach. Equal Running hashes do not establish a recovery lineage.
	return cfg.Intent == nil && cfg.Pending == nil && !cfg.RecoveryRequired && plan.work.Transition.Previous == anchor.configurationHash
}
