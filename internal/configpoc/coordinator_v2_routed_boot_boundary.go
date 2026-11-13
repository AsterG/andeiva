package configpoc

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const v2RoutedBootBoundaryFeature = "configuration.routed-boot-boundary.v1"

// A boundary preserves the original work and its deadline. It is evidence of
// an OS incarnation change, never proof that the old target was restored.
type v2RoutedBootBoundary struct {
	FreshScope    *RoutedFreshScopeEvidenceV3            `json:"fresh_scope,omitempty"`
	Source        string                                 `json:"source_configuration"`
	OldWork       string                                 `json:"old_work"`
	Origin        *v2ReserveWorkRef                      `json:"origin,omitempty"`
	OldBoot       *v2ReserveWorkRef                      `json:"old_boot,omitempty"`
	NewOperation  string                                 `json:"new_boot_operation"`
	NewIdentity   networkexecutor.OwnedNamespaceIdentity `json:"new_identity"`
	CompletedBoot string                                 `json:"completed_boot,omitempty"`
	Resolution    string                                 `json:"resolution,omitempty"`
}

func validRoutedBootBoundaryShapeV2(b *v2RoutedBootBoundary) bool {
	if b == nil {
		return true
	}
	if b.FreshScope != nil && (!ValidRoutedFreshScopeEvidenceV3(*b.FreshScope) || b.FreshScope.New != b.NewIdentity || b.FreshScope.Work != b.OldWork) {
		return false
	}
	if !validHash(b.Source) || !validHash(b.OldWork) || b.NewOperation == "" || len(b.NewOperation) > 128 || !validRoutedIdentityV1(b.NewIdentity) || (b.Origin == nil) == (b.OldBoot == nil) {
		return false
	}
	if b.Origin != nil && !validReserveWorkRefV2(*b.Origin) {
		return false
	}
	if b.OldBoot != nil && !validReserveWorkRefV2(*b.OldBoot) {
		return false
	}
	return (b.CompletedBoot == "" || validHash(b.CompletedBoot)) && (b.Resolution == "" || validHash(b.Resolution)) && (b.Resolution == "" || b.CompletedBoot != "")
}

// The caller separately binds NewIdentity to retained trusted runtime resources.
// All old scope/deadline data comes from authenticated canonical objects.
func routedBootBoundarySourceV2(b v2RoutedBootBoundary, lineage string, load func(string, any) error) (v2Configuration, RoutedSelectedPlanV1, error) {
	var source v2Configuration
	if !validRoutedBootBoundaryShapeV2(&b) || load == nil || load(b.Source, &source) != nil || !validV2Configuration(&source) || source.Running.Config.SchemaVersion != 7 {
		return source, RoutedSelectedPlanV1{}, ErrRecovery
	}
	var header v2RoutedWork
	if load(b.OldWork, &header) != nil || header.Boundary != nil {
		return source, RoutedSelectedPlanV1{}, ErrRecovery
	}
	old, err := loadRoutedWorkV2(b.OldWork, lineage, load)
	if err != nil || old.work.Boundary != nil || old.Scope().Identity.BootID == b.NewIdentity.BootID && !freshScopeMatchesV3(b.FreshScope, old.Scope().Identity, b.NewIdentity, b.OldWork) || old.Scope().Identity.RunID == b.NewIdentity.RunID || old.Scope().Identity.UID != b.NewIdentity.UID || old.Scope().Identity.GID != b.NewIdentity.GID {
		return source, old, ErrRecovery
	}
	if b.FreshScope != nil && !freshScopeMatchesV3(b.FreshScope, old.Scope().Identity, b.NewIdentity, b.OldWork) {
		return source, old, ErrRecovery
	}
	if b.Origin != nil {
		var op v2Operation
		p := source.Pending
		if source.Intent != nil || source.RecoveryRequired || p == nil || p.Domain != "routed" || p.OriginCommit != b.Origin.ID || load(b.Origin.Object, &op) != nil || op.ID != b.Origin.ID || op.Lineage != lineage || op.Domain != "routed" || op.State != "final" || !op.Pinned || op.Outcome == nil || op.Outcome.Code != "applied_pending_confirmation" || !validReserveBundleV2(op.Reserve) || !reserveScopeMatchesOperationV2(op.Reserve, op) || op.Fingerprint != v2OperationFingerprint(op) || !v2RequestValid(op.Domain, op.Request) || op.Reserve.PlanIntent == nil || op.Reserve.PlanIntent.RoutedWork != b.OldWork || op.Subject != p.Owner || old.work.Subject != p.Owner || old.work.Operation != op.ID || old.Lease() != p.Lease || !old.Deadline().Equal(p.Deadline) || op.Outcome.ConfirmationDeadline == nil || !op.Outcome.ConfirmationDeadline.Equal(p.Deadline) || op.Outcome.ConfirmationLease != p.Lease || op.Outcome.RunningRevision != p.Target || old.target.Composite.Hash != source.Running.Hash {
			return source, old, ErrRecovery
		}
	} else {
		var record v2RecoveryRecord
		in := source.Intent
		if source.Pending != nil || in == nil || in.Kind != v2BootKind || in.Domain != "routed" || in.RoutedWork != b.OldWork || load(b.OldBoot.Object, &record) != nil || record.ID != b.OldBoot.ID || record.State != "pending" || !record.Pinned || !validRecoveryRecordV2(record, lineage) || !routedBootRecordMatchesV2(old, record) || validateRoutedWorkIntentV2(in, old, load) != nil || !validReserveBundleV2(record.Reserve) || record.Reserve.Scope.Kind != "boot" || reserveWorkV2(record.Reserve) != record.ID || record.Reserve.Scope.Boot != old.Scope().Identity.BootID || record.Reserve.Scope.Fingerprint != reserveRecoveryFingerprintV2(record) {
			return source, old, ErrRecovery
		}
	}
	return source, old, nil
}

func routedBootBoundaryProjectionV2(source v2Configuration) v2Configuration {
	projected := clone(source)
	projected.Intent, projected.Pending, projected.RecoveryRequired = nil, nil, false
	if source.Intent != nil && source.Intent.Kind == v2BootKind {
		projected.LastRecovery = projected.LastCompletedBoot
	}
	return projected
}

func boundaryRetainsOriginV2(state v2State, op v2Operation) bool {
	b := state.RoutedBootBoundary
	return b != nil && b.CompletedBoot == "" && b.Origin != nil && b.Origin.ID == op.ID && op.Pinned && op.State == "final" && op.Domain == "routed" && op.Outcome != nil && op.Outcome.Code == "applied_pending_confirmation"
}

func preservesRoutedBootBoundaryV2(previous, next v2State) bool {
	b := next.RoutedBootBoundary
	if b == nil || previous.RoutedBootBoundary != nil || previous.Configuration == nil || next.Configuration == nil || !hasFeatureV2(next, v2RoutedBootBoundaryFeature) || !validRoutedBootBoundaryShapeV2(b) || b.CompletedBoot != "" || b.Resolution != "" {
		return false
	}
	_, source, err := v2Canonical(*previous.Configuration)
	in := next.Configuration.Intent
	if err != nil || source != b.Source || in == nil || in.Kind != v2BootKind || in.Domain != "routed" || in.Operation != b.NewOperation || in.BootID == nil || string(*in.BootID) != b.NewIdentity.BootID || in.RoutedWork == "" || !reflect.DeepEqual(next.Configuration.Pending, previous.Configuration.Pending) || next.Configuration.RecoveryRequired {
		return false
	}
	if old := previous.Configuration.Intent; old != nil {
		return b.OldBoot != nil && old.Operation == b.OldBoot.ID && old.Kind == v2BootKind && old.RoutedWork == b.OldWork && old.BootID != nil && (*old.BootID != *in.BootID || b.FreshScope != nil)
	}
	return previous.Configuration.Pending != nil && b.Origin != nil && previous.Configuration.Pending.OriginCommit == b.Origin.ID
}

func (c *v2Coordinator) openRoutedBootBoundaryV2(ctx context.Context) (bool, error) {
	if c.store.state.RoutedDHCP != nil {
		return true, ErrRecovery
	}
	s := c.store
	if !hasFeatureV2(s.state, v2RoutedFeature) || c.options.Routed == nil || c.options.BootID == nil {
		return false, nil
	}
	if s.reserves == nil {
		return true, ErrRecovery
	}
	identity := c.options.RoutedIdentity
	if !validRoutedIdentityV1(identity) || identity != c.options.Routed.Identity() || identity.BootID != string(*c.options.BootID) {
		return true, ErrRecovery
	}
	if b := s.state.RoutedBootBoundary; b != nil {
		if b.NewIdentity != identity {
			return true, ErrRecovery
		}
		if s.state.Configuration.Intent != nil {
			return false, nil
		}
		if err := c.resumeRoutedLockedV2(ctx); err != nil {
			return true, err
		}
		if !c.readback(*s.state.Configuration) {
			return true, ErrRecovery
		}
		if err := c.finishRoutedBootBoundaryV2(); err != nil {
			return true, err
		}
		if s.reserves != nil {
			if err := s.reserves.maintain(s); err != nil {
				return true, err
			}
		}
		return true, c.publishLocalLocked()
	}
	cfg := s.state.Configuration
	if cfg.Pending == nil && cfg.Intent == nil {
		return false, nil
	}
	b := v2RoutedBootBoundary{NewIdentity: identity}
	var oldWork string
	if p := cfg.Pending; p != nil && cfg.Intent == nil && !cfg.RecoveryRequired {
		if p.Domain != "routed" || s.state.SystemBundle != nil {
			return true, ErrRecovery
		}
		op, err := s.lookupRetained(p.Owner, p.OriginCommit)
		if err != nil || op.Reserve == nil || op.Reserve.PlanIntent == nil {
			return true, ErrRecovery
		}
		oldWork = op.Reserve.PlanIntent.RoutedWork
		_, hash, err := v2Canonical(op)
		if err != nil {
			return true, err
		}
		b.Origin = &v2ReserveWorkRef{ID: op.ID, Object: hash}
	} else if in := cfg.Intent; in != nil && in.Kind == v2BootKind && in.Domain == "routed" && cfg.Pending == nil {
		var record v2RecoveryRecord
		if s.readObject(cfg.LastRecovery, &record) != nil || s.state.SystemBundle == nil || s.state.SystemBundle.Work != record.ID {
			return true, ErrRecovery
		}
		oldWork = in.RoutedWork
		b.OldBoot = &v2ReserveWorkRef{ID: record.ID, Object: cfg.LastRecovery}
		if !reflect.DeepEqual(record.Reserve, s.state.SystemBundle.Bundle) {
			return true, ErrRecovery
		}
	} else {
		return true, ErrRecovery
	}
	old, err := loadRoutedWorkV2(oldWork, s.state.Lineage, s.readObject)
	if err != nil {
		return true, ErrRecovery
	}
	if old.Scope().Identity.BootID == identity.BootID {
		if old.Scope().Identity == identity {
			return false, nil
		}
		b.FreshScope, err = c.proveFreshScopeV3(ctx, old.Scope().Identity, oldWork)
		if err != nil {
			return true, err
		}
	}
	if old.work.Boundary != nil || old.Scope().Identity.RunID == identity.RunID || old.Scope().Identity.UID != identity.UID || old.Scope().Identity.GID != identity.GID {
		return true, ErrRecovery
	}
	// Check the complete new-boot reserve before creating boundary objects.
	if err = s.physicalCapacity(2*v2OperationReserveBytes, 2*v2OperationReserveInodes); err != nil {
		return true, err
	}
	if !closingBudgetFitsV2(s.used.Bytes, s.state.ReservedBytes, 2*v2OperationReserveBytes, s.budget.Bytes) || !closingBudgetFitsV2(s.used.Inodes, s.state.ReservedInodes, 2*v2OperationReserveInodes, s.budget.Inodes) {
		return true, errV2Limited
	}
	b.Source, err = s.object(*cfg)
	if err != nil {
		return true, err
	}
	if b.Origin != nil {
		op, e := s.lookupRetained(cfg.Pending.Owner, cfg.Pending.OriginCommit)
		if e != nil {
			return true, e
		}
		hash, e := s.object(op)
		if e != nil || hash != b.Origin.Object {
			return true, ErrRecovery
		}
	}
	b.OldWork = oldWork
	b.NewOperation, err = v2ID("boot", s.selection.Sequence+1)
	if err != nil {
		return true, err
	}
	if _, _, err = routedBootBoundarySourceV2(b, s.state.Lineage, s.readObject); err != nil {
		return true, err
	}
	c.bootBoundary = &b
	defer func() { c.bootBoundary = nil }()
	if err = c.bootStartupLocked(ctx, *c.options.BootID); err != nil {
		return true, fmt.Errorf("fresh boundary boot: %w", err)
	}
	if err = c.finishRoutedBootBoundaryV2(); err != nil {
		return true, fmt.Errorf("fresh boundary completion: %w", err)
	}
	if s.reserves != nil {
		if err = s.reserves.maintain(s); err != nil {
			return true, fmt.Errorf("fresh boundary retirement: %w", err)
		}
	}
	return true, c.publishLocalLocked()
}

func (c *v2Coordinator) finishRoutedBootBoundaryV2() error {
	s := c.store
	b := clone(s.state.RoutedBootBoundary)
	if b == nil {
		return nil
	}
	if s.reserves == nil {
		return ErrRecovery
	}
	if b.CompletedBoot != "" {
		return validateRoutedBootBoundaryV2(s.state, s.readObject)
	}
	if s.state.Configuration.Intent != nil || s.state.Configuration.Pending != nil || s.state.Configuration.RecoveryRequired {
		return ErrRecovery
	}
	var completed v2RecoveryRecord
	hash := s.state.Configuration.LastCompletedBoot
	if s.readObject(hash, &completed) != nil || completed.ID != b.NewOperation || completed.Kind != v2BootKind || completed.State != "final" || completed.BootID == nil || string(*completed.BootID) != b.NewIdentity.BootID || completed.Pinned {
		return ErrRecovery
	}
	_, old, err := routedBootBoundarySourceV2(*b, s.state.Lineage, s.readObject)
	if err != nil {
		return err
	}
	var target v2Configuration
	if s.readObject(completed.Target, &target) != nil || target.Running.Hash != s.state.Configuration.Running.Hash {
		return ErrRecovery
	}
	b.CompletedBoot = hash
	st := clone(s.state)
	cfg := clone(*st.Configuration)
	// Finality describes the already verified fresh Startup. Reuse its exact
	// completion time so an interrupted bookkeeping retry has identical bytes.
	at := *completed.Completed
	if at.Before(s.state.Clock) {
		return ErrRecovery
	}
	until := at.Add(30 * 24 * time.Hour)
	var record v2RecoveryRecord
	if b.Origin != nil {
		origin, e := s.lookupRetained(old.work.Subject, b.Origin.ID)
		if e != nil || !origin.Pinned || origin.Outcome == nil || origin.Outcome.ConfirmationDeadline == nil || !origin.Outcome.ConfirmationDeadline.Equal(old.Deadline()) {
			return ErrRecovery
		}
		restore, e := s.reserves.recoveryAllowance(s, origin)
		if e != nil {
			return e
		}
		defer restore()
		id, e := v2ID("boot-boundary", s.selection.Sequence+1)
		if e != nil {
			return e
		}
		newBoot := v2BootID(b.NewIdentity.BootID)
		record = v2RecoveryRecord{Format: v2Format, ID: id, Origin: origin.ID, Lease: old.Lease(), Subject: origin.Subject, Lineage: st.Lineage, Kind: "boot_boundary", State: "final", Previous: b.Source, Target: completed.Target, BootID: &newBoot, Started: completed.Started, Completed: &at, RetainUntil: &until, SupersededBy: hash, BootBoundary: clone(b)}
		origin.Pinned = false
		v2Release(&st, origin)
		if e = s.putOperation(&st, origin); e != nil {
			return e
		}
	} else {
		if s.readObject(b.OldBoot.Object, &record) != nil || record.State != "pending" || !record.Pinned {
			return ErrRecovery
		}
		record.State, record.Pinned = "final", false
		record.Completed, record.RetainUntil = &at, &until
		record.SupersededBy, record.BootBoundary = hash, clone(b)
		if s.reserves == nil || s.reserves.verifyBundle(s, record.Reserve) != nil || s.state.ReservedBytes < v2OperationReserveBytes || s.state.ReservedInodes < v2OperationReserveInodes {
			return ErrRecovery
		}
		priorAllowance := s.allowance
		s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
		defer func() { s.allowance = priorAllowance }()
	}
	audit, err := c.appendAuditLocked(&cfg, record.ID, record.Origin, record.Lease, "system", record.Kind, "superseded_by_boot", st.Generation, at)
	if err != nil {
		return err
	}
	record.Audit = audit
	if err = validateRoutedBootSupersessionV2(record, st.Lineage, s.readObject); err != nil {
		return err
	}
	resolution, err := s.object(record)
	if err != nil {
		return err
	}
	cfg.RecoveryIndex, err = c.recoveryIndexPut(cfg.RecoveryIndex, record, resolution)
	if err != nil {
		return err
	}
	cfg.LastRecovery = resolution
	b.Resolution = resolution
	st.RoutedBootBoundary = b
	st.Configuration = &cfg
	st.Clock = at
	if err = c.point("before_boot_boundary_completion"); err != nil {
		return err
	}
	if err = s.publish(st); err != nil {
		return err
	}
	return c.point("after_boot_boundary_completion")
}

func validateRoutedBootSupersessionV2(record v2RecoveryRecord, lineage string, load func(string, any) error) error {
	if !validRecoveryRecordV2(record, lineage) || record.BootBoundary == nil || record.SupersededBy == "" || load == nil {
		return ErrRecovery
	}
	b := record.BootBoundary
	source, old, err := routedBootBoundarySourceV2(*b, lineage, load)
	if err != nil {
		return err
	}
	var completed v2RecoveryRecord
	if load(record.SupersededBy, &completed) != nil || !validRecoveryRecordV2(completed, lineage) || completed.Kind != v2BootKind || completed.State != "final" || completed.Pinned || completed.BootBoundary != nil || completed.SupersededBy != "" || completed.ID != b.NewOperation || completed.BootID == nil || string(*completed.BootID) != b.NewIdentity.BootID || completed.Reserve == nil || completed.Reserve.PlanIntent == nil {
		return ErrRecovery
	}
	newPlan, err := loadRoutedWorkV2(completed.Reserve.PlanIntent.RoutedWork, lineage, load)
	if err != nil || newPlan.Scope().Identity != b.NewIdentity || !routedBootRecordMatchesV2(newPlan, completed) || newPlan.work.Boundary == nil {
		return ErrRecovery
	}
	expected := clone(*b)
	expected.CompletedBoot, expected.Resolution = "", ""
	if !reflect.DeepEqual(newPlan.work.Boundary, &expected) {
		return ErrRecovery
	}
	var previous, target v2Configuration
	if load(completed.Previous, &previous) != nil || load(completed.Target, &target) != nil || !validBootTargetV2(previous, target) {
		return ErrRecovery
	}
	_, want, e1 := v2Canonical(routedBootBoundaryProjectionV2(source))
	_, actual, e2 := v2Canonical(previous)
	if e1 != nil || e2 != nil || want != actual {
		return ErrRecovery
	}
	var bootAudit, audit v2CoordinatorAudit
	if load(completed.Audit, &bootAudit) != nil || bootAudit.Operation != completed.ID || bootAudit.Kind != v2BootKind || bootAudit.Result != "verified" || bootAudit.Running != target.Running.Hash || bootAudit.Startup != target.Startup.Hash || load(record.Audit, &audit) != nil || audit.Operation != record.ID || audit.Kind != record.Kind || audit.Result != "superseded_by_boot" || audit.Subject != "system" || audit.Running != target.Running.Hash || audit.Startup != target.Startup.Hash || !audit.At.Equal(*record.Completed) || record.Completed.Before(*completed.Completed) {
		return ErrRecovery
	}
	if b.Origin != nil {
		if record.Kind != "boot_boundary" || record.Origin != b.Origin.ID || record.Subject != old.work.Subject || record.Lease != old.Lease() || record.Previous != b.Source || record.Target != completed.Target || record.BootID == nil || string(*record.BootID) != b.NewIdentity.BootID {
			return ErrRecovery
		}
	} else {
		var original v2RecoveryRecord
		if record.Kind != v2BootKind || record.ID != b.OldBoot.ID || load(b.OldBoot.Object, &original) != nil || reserveRecoveryFingerprintV2(record) != reserveRecoveryFingerprintV2(original) || !reflect.DeepEqual(record.Reserve, original.Reserve) {
			return ErrRecovery
		}
	}
	return nil
}

func validateRoutedBootBoundaryV2(state v2State, load func(string, any) error) error {
	b := state.RoutedBootBoundary
	if b == nil {
		return nil
	}
	if !hasFeatureV2(state, v2RoutedBootBoundaryFeature) || state.Configuration == nil || !validRoutedBootBoundaryShapeV2(b) {
		return ErrRecovery
	}
	if b.FreshScope != nil && !hasFeatureV2(state, v3RoutedFreshScopeFeature) {
		return ErrRecovery
	}
	source, _, err := routedBootBoundarySourceV2(*b, state.Lineage, load)
	if err != nil {
		return err
	}
	if b.CompletedBoot != "" {
		var record v2RecoveryRecord
		if b.Resolution == "" || load(b.Resolution, &record) != nil || validateRoutedBootSupersessionV2(record, state.Lineage, load) != nil {
			return ErrRecovery
		}
		copy := clone(*b)
		copy.Resolution = ""
		if !reflect.DeepEqual(record.BootBoundary, &copy) {
			return ErrRecovery
		}
		return nil
	}
	in := state.Configuration.Intent
	if in != nil && !reflect.DeepEqual(state.Configuration.Pending, source.Pending) {
		return ErrRecovery
	}
	if in == nil {
		var completed v2RecoveryRecord
		if load(state.Configuration.LastCompletedBoot, &completed) != nil || completed.State != "final" || completed.Kind != v2BootKind || completed.ID != b.NewOperation || completed.BootID == nil || string(*completed.BootID) != b.NewIdentity.BootID || completed.Reserve == nil || completed.Reserve.PlanIntent == nil {
			return ErrRecovery
		}
		p, err := loadRoutedWorkV2(completed.Reserve.PlanIntent.RoutedWork, state.Lineage, load)
		if err != nil || !reflect.DeepEqual(p.work.Boundary, b) || !routedBootRecordMatchesV2(p, completed) {
			return ErrRecovery
		}
		return nil
	}
	if in == nil || in.Kind != v2BootKind || in.Domain != "routed" || in.Operation != b.NewOperation || in.BootID == nil || string(*in.BootID) != b.NewIdentity.BootID {
		return ErrRecovery
	}
	p, err := loadRoutedWorkV2(in.RoutedWork, state.Lineage, load)
	if err != nil || !reflect.DeepEqual(p.work.Boundary, b) || validateRoutedWorkIntentV2(in, p, load) != nil {
		return ErrRecovery
	}
	return nil
}

func (s *v2Store) preservesRoutedBootBoundaryStateV2(next v2State) bool {
	p, n := s.state.RoutedBootBoundary, next.RoutedBootBoundary
	if p == nil {
		return n == nil || preservesRoutedBootBoundaryV2(s.state, next)
	}
	if n != nil {
		left, right := clone(*p), clone(*n)
		left.CompletedBoot, left.Resolution, right.CompletedBoot, right.Resolution = "", "", "", ""
		return reflect.DeepEqual(left, right) && (p.CompletedBoot == "" || p.CompletedBoot == n.CompletedBoot) && (p.Resolution == "" || p.Resolution == n.Resolution)
	}
	if p.CompletedBoot == "" || p.Resolution == "" || next.Configuration == nil || next.Configuration.Intent != nil || next.Configuration.Pending != nil || next.Configuration.RecoveryRequired || next.Configuration.LastCompletedBoot != p.CompletedBoot || next.ReserveArchiveRoot == "" {
		return false
	}
	var bundle *v2ReserveBundle
	if p.Origin != nil {
		var origin v2Operation
		if s.readObject(p.Origin.Object, &origin) != nil {
			return false
		}
		bundle = origin.Reserve
	} else if p.OldBoot != nil {
		var record v2RecoveryRecord
		if s.readObject(p.OldBoot.Object, &record) != nil {
			return false
		}
		bundle = record.Reserve
	}
	if bundle == nil {
		return false
	}
	reader := &v2Store{root: s.root, state: next, access: s.access, readOnly: s.readOnly}
	archive, found, err := reader.reserveArchiveBundleLookupV2(next.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: bundle.Claims.Admission}, "claim")
	return err == nil && found && validateArchiveFinalityV2(archive, next, reader.readObject) == nil
}
