package configpoc

import (
	"reflect"
	"time"
)

func validRoutedDHCPConfigurationHeaderV4(h *v4RoutedDHCPConfigurationState, st v2State) bool {
	enabled := hasFeatureV2(st, v4RoutedDHCPConfigurationFeature)
	if enabled && (!hasFeatureV2(st, v3RoutedDHCPFeature) || !hasFeatureV2(st, v2RoutedFeature) || !hasFeatureV2(st, v2SharedReaderFeature) || st.RecoveryReserveVersion != 1) {
		return false
	}
	return h == nil || enabled && h.Version == 4 && (h.Continuation != "" || h.Transition != "") && (h.Continuation == "" || validHash(h.Continuation)) && (h.Transition == "" || validHash(h.Transition)) && st.RoutedDHCP != nil && st.RoutedDHCP.Phase == "applied"
}

type routedDHCPConfigurationContextV4 struct {
	transition         v4RoutedDHCPConfiguration
	sourceState        v2State
	sourceWork         v3RoutedDHCPWork
	before, target     v2Configuration
	operation          v2Operation
	finalConfiguration string
}

// Object/catalogue callbacks are read-only. The G1 caller additionally visits
// every source-state, audit, configuration and grouped-plan dependency.
func routedDHCPConfigurationContextV4Read(x v4RoutedDHCPConfiguration, st v2State, load func(string, any) error, lookup func(string, string) (v2Operation, error)) (out routedDHCPConfigurationContextV4, result error) {
	bad := func() (routedDHCPConfigurationContextV4, error) {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	if !validRoutedDHCPConfigurationShapeV4(x) || load == nil || lookup == nil || x.Impact != "preserve" || st.Lineage != x.Lineage || st.Configuration == nil || st.RoutedDHCP == nil || st.RoutedDHCP.Phase != "applied" || st.RoutedDHCP.Work != x.SourceWork {
		return bad()
	}
	out.transition = x
	var sel v2Selection
	if load(x.SourceSelection.Selection, &sel) != nil || !v2ValidSelection(sel) || sel.Lineage != x.Lineage || sel.Sequence != x.SourceSelection.Sequence || sel.Previous != x.SourceSelection.Previous || sel.State != x.SourceSelection.State || load(sel.State, &out.sourceState) != nil || !v2ValidState(out.sourceState) {
		return bad()
	}
	source := out.sourceState
	if source.Lineage != x.Lineage || source.Generation != x.Expected || source.Configuration == nil || source.RoutedDHCP == nil || source.RoutedDHCP.Phase != "applied" || !reflect.DeepEqual(source.RoutedDHCP, st.RoutedDHCP) || source.Configuration.Intent != nil || source.Configuration.RecoveryRequired {
		return bad()
	}
	var err error
	out.sourceWork, err = loadRoutedDHCPWorkV3(x.SourceWork, x.Lineage, load)
	if err != nil || load(x.Before, &out.before) != nil || load(x.Target, &out.target) != nil || !validV2Configuration(&out.before) || !validV2Configuration(&out.target) || !reflect.DeepEqual(*source.Configuration, out.before) {
		return bad()
	}
	if impact, e := routedDHCPConfigurationImpactV4(out.sourceWork, out.before, out.target); e != nil || impact != x.Impact {
		return bad()
	}
	out.operation, err = lookup(x.Subject, x.Operation)
	op := out.operation
	if err != nil || op.Retired || op.ID != x.Operation || op.Subject != x.Subject || op.Namespace != x.Namespace || op.Fingerprint != x.Fingerprint || op.Domain != "routed" || op.Expected != x.Expected {
		return bad()
	}
	// SourceSelection is an admission boundary, never a manufactured final
	// operation. G1 and the physical R2 reader also visit its bound admission.
	original, e := (&v2Store{state: source, objectReader: load}).lookupRetained(x.Subject, x.Operation)
	if e != nil || original.State != "accepted" || original.Pinned || !reserveScopeMatchesOperationV2(original.Reserve, original) || original.Reserve.Plan != nil || original.Reserve.PlanIntent != nil || !sameDHCPConfigurationOperationV4(original, op) {
		return bad()
	}
	matched := false
	for _, active := range source.ActiveReserves {
		if active.Work == original.ID && !active.CanonicalHeld && reflect.DeepEqual(active.Bundle, original.Reserve) {
			matched = true
		}
	}
	if !matched {
		return bad()
	}
	if op.State == "final" {
		if op.Completed == nil || op.RetainUntil == nil || op.RetainUntil.Before(op.Completed.Add(30*24*time.Hour)) || op.Outcome == nil || !validHash(op.Outcome.AuditHash) {
			return bad()
		}
	} else if !(&v2Store{state: st}).validOperation(op) {
		return bad()
	}
	projectionTime := op.Accepted
	lease := ""
	if x.Kind == "metadata" {
		if !metadataOperationV2(op.Request.Kind) || out.before.Pending != nil || out.target.Pending != nil || out.before.Running.Hash != out.target.Running.Hash {
			return bad()
		}
	} else {
		if op.Request.Kind != OpCommit || op.Request.ConfirmSeconds == nil || out.target.Pending == nil || x.Group.Side != "target" {
			return bad()
		}
		seconds := *op.Request.ConfirmSeconds
		projectionTime, err = routedDHCPConfigurationProjectionTimeV4(out.target.Pending.Deadline, seconds)
		if err != nil {
			return bad()
		}
		lease = out.target.Pending.Lease
		if projectionTime.Before(op.Accepted) || projectionTime.After(op.ExecuteBefore) {
			return bad()
		}
		plan, e := loadRoutedWorkV2(x.Group.Work, x.Lineage, load)
		if e != nil || plan.Cold() || plan.Scope().Identity != out.sourceWork.Snapshot.Identity || plan.work.Operation != op.ID || plan.work.Subject != op.Subject || plan.Lease() != lease || !plan.Deadline().Equal(out.target.Pending.Deadline) {
			return bad()
		}
		prior, target := plan.Bundles()
		if prior == nil || prior.Composite.Hash != out.before.Running.Hash || target.Composite.Hash != out.target.Running.Hash {
			return bad()
		}
		if op.Reserve == nil || op.Reserve.PlanIntent == nil || op.Reserve.PlanIntent.RoutedWork != x.Group.Work {
			return bad()
		}
	}
	projected, changed, e := routedTargetV2(&v2Store{state: source, objectReader: load}, op, out.before, projectionTime, lease)
	generation := x.Expected
	if changed {
		generation++
	}
	if e != nil || generation != x.Generation || !reflect.DeepEqual(projected, out.target) {
		return bad()
	}
	return out, nil
}

// Match the routed target's existing confirmation range before converting the
// unsigned wire value to nanoseconds. This reader does not change any deadline.
func routedDHCPConfigurationProjectionTimeV4(deadline time.Time, seconds uint64) (time.Time, error) {
	if seconds < 30 || seconds > 120 {
		return time.Time{}, ErrRecovery
	}
	return deadline.Add(-time.Duration(seconds) * time.Second), nil
}

func sameDHCPConfigurationOperationV4(original, current v2Operation) bool {
	if original.Reserve == nil || current.Reserve == nil || !reflect.DeepEqual(original.Reserve.Admission, current.Reserve.Admission) || !reflect.DeepEqual(original.Reserve.Claims, current.Reserve.Claims) || !reflect.DeepEqual(original.Reserve.ClosingEscrow, current.Reserve.ClosingEscrow) || !reflect.DeepEqual(original.Reserve.Scope, current.Reserve.Scope) {
		return false
	}
	original.State, current.State = "", ""
	original.Completed, current.Completed = nil, nil
	original.RetainUntil, current.RetainUntil = nil, nil
	original.Outcome, current.Outcome = nil, nil
	original.Pinned, current.Pinned = false, false
	original.Reserve, current.Reserve = nil, nil
	return reflect.DeepEqual(original, current)
}

func routedDHCPConfigurationContinuationV4Read(hash string, st v2State, load func(string, any) error) (routedDHCPConfigurationContextV4, error) {
	var receipt v4RoutedDHCPConfigurationContinuation
	if !validHash(hash) || load(hash, &receipt) != nil || receipt.Version != 4 || !validHash(receipt.Transition) || !validHash(receipt.Operation) || !validHash(receipt.Configuration) {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	var transition v4RoutedDHCPConfiguration
	if load(receipt.Transition, &transition) != nil {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	// The receipt pins the final immutable operation. It must remain readable
	// after its circular catalogue slot or actor namespace is retired.
	var op v2Operation
	if load(receipt.Operation, &op) != nil {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	c, err := routedDHCPConfigurationContextV4Read(transition, st, load, func(subject, id string) (v2Operation, error) {
		if op.Subject != subject || op.ID != id {
			return v2Operation{}, ErrRecovery
		}
		return op, nil
	})
	if err != nil {
		return c, err
	}
	var final v2Configuration
	if load(receipt.Configuration, &final) != nil || !validV2Configuration(&final) || op.State != "final" || op.Completed == nil || op.Outcome == nil || op.Outcome.Generation != transition.Generation || op.Outcome.RunningRevision != final.Running.Hash || op.Outcome.StartupRevision != final.Startup.Hash || !sameDHCPConfigurationV4(c.target, final) {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	code := "applied"
	if transition.Kind == "grouped" {
		code = "applied_pending_confirmation"
	}
	if op.Outcome.Code != code {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	// Metadata keeps Running unchanged, and a selected Running already has its
	// verified witness. verifiedInsert therefore preserves the exact index root.
	if transition.Kind == "metadata" && final.VerifiedIndex != c.before.VerifiedIndex {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	var audit v2CoordinatorAudit
	if load(op.Outcome.AuditHash, &audit) != nil || audit.Format != v2Format || audit.Subject != op.Subject || audit.Operation != op.ID || audit.Kind != op.Request.Kind || audit.Result != code || audit.Generation != transition.Generation || audit.Running != final.Running.Hash || audit.Startup != final.Startup.Hash || audit.Sequence != final.AuditSequence || op.Outcome.AuditHash != final.AuditTip || c.before.AuditSequence == ^uint64(0) || audit.Sequence != c.before.AuditSequence+1 || audit.Previous != c.before.AuditTip || op.Outcome.AuditFirst != audit.Sequence || op.Outcome.AuditLast != audit.Sequence || op.Outcome.DomainGeneration != domainSnapshotV2(&final, op.Domain).Generation || audit.At.Before(op.Accepted) || !audit.At.Equal(*op.Completed) {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	if final.Pending != nil && (op.Outcome.ConfirmationDeadline == nil || !op.Outcome.ConfirmationDeadline.Equal(final.Pending.Deadline) || op.Outcome.ConfirmationLease != final.Pending.Lease) {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	if final.Pending == nil && (audit.OriginCommit != "" || audit.Lease != "" || op.Outcome.ConfirmationDeadline != nil || op.Outcome.ConfirmationLease != "") || final.Pending != nil && (audit.OriginCommit != final.Pending.OriginCommit || audit.Lease != final.Pending.Lease) {
		return routedDHCPConfigurationContextV4{}, ErrRecovery
	}
	c.target = final
	c.finalConfiguration = receipt.Configuration
	return c, nil
}

// Original Work and its R2 scope remain bound to their ORIGINAL generation.
// Only a separate typed edge may bind current configuration to that source.
func validRoutedDHCPOriginalScopeV4(st v2State, w v3RoutedDHCPWork) bool {
	d := st.RoutedDHCP
	if !validRoutedDHCPShapeV3(st) || d == nil || d.Phase != "applied" || d.Bundle.Scope.Global != w.Generation || d.Bundle.Scope.Generation != w.Generation {
		return false
	}
	in := d.Bundle.PlanIntent
	return in.Operation == reserveWorkV2(d.Bundle) && in.Previous == w.Configuration && in.Target == w.Configuration && in.TargetGeneration == w.Generation && in.Subject == "" && in.Lease == "" && in.OriginCommit == "" && d.Bundle.Scope.Deadline.IsZero() && d.Bundle.Scope.Lease == ""
}

func exactDHCPConfigurationIntentV4(c routedDHCPConfigurationContextV4, current v2Configuration) bool {
	in := current.Intent
	current.Intent = nil
	if !reflect.DeepEqual(current, c.before) {
		return false
	}
	if in == nil {
		return c.operation.State == "accepted" || c.transition.Kind == "metadata" && c.operation.State == "final"
	}
	if c.transition.Kind == "metadata" {
		return false
	}
	x := c.transition
	work := ""
	if x.Group != nil {
		work = x.Group.Work
	}
	return in.Operation == x.Operation && in.Subject == x.Subject && in.Domain == "routed" && in.Kind == c.operation.Request.Kind && in.Previous == x.Before && in.Target == x.Target && in.TargetGeneration == x.Generation && in.RoutedWork == work && in.BootID == nil && !in.Recovery && in.GuardDeadline == nil && in.OriginCommit == "" && ((c.target.Pending == nil && in.Lease == "") || (c.target.Pending != nil && in.Lease == c.target.Pending.Lease))
}

// Audit and verified-history indexes remain independently visited by G1.
func sameDHCPConfigurationV4(a, b v2Configuration) bool {
	a.AuditSequence, b.AuditSequence = 0, 0
	a.AuditTip, b.AuditTip = "", ""
	a.VerifiedIndex, b.VerifiedIndex = "", ""
	return reflect.DeepEqual(a, b)
}
