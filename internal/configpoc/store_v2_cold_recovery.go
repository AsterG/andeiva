package configpoc

// These predicates recognize the exact existing completion projections. They
// do not publish, repair, extend a lease or accept a matching Running hash alone.
func coldCompletedPredecessorV1(v *selectedViewV2, a RoutedColdAnchorV1, p RoutedSelectedPlanV1, purpose RoutedSelectionPurposeV2) bool {
	if p.work.Kind != v2BootKind || !p.Cold() || p.work.Boundary != nil || p.bootRecord == nil || !routedBootRecordMatchesV2(p, *p.bootRecord) {
		return false
	}
	if purpose != SelectionBootstrapV2 && purpose != SelectionConfirmV2 && purpose != SelectionResumeV2 && purpose != SelectionMatchBeforeV2 && purpose != SelectionMatchTargetV2 {
		return false
	}
	var before v2Configuration
	if v.store.readObject(p.work.Transition.Previous, &before) != nil || !validV2Configuration(&before) || before.Intent != nil || before.Pending != nil || before.RecoveryRequired {
		return false
	}
	if in := a.configuration.Intent; in != nil && !in.Recovery && (in.Kind == OpCommit || in.Kind == OpRollback || in.Kind == OpConfirm) {
		return coldCompletedOperationV1(v, a, before)
	}
	if a.configuration.Pending != nil {
		return coldCompletedRecoveryV1(v, a, before)
	}
	return false
}

func coldCompletedOperationV1(v *selectedViewV2, a RoutedColdAnchorV1, before v2Configuration) bool {
	in := a.configuration.Intent
	op, err := v.store.lookupRetained(in.Subject, in.Operation)
	if err != nil || op.State != "final" || op.Pinned || op.Domain != "routed" || op.Request.Kind != in.Kind || op.Reserve == nil || op.Reserve.PlanIntent == nil || op.Reserve.PlanIntent.RoutedWork != a.reference.WorkHash || op.Outcome == nil || op.Outcome.Code != "failed_rolled_back" || op.Completed == nil {
		return false
	}
	var target v2Configuration
	if v.store.readObject(in.Previous, &target) != nil || !validV2Configuration(&target) || target.Intent != nil {
		return false
	}
	generation := a.reference.Generation
	if op.Request.Kind == OpConfirm {
		pending := target.Pending
		if pending == nil || pending.Domain != "routed" || pending.Owner != op.Subject || pending.OriginCommit != op.Request.Origin || pending.Target != op.Request.Target || generation == ^uint64(0) {
			return false
		}
		var original v2Configuration
		if v.store.readObject(pending.Previous, &original) != nil {
			return false
		}
		var ok bool
		target, ok = coldRevertedConfigurationV1(target, original)
		if !ok {
			return false
		}
		generation++
	}
	target.Intent = nil
	target.RecoveryRequired = false
	var audit v2CoordinatorAudit
	if v.store.readObject(op.Outcome.AuditHash, &audit) != nil || audit.Operation != op.ID || audit.Subject != op.Subject || audit.Kind != op.Request.Kind || audit.Result != "failed_rolled_back" || audit.Generation != generation || !audit.At.Equal(*op.Completed) || !coldCompletionAuditV1(a.configuration, target, audit) {
		return false
	}
	if op.Request.Kind == OpConfirm {
		if audit.OriginCommit != op.Request.Origin || a.configuration.Pending == nil || audit.Lease != a.configuration.Pending.Lease {
			return false
		}
	} else if audit.OriginCommit != "" || audit.Lease != "" {
		return false
	}
	if op.Outcome.Generation != generation || op.Outcome.RunningRevision != target.Running.Hash || op.Outcome.StartupRevision != target.Startup.Hash || op.Outcome.AuditFirst != audit.Sequence || op.Outcome.AuditLast != audit.Sequence {
		return false
	}
	target.AuditSequence = audit.Sequence
	target.AuditTip = op.Outcome.AuditHash
	return coldSameConfigurationV1(target, before)
}

func coldCompletedRecoveryV1(v *selectedViewV2, a RoutedColdAnchorV1, before v2Configuration) bool {
	source := a.configuration
	sourceHash := a.configurationHash
	if in := source.Intent; in != nil {
		if !in.Recovery || in.Domain != "routed" || in.RoutedWork != a.reference.WorkHash || (in.Kind != "restart" && in.Kind != "timeout") {
			return false
		}
		if v.store.readObject(in.Previous, &source) != nil {
			return false
		}
		sourceHash = in.Previous
	}
	pending := source.Pending
	if pending == nil || pending.Domain != "routed" || source.Intent != nil || source.RecoveryRequired {
		return false
	}
	var record v2RecoveryRecord
	if v.store.readObject(before.LastRecovery, &record) != nil || !validRecoveryRecordV2(record, v.ref.Lineage) || record.State != "final" || record.BootBoundary != nil || (record.Kind != "restart" && record.Kind != "timeout") || record.Previous != sourceHash || record.Origin != pending.OriginCommit || record.Subject != pending.Owner || record.Lease != pending.Lease {
		return false
	}
	var original v2Configuration
	if v.store.readObject(pending.Previous, &original) != nil {
		return false
	}
	target, ok := coldRevertedConfigurationV1(source, original)
	if !ok {
		return false
	}
	_, hash, err := v2Canonical(target)
	if err != nil || hash != record.Target {
		return false
	}
	if a.reference.Generation == ^uint64(0) {
		return false
	}
	var audit v2CoordinatorAudit
	if v.store.readObject(record.Audit, &audit) != nil || audit.Operation != record.ID || audit.OriginCommit != record.Origin || audit.Lease != record.Lease || audit.Subject != "system" || audit.Kind != record.Kind || audit.Result != "reverted" || audit.Generation != a.reference.Generation+1 || (audit.At.Before(record.Started) || audit.At.After(*record.Completed)) || !coldCompletionAuditV1(source, target, audit) {
		return false
	}
	entry, found, err := (&v2Coordinator{store: v.store}).verifiedLookup(before.RecoveryIndex, checkpointDigest([]byte(record.ID)))
	if err != nil || !found || entry.Operation != record.ID || entry.Audit != before.LastRecovery {
		return false
	}
	target.AuditSequence = audit.Sequence
	target.AuditTip = record.Audit
	target.LastRecovery = before.LastRecovery
	// Membership is verified in the contextual index; its other edges remain
	// subject to existing action/full graph validation, not a new index writer.
	target.RecoveryIndex = before.RecoveryIndex
	return coldSameConfigurationV1(target, before)
}

func coldCompletionAuditV1(source, target v2Configuration, audit v2CoordinatorAudit) bool {
	return source.AuditSequence != ^uint64(0) && audit.Format == v2Format && audit.Sequence == source.AuditSequence+1 && audit.Previous == source.AuditTip && audit.Running == target.Running.Hash && audit.Startup == target.Startup.Hash
}
func coldSameConfigurationV1(a, b v2Configuration) bool {
	_, left, e1 := v2Canonical(a)
	_, right, e2 := v2Canonical(b)
	return e1 == nil && e2 == nil && left == right
}
func coldRevertedConfigurationV1(current, original v2Configuration) (v2Configuration, bool) {
	if !validV2Configuration(&original) || original.Intent != nil {
		return v2Configuration{}, false
	}
	target := clone(current)
	target.Pending = nil
	target.Intent = nil
	target.Candidate = nil
	target.RecoveryRequired = false
	localChanged := target.LocalServices.Running.Hash != original.LocalServices.Running.Hash || target.LocalServices.LastGood.Hash != original.LocalServices.LastGood.Hash || target.LocalServices.Candidate != nil
	if target.Firewall.Generation == ^uint64(0) || localChanged && target.LocalServices.Generation == ^uint64(0) {
		return v2Configuration{}, false
	}
	target.Firewall.Running = original.Firewall.Running
	target.Firewall.LastGood = original.Firewall.LastGood
	target.Firewall.Candidate = nil
	target.Firewall.Generation++
	target.LocalServices.Running = original.LocalServices.Running
	target.LocalServices.LastGood = original.LocalServices.LastGood
	target.LocalServices.Candidate = nil
	target.CandidateGroup = nil
	if localChanged {
		target.LocalServices.Generation++
	}
	if target.refresh() != nil {
		return v2Configuration{}, false
	}
	return target, true
}
