package configpoc

func (c *v2Coordinator) validateReferencesLocked() error {
	s := c.store
	state := s.state.Configuration
	if state == nil || !validV2Configuration(state) {
		return errV2Unavailable
	}
	if err := c.pendingReferencesLocked(state); err != nil {
		return err
	}
	if state.AuditTip != "" {
		var audit v2CoordinatorAudit
		if s.readObject(state.AuditTip, &audit) != nil || audit.Format != v2Format || audit.Sequence != state.AuditSequence || audit.Generation != s.state.Generation || audit.Running != state.Running.Hash || audit.Startup != state.Startup.Hash {
			return errV2Unavailable
		}
	}
	if state.Pending == nil {
		proof, known, err := c.verifiedLookup(state.VerifiedIndex, state.Running.Hash)
		if err != nil || !known {
			return errV2Unavailable
		}
		if c.verifyWitness(proof) != nil {
			return errV2Unavailable
		}
	}
	if state.Intent != nil {
		intent := state.Intent
		var previous, target v2Configuration
		if s.readObject(intent.Previous, &previous) != nil || s.readObject(intent.Target, &target) != nil || !validV2Configuration(&previous) || !validV2Configuration(&target) || previous.Intent != nil || target.Intent != nil || intent.TargetGeneration < s.state.Generation || (intent.TargetGeneration != s.state.Generation && (s.state.Generation == ^uint64(0) || intent.TargetGeneration != s.state.Generation+1)) {
			return errV2Unavailable
		}
		if intent.Recovery {
			if state.LastRecovery == "" || (intent.Kind != v2BootKind && (intent.OriginCommit == "" || intent.Lease == "")) {
				return errV2Unavailable
			}
		} else {
			op, err := s.lookupRetained(intent.Subject, intent.Operation)
			if err != nil || (op.State != "pending" && op.State != "uncertain") || op.Domain != intent.Domain || op.Request.Kind != intent.Kind {
				return errV2Unavailable
			}
		}
		if validateGuardDeadlineContextV2(intent, previous, target, hasFeatureV2(s.state, v2GuardDeadlineFeature), true) != nil {
			return errV2Unavailable
		}
	}
	if state.Pending != nil {
		pending := state.Pending
		origin, err := s.lookupRetained(pending.Owner, pending.OriginCommit)
		if err != nil || origin.Domain != pending.Domain || (origin.Request.Kind != OpCommit && origin.Request.Kind != OpRollback) || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.Code != "applied_pending_confirmation" || origin.Outcome.ConfirmationLease != pending.Lease || origin.Outcome.RunningRevision != pending.Target || origin.Outcome.ConfirmationDeadline == nil || !origin.Outcome.ConfirmationDeadline.Equal(pending.Deadline) {
			return errV2Unavailable
		}
		var previous v2Configuration
		if s.readObject(pending.Previous, &previous) != nil || !validV2Configuration(&previous) || previous.Intent != nil || previous.Pending != nil {
			return errV2Unavailable
		}
	}
	if state.LastRecovery != "" {
		var record v2RecoveryRecord
		if s.readObject(state.LastRecovery, &record) != nil || !validRecoveryRecordV2(record, s.state.Lineage) {
			return errV2Unavailable
		}
		indexed, err := c.recoveryLookupLocked(record.ID)
		if err != nil || indexed.ID != record.ID || indexed.State != record.State || indexed.Audit != record.Audit {
			return errV2Unavailable
		}
		if record.State == "pending" && (state.Intent == nil || !state.Intent.Recovery || state.Intent.Operation != record.ID || state.Intent.Lease != record.Lease || state.Intent.OriginCommit != record.Origin) {
			return errV2Unavailable
		}
		if record.Kind == v2BootKind && (!hasFeatureV2(s.state, v2BootFeature) || (record.State == "pending" && (state.Intent.Kind != v2BootKind || state.Intent.BootID == nil || *state.Intent.BootID != *record.BootID))) {
			return errV2Unavailable
		}
	}
	if state.LastCompletedBoot != "" {
		if err := c.validateCompletedBootLocked(state.LastCompletedBoot); err != nil {
			return err
		}
	}
	return nil
}

func (c *v2Coordinator) pendingReferencesLocked(state *v2Configuration) error {
	for _, namespace := range c.store.state.Namespaces {
		for _, id := range namespaceOpenIDsV2(namespace) {
			op, err := c.store.lookupRetained(namespace.Subject, id)
			if err != nil {
				return err
			}
			if op.State == "accepted" {
				continue
			}
			if state == nil {
				return ErrRecovery
			}
			switch op.State {
			case "pending", "uncertain":
				if state.Intent == nil || state.Intent.Recovery || state.Intent.Operation != op.ID || state.Intent.Subject != op.Subject {
					return ErrRecovery
				}
			case "final":
				if !op.Pinned || state.Pending == nil || state.Pending.OriginCommit != op.ID || state.Pending.Owner != op.Subject {
					return ErrRecovery
				}
			default:
				return ErrRecovery
			}
		}
	}
	return nil
}
