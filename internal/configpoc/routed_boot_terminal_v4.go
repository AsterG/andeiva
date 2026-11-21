package configpoc

import "context"

// archiveInterruptedRoutedV4 gives an unfinished routed transaction its
// terminal record when the scope that owned it belongs to another kernel boot.
//
// Nothing of that scope can be restored or read back: the helper instead proves
// that the scope is gone and that the new scope is closed and empty. The
// transaction then receives the same terminal projection an ordinary recovery
// publishes, without any engine effect, deadline, permit, mark or lease from
// the previous boot. It becomes final exactly once and holds no reservation
// afterwards. The caller continues with the ordinary Startup boot, which proves
// the scope again and is repeatable from every publication.
//
// A scope of the running boot, a missing proof and every state this function
// does not recognize return nil without publishing: the existing rejection of
// those selections is unchanged.
func (c *v2Coordinator) archiveInterruptedRoutedV4(ctx context.Context) error {
	s := c.store
	cfg := s.state.Configuration
	if cfg == nil || !hasFeatureV2(s.state, v2RoutedFeature) || c.options.Routed == nil || c.options.BootID == nil || c.options.RebootScope == nil || s.reserves == nil ||
		s.state.RoutedDHCP != nil || s.state.RoutedBootBoundary != nil || cfg.RecoveryRequired {
		return nil
	}
	in := cfg.Intent
	if in == nil || in.Kind == v2BootKind || in.Domain != "routed" || !validHash(in.RoutedWork) {
		return nil
	}
	identity := c.options.RoutedIdentity
	if !validRoutedIdentityV1(identity) || identity != c.options.Routed.Identity() || identity.BootID != string(*c.options.BootID) {
		return nil
	}
	old, err := loadRoutedWorkV2(in.RoutedWork, s.state.Lineage, s.readObject)
	if err != nil || old.work.Boundary != nil || validateRoutedWorkIntentV2(in, old, s.readObject) != nil {
		return nil
	}
	scope := old.Scope().Identity
	if scope.BootID == identity.BootID || scope.RunID == identity.RunID || scope.UID != identity.UID || scope.GID != identity.GID {
		return nil
	}
	if in.Recovery {
		if in.Kind != "timeout" && in.Kind != "restart" || cfg.Pending == nil || cfg.Pending.Domain != "routed" {
			return nil
		}
	} else if in.Kind != OpCommit && in.Kind != OpRollback && in.Kind != OpConfirm {
		return nil
	}
	if _, err = c.proveRebootScopeV4(ctx, scope, in.RoutedWork); err != nil {
		return err
	}
	previousAllowance := s.allowance
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = previousAllowance }()
	if err = c.point("before_boot_terminal_archive"); err != nil {
		return err
	}
	if in.Recovery {
		err = c.archiveRollbackByBootV4(in)
	} else {
		err = c.archiveOperationByBootV4(in)
	}
	if err != nil {
		return err
	}
	return c.point("after_boot_terminal_archive")
}

// The pending Confirm window ends with the revert projection of its original
// rollback record. Its deadline is not consulted: it belongs to another boot.
func (c *v2Coordinator) archiveRollbackByBootV4(in *v2CoordinatorIntent) error {
	s := c.store
	origin, err := s.lookupRetained(in.Subject, in.OriginCommit)
	if err != nil || origin.Domain != in.Domain || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.ConfirmationLease != in.Lease {
		return ErrRecovery
	}
	restore, err := s.reserves.recoveryAllowance(s, origin)
	if err != nil {
		return err
	}
	defer restore()
	var previous, target v2Configuration
	if s.readObject(in.Previous, &previous) != nil || s.readObject(in.Target, &target) != nil || !validV2Configuration(&previous) || !validV2Configuration(&target) || target.Intent != nil {
		return ErrRecovery
	}
	return c.completeRecoveryLocked(in, origin, target)
}

// An operation interrupted before its result was published ends as a failed
// operation with the configuration it started from. A Confirm additionally
// reverts the pending change it could not finish confirming.
func (c *v2Coordinator) archiveOperationByBootV4(in *v2CoordinatorIntent) error {
	s := c.store
	op, err := s.lookupRetained(in.Subject, in.Operation)
	if err != nil || op.State != "pending" && op.State != "uncertain" || op.Domain != "routed" || op.Request.Kind != in.Kind {
		return ErrRecovery
	}
	restore, err := s.closingOperationAllowanceLocked(op)
	if err != nil {
		return err
	}
	defer restore()
	if s.reserves.verifyBundle(s, op.Reserve) != nil {
		return ErrRecovery
	}
	var previous v2Configuration
	if s.readObject(in.Previous, &previous) != nil || !validV2Configuration(&previous) || previous.Intent != nil {
		return ErrRecovery
	}
	generation, code := s.state.Generation, ErrInterrupted.Error()
	if in.Kind == OpConfirm {
		pending := previous.Pending
		var original v2Configuration
		if pending == nil || pending.Domain != "routed" || pending.Owner != op.Subject || pending.OriginCommit != op.Request.Origin || pending.Target != op.Request.Target ||
			s.state.Generation == ^uint64(0) || s.readObject(pending.Previous, &original) != nil {
			return ErrRecovery
		}
		origin, e := s.lookupRetained(pending.Owner, pending.OriginCommit)
		if e != nil || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.ConfirmationLease != pending.Lease || origin.Outcome.RunningRevision != pending.Target {
			return ErrRecovery
		}
		reverted, ok := coldRevertedConfigurationV1(previous, original)
		if !ok {
			return ErrRecovery
		}
		previous, generation, code = reverted, generation+1, ErrRecovery.Error()
	}
	previous.RecoveryRequired = false
	previous.Intent = nil
	_, err = c.completeLocked(op, previous, generation, "failed_rolled_back", code, false, c.recoveryNow())
	return err
}

// finishRetiredRoutedBootBoundaryV4 handles a scope replacement registered by
// an earlier kernel boot. When that boot had already verified and selected
// Startup, only the bookkeeping of the replacement is missing. It is completed
// from the records that boot left, after the helper proves that its scope is
// gone, and the ordinary Startup boot then runs for the new scope.
//
// A replacement whose own Startup boot was still selected is not repeated
// here: its system reservation cannot be released before a later boot is
// verified. That selection and every scope of the running boot stay rejected.
func (c *v2Coordinator) finishRetiredRoutedBootBoundaryV4(ctx context.Context, b v2RoutedBootBoundary) (bool, error) {
	s := c.store
	cfg := s.state.Configuration
	identity := c.options.RoutedIdentity
	active := s.state.RoutedActive
	if c.options.RebootScope == nil || s.reserves == nil || b.NewIdentity.BootID == identity.BootID || b.NewIdentity.RunID == identity.RunID ||
		b.NewIdentity.UID != identity.UID || b.NewIdentity.GID != identity.GID || cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired || active == nil {
		return true, ErrRecovery
	}
	completed, err := loadRoutedWorkV2(active.Work, s.state.Lineage, s.readObject)
	if err != nil || completed.Scope().Identity != b.NewIdentity {
		return true, ErrRecovery
	}
	if _, err = c.proveRebootScopeV4(ctx, b.NewIdentity, active.Work); err != nil {
		return true, err
	}
	if err = c.finishRoutedBootBoundaryV2(); err != nil {
		return true, err
	}
	if err = s.reserves.maintain(s); err != nil {
		return true, err
	}
	return false, nil
}

const (
	bootAttestationAuditKindV4   = "boot_attestation"
	bootAttestationAuditResultV4 = "accepted_without_receipt"
)

// auditBootAttestationV4 adds one protected audit entry for a completed boot
// whose previous scope was accepted from a boot attestation instead of an
// orderly drain receipt. It is published after the boot is final, because the
// boot audit itself must directly follow the configuration it started from.
// Repeating it for the same boot finds the existing entry and publishes nothing.
func (c *v2Coordinator) auditBootAttestationV4() error {
	s := c.store
	cfg := s.state.Configuration
	if cfg == nil || cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired || c.options.BootID == nil || s.state.RoutedActive == nil || cfg.LastCompletedBoot == "" {
		return nil
	}
	var boot v2RecoveryRecord
	if s.readObject(cfg.LastCompletedBoot, &boot) != nil || boot.Kind != v2BootKind || boot.State != "final" || boot.BootID == nil || *boot.BootID != *c.options.BootID {
		return nil
	}
	plan, err := loadRoutedWorkV2(s.state.RoutedActive.Work, s.state.Lineage, s.readObject)
	if err != nil || plan.work.Kind != v2BootKind || plan.work.Operation != boot.ID {
		return nil
	}
	if e := plan.RebootScopeEvidenceV4(); e == nil || !e.BootAttested {
		return nil
	}
	var verified v2CoordinatorAudit
	if s.readObject(boot.Audit, &verified) != nil {
		return ErrRecovery
	}
	for hash := cfg.AuditTip; hash != "" && hash != boot.Audit; {
		var entry v2CoordinatorAudit
		if s.readObject(hash, &entry) != nil || entry.Sequence <= verified.Sequence {
			return ErrRecovery
		}
		if entry.Operation == boot.ID && entry.Kind == bootAttestationAuditKindV4 {
			return nil
		}
		hash = entry.Previous
	}
	st := clone(s.state)
	at := c.recoveryNow()
	if _, err = c.appendAuditLocked(st.Configuration, boot.ID, "", "", "system", bootAttestationAuditKindV4, bootAttestationAuditResultV4, st.Generation, at); err != nil {
		return err
	}
	st.Clock = at
	if err = c.point("before_boot_attestation_audit"); err != nil {
		return err
	}
	if err = s.publish(st); err != nil {
		return err
	}
	return c.point("after_boot_attestation_audit")
}
