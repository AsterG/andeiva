package configpoc

import (
	"context"
	"errors"
	"time"
)

func (c *v2Coordinator) appendAuditLocked(state *v2Configuration, operation, origin, lease, subject, kind, result string, generation uint64, at time.Time) (string, error) {
	current := c.store.state.Configuration
	if current == nil {
		current = &v2Configuration{}
	}
	if current.AuditSequence == ^uint64(0) {
		return "", errV2Limited
	}
	record := v2CoordinatorAudit{Format: v2Format, Sequence: current.AuditSequence + 1, Previous: current.AuditTip, Operation: operation, OriginCommit: origin, Lease: lease, Subject: subject, Kind: kind, Result: result, At: at.UTC(), Generation: generation, Running: state.Running.Hash, Startup: state.Startup.Hash}
	hash, err := c.store.object(record)
	if err != nil {
		return "", err
	}
	state.AuditSequence = record.Sequence
	state.AuditTip = hash
	return hash, nil
}

func (c *v2Coordinator) completeLocked(op v2Operation, target v2Configuration, generation uint64, code, errorCode string, pin bool, at time.Time) (v2Operation, error) {
	s := c.store
	st := clone(s.state)
	target.Intent = nil
	originID, lease := "", ""
	if pending := s.state.Configuration.Pending; pending != nil && op.Request.Kind == OpConfirm {
		originID = pending.OriginCommit
		lease = pending.Lease
	}
	if target.Pending != nil {
		originID = target.Pending.OriginCommit
		lease = target.Pending.Lease
	}
	audit, err := c.appendAuditLocked(&target, op.ID, originID, lease, op.Subject, op.Request.Kind, code, generation, at)
	if err != nil {
		s.blocked = true
		return v2Operation{}, err
	}
	if code == "applied" && target.Pending == nil {
		target.VerifiedIndex, err = c.verifiedInsert(target.VerifiedIndex, 0, v2VerifiedEntry{Revision: target.Running.Hash, Audit: audit, Operation: op.ID})
		if err != nil {
			s.blocked = true
			return v2Operation{}, err
		}
	}
	completed := at.UTC()
	until := completed.Add(30 * 24 * time.Hour)
	outcome := v2Outcome{Code: code, ErrorCode: errorCode, Generation: generation, AuditHash: audit, DomainGeneration: domainSnapshotV2(&target, op.Domain).Generation, RunningRevision: target.Running.Hash, StartupRevision: target.Startup.Hash, AuditFirst: target.AuditSequence, AuditLast: target.AuditSequence}
	if target.Pending != nil {
		deadline := target.Pending.Deadline
		outcome.ConfirmationDeadline = &deadline
		outcome.ConfirmationLease = target.Pending.Lease
	}
	op.State = "final"
	op.Completed = &completed
	op.RetainUntil = &until
	op.Outcome = &outcome
	op.Pinned = pin
	if op.Request.Kind == OpConfirm && originID != "" && (code == "applied" || code == "failed_rolled_back") && target.Pending == nil {
		origin, e := s.lookupRetained(op.Subject, originID)
		if e != nil {
			return v2Operation{}, e
		}
		origin.Pinned = false
		v2Release(&st, origin)
		if e = s.putOperation(&st, origin); e != nil {
			s.blocked = true
			return v2Operation{}, e
		}
	}
	if !pin {
		v2Release(&st, op)
	}
	st.Configuration = &target
	st.Generation = generation
	st.Clock = completed
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return v2Operation{}, err
	}
	if err = s.publish(st); err != nil {
		return v2Operation{}, err
	}
	if err = c.publishLocalLocked(); err != nil {
		c.armLocked()
		return op, ErrRecovery
	}
	if s.reserves != nil {
		if err = s.reserves.maintainWork(s, op.ID); err != nil {
			return op, err
		}
	}
	return op, nil
}

func (c *v2Coordinator) uncertainLocked(op v2Operation, cause error) (v2CoordinatorResult, error) {
	c.invalidateLocalLocked()
	s := c.store
	if s.reserves != nil {
		if err := s.reserves.emergencyCandidate(s, op.Reserve, "recovery_uncertain"); err != nil {
			return v2CoordinatorResult{Operation: clone(op), Current: clone(*s.state.Configuration), GlobalGeneration: s.state.Generation}, ErrRecovery
		}
	}
	if s.reserves != nil {
		// The selected intent is already a durable mutation fence. A failed
		// effect does not justify a second unbounded metadata attempt.
		selected, e := s.lookupRetained(op.Subject, op.ID)
		if e != nil {
			return v2CoordinatorResult{}, ErrRecovery
		}
		return v2CoordinatorResult{Operation: clone(selected), Current: clone(*s.state.Configuration), GlobalGeneration: s.state.Generation}, ErrRecovery
	}
	st := clone(s.state)
	state := st.Configuration
	state.RecoveryRequired = true
	op.State = "uncertain"
	op.Pinned = true
	if _, err := c.appendAuditLocked(state, op.ID, "", "", op.Subject, op.Request.Kind, "uncertain", st.Generation, c.recoveryNow()); err != nil {
		s.blocked = true
		return v2CoordinatorResult{}, err
	}
	if err := s.putOperation(&st, op); err != nil {
		s.blocked = true
		return v2CoordinatorResult{}, err
	}
	if err := s.publish(st); err != nil {
		return v2CoordinatorResult{}, err
	}
	return v2CoordinatorResult{Operation: clone(op), Current: clone(*state), GlobalGeneration: st.Generation}, cause
}

func (c *v2Coordinator) compensateLocked(_ context.Context, op v2Operation, previous v2Configuration, cause error) (v2CoordinatorResult, error) {
	// Rollback must not inherit a request's cancelled context.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if metadataOperationV2(op.Request.Kind) {
		if !c.readback(previous) {
			return c.uncertainLocked(op, ErrRecovery)
		}
	} else if c.hasPreparedGuard(op.Domain) && op.Request.Kind == OpConfirm {
		return c.compensateConfirmationLocked(ctx, op, previous)
	} else if c.hasPreparedGuard(op.Domain) {
		if err := c.compensationGuardsLocked(ctx, op, previous); err != nil {
			return c.uncertainLocked(op, ErrRecovery)
		}
	} else {
		for _, engine := range c.enginesV2(op.Domain) {
			if err := engine.Apply(ctx, domainSnapshotV2(&previous, op.Domain).Running); err != nil {
				return c.uncertainLocked(op, ErrRecovery)
			}
		}
	}
	if !c.readback(previous) {
		return c.uncertainLocked(op, ErrRecovery)
	}
	previous.RecoveryRequired = false
	previous.Intent = nil
	errorCode := "ANDEIVA_CONFIG_ENGINE_FAILURE"
	if errors.Is(cause, ErrExpired) {
		errorCode = ErrExpired.Error()
	}
	if errors.Is(cause, ErrInterrupted) {
		errorCode = ErrInterrupted.Error()
	}
	final, err := c.completeLocked(op, previous, c.store.state.Generation, "failed_rolled_back", errorCode, false, c.recoveryNow())
	if err != nil {
		return v2CoordinatorResult{}, err
	}
	c.armLocked()
	reported := ErrEngine
	if errors.Is(cause, ErrExpired) {
		reported = ErrExpired
	}
	if errors.Is(cause, ErrInterrupted) {
		reported = ErrInterrupted
	}
	return v2CoordinatorResult{Operation: final, Current: clone(*c.store.state.Configuration), GlobalGeneration: c.store.state.Generation}, reported
}

func (c *v2Coordinator) tick(ctx context.Context, at time.Time) error {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	return c.tickLocked(ctx, at.UTC())
}
func (c *v2Coordinator) tickLocked(ctx context.Context, at time.Time) error {
	if c.closed || c.store.blocked {
		return errV2Unavailable
	}
	state := c.store.state.Configuration
	if state == nil {
		return errV2Invalid
	}
	if state.Intent != nil {
		return ErrRecovery
	}
	if state.Pending == nil {
		return nil
	}
	if at.Before(c.store.state.Clock) {
		return errV2Unavailable
	}
	if at.Before(state.Pending.Deadline) {
		return nil
	}
	return c.revertLocked(ctx, "timeout")
}

func (c *v2Coordinator) recoveryStatus() (v2RecoveryRecord, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.store.blocked || c.store.state.Configuration == nil || c.store.state.Configuration.LastRecovery == "" {
		return v2RecoveryRecord{}, errV2NotFound
	}
	var record v2RecoveryRecord
	if c.store.readObject(c.store.state.Configuration.LastRecovery, &record) != nil || record.Format != v2Format {
		return v2RecoveryRecord{}, errV2Unavailable
	}
	if !validRecoveryRecordV2(record, c.store.state.Lineage) {
		return v2RecoveryRecord{}, errV2Unavailable
	}
	return record, nil
}

func (c *v2Coordinator) revertLocked(ctx context.Context, kind string) error {
	s := c.store
	current := clone(*s.state.Configuration)
	pending := current.Pending
	if pending == nil {
		return nil
	}
	origin, err := s.lookupRetained(pending.Owner, pending.OriginCommit)
	if err != nil || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.ConfirmationLease != pending.Lease {
		return ErrRecovery
	}
	var previous v2Configuration
	if s.readObject(pending.Previous, &previous) != nil || !validV2Configuration(&previous) || previous.Intent != nil {
		return errV2Unavailable
	}
	target := clone(current)
	target.Pending = nil
	target.Intent = nil
	target.Candidate = nil
	target.RecoveryRequired = false
	domain := domainSnapshotV2(&target, pending.Domain)
	prior := domainSnapshotV2(&previous, pending.Domain)
	domain.Running = prior.Running
	domain.LastGood = prior.LastGood
	domain.Candidate = nil
	if domain.Generation == ^uint64(0) || s.state.Generation == ^uint64(0) {
		return errV2Limited
	}
	domain.Generation++
	if target.refresh() != nil {
		return errV2Invalid
	}
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = v2Budget{} }()
	if s.reserves != nil {
		restore, e := s.reserves.recoveryAllowance(s, origin)
		if e != nil {
			return e
		}
		defer restore()
	}
	previousHash, err := s.object(current)
	if err != nil {
		s.blocked = true
		return err
	}
	targetHash, err := s.object(target)
	if err != nil {
		s.blocked = true
		return err
	}
	id, err := v2ID("recovery", s.selection.Sequence+1)
	if err != nil {
		return err
	}
	record := v2RecoveryRecord{Format: v2Format, ID: id, Origin: origin.ID, Lease: pending.Lease, Kind: kind, State: "pending", Previous: previousHash, Target: targetHash, Subject: origin.Subject, Lineage: s.state.Lineage, Started: c.recoveryNow(), Pinned: true}
	record.Reserve = clone(origin.Reserve)
	recordHash, err := s.object(record)
	if err != nil {
		s.blocked = true
		return err
	}
	st := clone(s.state)
	st.Configuration.LastRecovery = recordHash
	st.Configuration.RecoveryIndex, err = c.recoveryIndexPut(st.Configuration.RecoveryIndex, record, recordHash)
	if err != nil {
		s.blocked = true
		return err
	}
	st.Configuration.Intent = &v2CoordinatorIntent{Operation: id, Subject: origin.Subject, Domain: pending.Domain, Kind: kind, Previous: previousHash, Target: targetHash, TargetGeneration: st.Generation + 1, Recovery: true, OriginCommit: origin.ID, Lease: pending.Lease}
	st.Clock = c.recoveryNow()
	if err = s.publish(st); err != nil {
		return err
	}
	c.invalidateLocalLocked()
	if err = c.point("after_recovery_intent"); err != nil {
		return err
	}
	return c.finishRecoveryLocked(ctx)
}

func (c *v2Coordinator) finishRecoveryLocked(ctx context.Context) error {
	s := c.store
	intent := s.state.Configuration.Intent
	if intent == nil || !intent.Recovery {
		return errV2Invalid
	}
	origin, err := s.lookupRetained(intent.Subject, intent.OriginCommit)
	if err != nil || origin.Domain != intent.Domain || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.ConfirmationLease != intent.Lease {
		return ErrRecovery
	}
	if s.reserves != nil {
		restore, e := s.reserves.recoveryAllowance(s, origin)
		if e != nil {
			return e
		}
		defer restore()
	}
	var previous, target v2Configuration
	if s.readObject(intent.Previous, &previous) != nil || s.readObject(intent.Target, &target) != nil || !validV2Configuration(&previous) || !validV2Configuration(&target) || target.Intent != nil {
		return errV2Unavailable
	}
	for _, engine := range c.enginesV2(intent.Domain) {
		if engine.Validate(domainSnapshotV2(&target, intent.Domain).Running.Config) != nil {
			return c.fenceRecoveryLocked()
		}
	}
	if c.hasPreparedGuard(intent.Domain) {
		err = c.restoreGuardsLocked(ctx, intent.Lease, target, previous, intent.Domain)
	} else {
		err = c.applyLocked(ctx, previous, target)
	}
	if err != nil {
		return c.fenceRecoveryLocked()
	}
	if !c.readback(target) {
		return c.fenceRecoveryLocked()
	}
	if err = c.point("after_recovery_readback"); err != nil {
		return err
	}
	var record v2RecoveryRecord
	if s.readObject(s.state.Configuration.LastRecovery, &record) != nil || record.ID != intent.Operation || record.Lease != intent.Lease || record.Origin != origin.ID {
		return errV2Unavailable
	}
	audit, err := c.appendAuditLocked(&target, record.ID, origin.ID, intent.Lease, "system", record.Kind, "reverted", intent.TargetGeneration, c.recoveryNow())
	if err != nil {
		s.blocked = true
		return err
	}
	record.State = "final"
	record.Audit = audit
	completed := c.recoveryNow()
	until := completed.Add(30 * 24 * time.Hour)
	record.Completed = &completed
	record.RetainUntil = &until
	record.Pinned = false
	hash, err := s.object(record)
	if err != nil {
		s.blocked = true
		return err
	}
	target.LastRecovery = hash
	target.RecoveryIndex, err = c.recoveryIndexPut(s.state.Configuration.RecoveryIndex, record, hash)
	if err != nil {
		s.blocked = true
		return err
	}
	target.Intent = nil
	target.Pending = nil
	target.RecoveryRequired = false
	st := clone(s.state)
	st.Configuration = &target
	st.Generation = intent.TargetGeneration
	st.Clock = c.recoveryNow()
	origin.Pinned = false
	v2Release(&st, origin)
	if err = s.putOperation(&st, origin); err != nil {
		s.blocked = true
		return err
	}
	if err = s.publish(st); err != nil {
		return err
	}
	if err = c.publishLocalLocked(); err != nil {
		return err
	}
	if s.reserves != nil {
		if err = s.reserves.maintainWork(s, origin.ID); err != nil {
			return err
		}
	}
	c.armLocked()
	return nil
}

func (c *v2Coordinator) fenceRecoveryLocked() error {
	c.invalidateLocalLocked()
	if s := c.store; s.reserves != nil {
		intent := s.state.Configuration.Intent
		if intent == nil {
			return ErrRecovery
		}
		if s.state.SystemBundle != nil {
			_ = s.reserves.emergencyCandidate(s, s.state.SystemBundle.Bundle, "recovery_uncertain")
			return ErrRecovery
		}
		origin, err := s.lookupRetained(intent.Subject, intent.OriginCommit)
		if err != nil {
			return ErrRecovery
		}
		_ = s.reserves.emergencyCandidate(s, origin.Reserve, "recovery_uncertain")
		return ErrRecovery
	}
	st := clone(c.store.state)
	st.Configuration.RecoveryRequired = true
	st.Clock = c.recoveryNow()
	intent := st.Configuration.Intent
	if intent == nil {
		return ErrRecovery
	}
	audit, err := c.appendAuditLocked(st.Configuration, intent.Operation, intent.OriginCommit, intent.Lease, "system", intent.Kind, "uncertain", st.Generation, st.Clock)
	if err != nil {
		c.store.blocked = true
		return err
	}
	var record v2RecoveryRecord
	if c.store.readObject(st.Configuration.LastRecovery, &record) != nil {
		return errV2Unavailable
	}
	record.Audit = audit
	st.Configuration.LastRecovery, err = c.store.object(record)
	if err != nil {
		c.store.blocked = true
		return err
	}
	st.Configuration.RecoveryIndex, err = c.recoveryIndexPut(st.Configuration.RecoveryIndex, record, st.Configuration.LastRecovery)
	if err != nil {
		c.store.blocked = true
		return err
	}
	if err := c.store.publish(st); err != nil {
		return err
	}
	return ErrRecovery
}

func (c *v2Coordinator) reconcileLocked(ctx context.Context, reason string) error {
	s := c.store
	intent := s.state.Configuration.Intent
	if intent == nil {
		return nil
	}
	if intent.Kind == v2BootKind {
		return c.finishBootLocked(ctx)
	}
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = v2Budget{} }()
	if intent.Recovery {
		return c.finishRecoveryLocked(ctx)
	}
	op, err := s.lookupRetained(intent.Subject, intent.Operation)
	if err != nil || (op.State != "pending" && op.State != "uncertain") {
		return ErrRecovery
	}
	closingRestore, err := s.closingOperationAllowanceLocked(op)
	if err != nil {
		return err
	}
	defer closingRestore()
	if s.reserves != nil && s.reserves.verifyBundle(s, op.Reserve) != nil {
		return ErrRecovery
	}
	var previous v2Configuration
	if s.readObject(intent.Previous, &previous) != nil || !validV2Configuration(&previous) || previous.Intent != nil {
		return errV2Unavailable
	}
	_, err = c.compensateLocked(ctx, op, previous, ErrInterrupted)
	if errors.Is(err, ErrEngine) || errors.Is(err, ErrInterrupted) || errors.Is(err, ErrExpired) {
		return nil
	}
	_ = reason
	return err
}

func (c *v2Coordinator) reconcileStorageFailureLocked(ctx context.Context, previous v2Configuration, operation v2Operation) error {
	s := c.store
	// Keep the validated operation's purpose across selector reload. A newly
	// selected final state has no Intent; that must not permit kernel repair.
	domain := operation.Domain
	// Clear a storage fence only after the selected protocol is independently
	// reconciled under the same exclusive store lock. Unknown staging is retained.
	if s.scanV2Area() == nil && !s.blocked && s.readSelection() == nil && c.validateReferencesLocked() == nil && checkpointSync(s.root, nil, "") == nil {
		if s.state.Configuration.Intent != nil {
			return c.reconcileLocked(ctx, "storage-reconciliation")
		}
		if c.readback(*s.state.Configuration) {
			c.armLocked()
			return nil
		}
	}
	s.blocked = true
	// A durable pre-effect intent already authorizes this exact compensation.
	// Failure to journal it remains unavailable; never manufacture a final result.
	rollback, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if metadataOperationV2(operation.Request.Kind) {
		if !c.readback(previous) {
			return ErrRecovery
		}
		return errV2Unavailable
	}
	if c.hasPreparedGuard(domain) {
		intent := s.state.Configuration.Intent
		if intent == nil {
			return ErrRecovery
		}
		op, err := s.lookupRetained(intent.Subject, intent.Operation)
		if err != nil {
			return ErrRecovery
		}
		if c.compensationGuardsLocked(rollback, op, previous) != nil {
			return ErrRecovery
		}
		if !c.readback(previous) {
			return ErrRecovery
		}
		return errV2Unavailable
	}
	for _, engine := range c.enginesV2(domain) {
		if engine.Apply(rollback, domainSnapshotV2(&previous, domain).Running) != nil {
			return ErrRecovery
		}
	}
	if !c.readback(previous) {
		return ErrRecovery
	}
	return errV2Unavailable
}
