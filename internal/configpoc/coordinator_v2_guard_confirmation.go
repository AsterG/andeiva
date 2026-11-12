package configpoc

import "context"

// A failed confirmation may coincide with the helper's independent rollback.
// Publish that rollback only after its exact original lease and every component
// readback prove it. A remotely confirmed target remains fenced instead.
func (c *v2Coordinator) compensateConfirmationLocked(ctx context.Context, op v2Operation, previous v2Configuration) (v2CoordinatorResult, error) {
	s := c.store
	pending := previous.Pending
	if pending == nil || pending.Domain != op.Domain || pending.Owner != op.Subject || pending.OriginCommit != op.Request.Origin || pending.Target != op.Request.Target {
		return c.uncertainLocked(op, ErrRecovery)
	}
	origin, err := s.lookupRetained(pending.Owner, pending.OriginCommit)
	if err != nil || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.ConfirmationLease != pending.Lease || origin.Outcome.RunningRevision != pending.Target {
		return c.uncertainLocked(op, ErrRecovery)
	}
	var original v2Configuration
	if s.readObject(pending.Previous, &original) != nil || !validV2Configuration(&original) || original.Intent != nil {
		return c.uncertainLocked(op, ErrRecovery)
	}
	target := clone(previous)
	target.Intent = nil
	target.Pending = nil
	target.Candidate = nil
	target.RecoveryRequired = false
	domain := domainSnapshotV2(&target, op.Domain)
	prior := domainSnapshotV2(&original, op.Domain)
	domain.Running = prior.Running
	domain.LastGood = prior.LastGood
	domain.Candidate = nil
	if domain.Generation == ^uint64(0) || s.state.Generation == ^uint64(0) {
		return c.uncertainLocked(op, errV2Limited)
	}
	domain.Generation++
	if target.refresh() != nil {
		return c.uncertainLocked(op, ErrRecovery)
	}
	if c.restoreGuardsLocked(ctx, pending.Lease, target, previous, op.Domain) != nil || !c.readback(target) {
		return c.uncertainLocked(op, ErrRecovery)
	}
	final, err := c.completeLocked(op, target, s.state.Generation+1, "failed_rolled_back", ErrRecovery.Error(), false, c.recoveryNow())
	if err != nil {
		return v2CoordinatorResult{}, err
	}
	c.armLocked()
	return v2CoordinatorResult{Operation: final, Current: clone(*s.state.Configuration), GlobalGeneration: s.state.Generation}, ErrEngine
}
