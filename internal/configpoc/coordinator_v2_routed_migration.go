package configpoc

import "context"

// prepareRoutedCompositeLockedV2 is a cold trusted-assembly seam. It never
// synthesizes a routed policy or changes component bytes or engine state.
func (c *v2Coordinator) prepareRoutedCompositeLockedV2(ctx context.Context, budget v2ReachabilityBudget) error {
	if ctx == nil || c == nil || c.store == nil {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	s := c.store
	if c.closed || s.blocked || s.reserves == nil || s.state.RecoveryReserveVersion != 1 || s.state.Configuration == nil {
		return ErrRecovery
	}
	if hasFeatureV2(s.state, v2RoutedFeature) {
		return nil
	}
	state := clone(*s.state.Configuration)
	if state.Intent != nil || state.Pending != nil || state.RecoveryRequired || state.CandidateGroup != nil || state.Firewall.Candidate != nil || state.LocalServices.Candidate != nil {
		return ErrConflict
	}
	if !c.readback(state) || c.validateReferencesLocked() != nil || !validReachabilityBudgetV2(budget) {
		return ErrRecovery
	}
	root, err := s.root.Stat(".")
	if err != nil {
		return errV2Unavailable
	}
	reader := &v2ReachabilityReader{ctx: ctx, area: s.root, root: root, budget: budget, objects: map[string]bool{}, edges: map[string]uint8{}}
	closure, err := reader.traceLocked(s.lock)
	if err != nil || !closure.Complete || closure.Current != s.selector.Current || closure.Previous != s.selector.Previous || closure.State != s.selection.State {
		return ErrRecovery
	}
	// Both component histories remain untouched; only the composite wrapper
	// changes version. Startup may still reference a legacy firewall schema4.
	state.Running.Config.SchemaVersion = 7
	if err = state.refresh(); err != nil {
		return err
	}
	st := clone(s.state)
	addFeatureV2(&st, v2RoutedFeature)
	st.Configuration = &state
	if s.state.Generation == ^uint64(0) || !reserveMetadataStateFitsV2(reserveProjectedEnvelopeV2(st, state, "routed")) {
		return errV2Limited
	}
	if s.used.Bytes > s.budget.Bytes || s.state.ReservedBytes > s.budget.Bytes-s.used.Bytes || v2OperationReserveBytes > s.budget.Bytes-s.used.Bytes-s.state.ReservedBytes || s.used.Inodes > s.budget.Inodes || s.state.ReservedInodes > s.budget.Inodes-s.used.Inodes || v2OperationReserveInodes > s.budget.Inodes-s.used.Inodes-s.state.ReservedInodes {
		return errV2Limited
	}
	if err = s.physicalCapacity(v2OperationReserveBytes, v2OperationReserveInodes); err != nil {
		return err
	}
	if err = c.persistRevisions(state); err != nil {
		return err
	}
	operation, err := v2ID("routed-optin", s.selection.Sequence+1)
	if err != nil {
		return err
	}
	generation := st.Generation + 1
	audit, err := c.appendAuditLocked(&state, operation, "", "", "system", "routed_composite_optin", "verified", generation, c.recoveryNow())
	if err != nil {
		return err
	}
	state.VerifiedIndex, err = c.verifiedInsert(state.VerifiedIndex, 0, v2VerifiedEntry{Revision: state.Running.Hash, Audit: audit, Operation: operation})
	if err != nil {
		return err
	}
	st.Generation, st.Clock = generation, c.recoveryNow()
	return s.publish(st)
}
