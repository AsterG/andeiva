package configpoc

import "context"

func (c *v2Coordinator) retireDHCPScopeV3(ctx context.Context, work v3RoutedDHCPWork) error {
	s := c.store
	d := s.state.RoutedDHCP
	if d == nil || routedDHCPTerminalV3(d) || validateRoutedDHCPSelectedV3(s.state, s.readObject) != nil || s.reserves == nil || s.reserves.verifySelected(s) != nil {
		return ErrRecovery
	}
	proof, err := c.proveFreshScopeV3(ctx, work.Snapshot.Identity, d.Work)
	if err != nil {
		return err
	}
	previousAllowance := s.allowance
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = previousAllowance }()
	st := clone(s.state)
	audit, err := c.appendAuditLocked(st.Configuration, reserveWorkV2(d.Bundle), "", "", "", v3RoutedDHCPKind, "scope_retired", st.Generation, c.now())
	if err != nil {
		return err
	}
	st.RoutedDHCP.Phase, st.RoutedDHCP.Audit, st.RoutedDHCP.Retirement = "scope_retired", audit, proof
	addFeatureV2(&st, v3RoutedFreshScopeFeature)
	if validateRoutedDHCPSelectedV3(st, s.readObject) != nil {
		return ErrRecovery
	}
	// Check the inherited receipt and empty fresh namespace again immediately
	// before selecting retirement. No old WAN readback or restoration is claimed.
	again, err := c.proveFreshScopeV3(ctx, work.Snapshot.Identity, d.Work)
	if err != nil || again.ReceiptSHA256 != proof.ReceiptSHA256 || again.MetadataSHA256 != proof.MetadataSHA256 || again.Before != proof.Before || again.Dependencies != proof.Dependencies || again.DrainedAtBootNS != proof.DrainedAtBootNS || again.ObservedAtBootNS < proof.ObservedAtBootNS {
		return ErrRecovery
	}
	st.RoutedDHCP.Retirement = again
	if err = s.publish(st); err != nil {
		return err
	}
	return s.reserves.archiveTerminal(s, v2ActiveReserve{Work: reserveWorkV2(d.Bundle), Bundle: clone(d.Bundle), CanonicalHeld: true})
}
