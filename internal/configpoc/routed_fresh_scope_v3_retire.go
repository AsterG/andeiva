package configpoc

import "context"

func (c *v2Coordinator) retireDHCPScopeV3(ctx context.Context, work v3RoutedDHCPWork) error {
	s := c.store
	d := s.state.RoutedDHCP
	if d == nil || routedDHCPTerminalV3(d) || validateRoutedDHCPSelectedV3(s.state, s.readObject) != nil || s.reserves == nil || s.reserves.verifySelected(s) != nil {
		return ErrRecovery
	}
	proof, reboot, err := c.proveScopeRetirementV4(ctx, work.Snapshot.Identity, d.Work)
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
	st.RoutedDHCP.RebootRetirement = reboot
	if reboot != nil {
		addFeatureV2(&st, v4RoutedRebootScopeFeature)
	} else {
		addFeatureV2(&st, v3RoutedFreshScopeFeature)
	}
	if validateRoutedDHCPSelectedV3(st, s.readObject) != nil {
		return ErrRecovery
	}
	// Check the inherited receipt and empty fresh namespace again immediately
	// before selecting retirement. No old WAN readback or restoration is claimed.
	again, newBoot, err := c.proveScopeRetirementV4(ctx, work.Snapshot.Identity, d.Work)
	a, validA := compareScopeV4(proof, reboot)
	b, validB := compareScopeV4(again, newBoot)
	observed := b.observed
	b.observed = a.observed
	if err != nil || !validA || !validB || a != b || observed < a.observed {
		return ErrRecovery
	}
	st.RoutedDHCP.Retirement = again
	st.RoutedDHCP.RebootRetirement = newBoot
	if err = s.publish(st); err != nil {
		return err
	}
	return s.reserves.archiveTerminal(s, v2ActiveReserve{Work: reserveWorkV2(d.Bundle), Bundle: clone(d.Bundle), CanonicalHeld: true})
}
