package configpoc

import "context"

// Recovery is a trusted helper capability, never a function supplied through an
// operation request. The helper independently resolves WorkHash via its own G1
// reader, closes the gate, and proves baseline after withdrawing only owned WAN.
type RoutedDHCPRecoveryV3 interface {
	RoutedDHCPAuthorityV3
	WithdrawSelected(context.Context, SelectionReferenceV2) error
}

// The same-helper restart starts with a read-only check of the durable Work.
// Qualification still requires an independent full scan and live kernel proof.
func (c *v2Coordinator) retainRoutedDHCPAtOpenV4() error {
	s := c.store
	d := s.state.RoutedDHCP
	cfg := s.state.Configuration
	if d == nil || d.Phase != "applied" || !c.options.integrityAttached || c.options.BootID == nil ||
		!inspectionQuiescentV1(s.state) || cfg.LastCompletedBoot == "" || s.state.RoutedBootBoundary != nil ||
		s.state.SystemBundle != nil || len(s.state.ActiveReserves) != 0 || s.reserves == nil ||
		validateRoutedDHCPConfigurationSelectionV4(s.state.RoutedDHCPConfiguration, s.state, s.readObject, s.lookupRetained, routedDHCPConfigurationHeaderV4) != nil {
		return ErrRecovery
	}
	var boot v2RecoveryRecord
	if s.readObject(cfg.LastCompletedBoot, &boot) != nil || !validRecoveryRecordV2(boot, s.state.Lineage) ||
		boot.Kind != v2BootKind || boot.State != "final" || boot.BootID == nil || *boot.BootID != *c.options.BootID {
		return ErrRecovery
	}
	work, err := loadRoutedDHCPWorkV3(d.Work, s.state.Lineage, s.readObject)
	if err != nil || work.Snapshot.Identity != c.options.RoutedIdentity {
		return ErrRecovery
	}
	c.retainedDHCP = true
	return nil
}

func (c *v2Coordinator) recoverRoutedDHCPAtOpenV3(ctx context.Context) error {
	s := c.store
	d := s.state.RoutedDHCP
	if d == nil {
		return nil
	}
	if d.ColdSource != "" {
		old := d.RebootRetirement.Old
		if c.options.BootID == nil || string(*c.options.BootID) != c.options.RoutedIdentity.BootID ||
			d.RebootRetirement.New.BootID == c.options.RoutedIdentity.BootID {
			return ErrRecovery
		}
		if _, err := c.proveRebootScopeV4(ctx, old, d.Work); err != nil {
			return err
		}
		return nil
	}
	if routedDHCPTerminalV3(d) {
		if s.reserves == nil || s.reserves.verifySelected(s) != nil {
			return ErrRecovery
		}
		return s.reserves.maintain(s)
	}
	w, err := loadRoutedDHCPWorkV3(d.Work, s.state.Lineage, s.readObject)
	if err == nil && w.Snapshot.Identity != c.options.RoutedIdentity {
		return c.retireDHCPScopeV3(ctx, w)
	}
	if err != nil || validateRoutedDHCPSelectedV3(s.state, s.readObject) != nil || c.options.DHCPRecovery == nil || c.options.BootID == nil || string(*c.options.BootID) != w.Snapshot.Identity.BootID || c.options.RoutedIdentity != w.Snapshot.Identity || s.reserves == nil || s.reserves.verifySelected(s) != nil {
		return ErrRecovery
	}
	ref := SelectionReferenceV2{Selection: s.selector.Current, Previous: s.selector.Previous, State: s.selection.State, Lineage: s.state.Lineage, Sequence: s.selection.Sequence, Generation: s.state.Generation, WorkHash: d.Work, Mode: "dhcp-recovery"}
	if c.options.DHCPRecovery.WithdrawSelected(ctx, ref) != nil {
		return ErrRecovery
	}
	writer := &RoutedDHCPSelectedStoreV3{c: c, authority: c.options.DHCPRecovery, identity: w.Snapshot.Identity}
	if err := writer.transitionLocked(ctx, d.Work, true); err != nil {
		return err
	}
	if release, ok := c.options.DHCPRecovery.(interface{ ReleaseWithdrawn(context.Context) error }); ok {
		return release.ReleaseWithdrawn(ctx)
	}
	return nil
}
