package configpoc

import "context"

// Recovery is a trusted helper capability, never a function supplied through an
// operation request. The helper independently resolves WorkHash via its own G1
// reader, closes the gate, and proves baseline after withdrawing only owned WAN.
type RoutedDHCPRecoveryV3 interface {
	RoutedDHCPAuthorityV3
	WithdrawSelected(context.Context, SelectionReferenceV2) error
}

func (c *v2Coordinator) recoverRoutedDHCPAtOpenV3(ctx context.Context) error {
	s := c.store
	d := s.state.RoutedDHCP
	if d == nil {
		return nil
	}
	if d.Phase == "withdrawn" {
		if s.reserves == nil || s.reserves.verifySelected(s) != nil {
			return ErrRecovery
		}
		return s.reserves.maintain(s)
	}
	w, err := loadRoutedDHCPWorkV3(d.Work, s.state.Lineage, s.readObject)
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
