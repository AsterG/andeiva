package configpoc

import "context"

// Only selected finality can turn a fresh helper into an idle helper. Pending
// work is compensated through its original recovery intent instead.
func (c *v2Coordinator) resumeRoutedLockedV2(ctx context.Context) error {
	s := c.store
	if s.state.RoutedActive == nil {
		return nil
	}
	if c.options.Routed == nil || s.state.Configuration == nil || s.state.Configuration.Intent != nil || s.state.Configuration.Pending != nil || s.state.Configuration.RecoveryRequired || s.reserves == nil || s.reserves.verifySelected(s) != nil || validateRoutedActiveV2(s.state, s.readObject) != nil {
		return ErrRecovery
	}
	plan, err := loadRoutedWorkV2(s.state.RoutedActive.Work, s.state.Lineage, s.readObject)
	if err != nil || plan.Scope().Identity != c.options.RoutedIdentity {
		return ErrRecovery
	}
	plan.resolution = s.state.RoutedActive.Side
	return c.options.Routed.Resume(ctx, plan)
}
