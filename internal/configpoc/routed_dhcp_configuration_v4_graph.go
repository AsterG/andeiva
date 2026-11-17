package configpoc

// SourceSelection retains the prior selected state using the existing G1 graph.
// There is no independent continuation log, index, compactor or traversal budget.
// This edge is not installed in the state reader until the shared patch is reviewed.
func (r *v2ReachabilityReader) routedDHCPConfigurationV4(h *v4RoutedDHCPConfigurationState, key string, state v2State, depth int, headerOf routedDHCPConfigurationHeaderOfV4) error {
	if !validRoutedDHCPConfigurationHeaderV4(h, state) {
		return ErrRecovery
	}
	if h == nil {
		return nil
	}
	return r.walk("dhcp-configuration:"+key+":"+h.Continuation+":"+h.Transition, depth, func() error {
		load := func(hash string, target any) error {
			limit := int64(v2ObjectLimit)
			switch target.(type) {
			case *v4RoutedDHCPConfiguration, *v4RoutedDHCPConfigurationContinuation:
				limit = v4RoutedDHCPConfigurationLimit
			}
			release, err := r.loadBound(hash, target, limit)
			if err != nil {
				return err
			}
			defer release()
			return nil
		}
		v, err := routedDHCPConfigurationViewV4Read(h, state, load, func(subject, id string) (v2Operation, error) { return r.lookup(state, subject, id) }, headerOf)
		if err != nil {
			return err
		}
		for _, current := range []*routedDHCPConfigurationContextV4{v.current, v.pending} {
			if current == nil {
				continue
			}
			c := *current
			x := c.transition
			if err = r.snapshot(x.Before, key, c.sourceState, depth+1); err != nil {
				return err
			}
			if err = r.snapshot(x.Target, key, state, depth+1); err != nil {
				return err
			}
			if err = r.snapshot(c.sourceWork.Configuration, key, c.sourceState, depth+1); err != nil {
				return err
			}
			if c.finalConfiguration != "" {
				if err = r.snapshot(c.finalConfiguration, key, state, depth+1); err != nil {
					return err
				}
			}
			if c.operation.Outcome != nil {
				if err = r.operationAudit(c.operation, state, depth+1); err != nil {
					return err
				}
			}
			if x.Group != nil {
				if err = r.routedIntent(c.operation.Reserve.PlanIntent, key, state, depth+1); err != nil {
					return err
				}
			}
			if err = r.walk("state:"+x.SourceSelection.State, depth+1, func() error { return r.state(x.SourceSelection.State, c.sourceState, depth+2) }); err != nil {
				return err
			}
		}
		return nil
	})
}
