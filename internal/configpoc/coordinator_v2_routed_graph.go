package configpoc

func (r *v2ReachabilityReader) routedWork(hash, key string, state v2State, depth int) error {
	if !hasFeatureV2(state, v2RoutedFeature) {
		return errV2Unavailable
	}
	return r.walk("routed-work:"+hash, depth, func() error {
		plan, err := loadRoutedWorkV2(hash, state.Lineage, r.object)
		if err != nil {
			return err
		}
		if plan.work.Kind == v2BootKind && !hasFeatureV2(state, v2RoutedBootFeature) {
			return errV2Unavailable
		}
		if routedWorkUsesNoNetworkV2(plan) && !hasFeatureV2(state, v2RoutedNoNetworkFeature) {
			return errV2Unavailable
		}
		if err = routedBootHistoryV2(plan, state, r.object); err != nil {
			return err
		}
		if plan.work.Baseline != "" {
			if err := r.routedWork(plan.work.Baseline, key, state, depth+1); err != nil {
				return err
			}
		}
		for _, snapshot := range []string{plan.work.Transition.Previous, plan.work.Transition.Target} {
			if err := r.snapshot(snapshot, key, state, depth+1); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *v2ReachabilityReader) routedIntent(in *v2CoordinatorIntent, key string, state v2State, depth int) error {
	if in == nil || in.RoutedWork == "" {
		return nil
	}
	plan, err := loadRoutedWorkV2(in.RoutedWork, state.Lineage, r.object)
	if err != nil || validateRoutedWorkIntentV2(in, plan, r.object) != nil {
		return errV2Unavailable
	}
	return r.routedWork(in.RoutedWork, key, state, depth)
}

func (r *v2ReachabilityReader) routedActive(key string, state v2State, depth int) error {
	if state.RoutedActive == nil {
		return nil
	}
	if validateRoutedActiveV2(state, r.object) != nil {
		return errV2Unavailable
	}
	return r.routedWork(state.RoutedActive.Work, key, state, depth)
}
