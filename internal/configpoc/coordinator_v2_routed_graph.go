package configpoc

func (r *v2ReachabilityReader) routedWork(hash, key string, state v2State, depth int) error {
	if !hasFeatureV2(state, v2RoutedFeature) {
		return errV2Unavailable
	}
	memoKey := "routed-work:" + hash
	if r.cache != nil {
		contextKey, err := selectedValidationKeyV2(state)
		if err != nil {
			return err
		}
		memoKey += ":" + contextKey
	}
	return r.walk(memoKey, depth, func() error {
		plan, err := r.selectedRoutedWorkV2(hash, state.Lineage)
		if err != nil {
			return err
		}
		if plan.work.Kind == v2BootKind && !hasFeatureV2(state, v2RoutedBootFeature) {
			return errV2Unavailable
		}
		if routedWorkUsesNoNetworkV2(plan) && !hasFeatureV2(state, v2RoutedNoNetworkFeature) {
			return errV2Unavailable
		}
		if routedWorkUsesDHCPV3(plan) && !hasFeatureV2(state, v3RoutedDHCPFeature) {
			return ErrRecovery
		}
		if err = routedBootHistoryV2(plan, state, r.object); err != nil {
			return err
		}
		if plan.work.Boundary != nil {
			if err := r.routedBootBoundary(plan.work.Boundary, key, state, depth+1); err != nil {
				return err
			}
		}
		if proof := plan.work.FreshScope; proof != nil {
			if !hasFeatureV2(state, v3RoutedFreshScopeFeature) {
				return errV2Unavailable
			}
			if err := r.routedWork(proof.Work, key, state, depth+1); err != nil {
				return err
			}
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

func (r *v2ReachabilityReader) routedBootBoundary(b *v2RoutedBootBoundary, key string, state v2State, depth int) error {
	if b == nil {
		return nil
	}
	if !hasFeatureV2(state, v2RoutedBootBoundaryFeature) {
		return errV2Unavailable
	}
	return r.walk("routed-boot-boundary:"+key+":"+b.Source, depth, func() error {
		source, _, err := routedBootBoundarySourceV2(*b, state.Lineage, r.object)
		if err != nil {
			return err
		}
		var held v2Configuration
		release, err := r.load(b.Source, &held)
		if err != nil {
			return err
		}
		defer release()
		if err = r.configuration(routedBootBoundaryProjectionV2(source), checkpointDigest([]byte(key+b.Source)), state, depth+1, false); err != nil {
			return err
		}
		if err = r.routedWork(b.OldWork, key, state, depth+1); err != nil {
			return err
		}
		if b.OldBoot != nil {
			var old v2RecoveryRecord
			if err = r.object(b.OldBoot.Object, &old); err != nil {
				return err
			}
			if err = r.reserveBundle(old.Reserve, key, state, depth+1); err != nil {
				return err
			}
		}
		if b.Origin != nil {
			var op v2Operation
			if err = r.object(b.Origin.Object, &op); err != nil {
				return err
			}
			if err = r.operationAudit(op, state, depth+1); err != nil {
				return err
			}
			if err = r.reserveBundle(op.Reserve, key, state, depth+1); err != nil {
				return err
			}
			if source.Pending != nil {
				if err = r.snapshot(source.Pending.Previous, key, state, depth+1); err != nil {
					return err
				}
			}
		} else if err = r.recovery(b.OldBoot.Object, b.OldBoot.ID, key, state, depth+1); err != nil {
			return err
		}
		if b.CompletedBoot != "" {
			var completed v2RecoveryRecord
			if err = r.object(b.CompletedBoot, &completed); err != nil {
				return err
			}
			if err = r.recovery(b.CompletedBoot, completed.ID, key, state, depth+1); err != nil {
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
	if r.cache != nil {
		contextKey, err := selectedValidationKeyV2(struct {
			Intent *v2CoordinatorIntent
			State  v2State
		}{in, state})
		if err != nil {
			return err
		}
		return r.walk("selected-intent:"+contextKey, depth, func() error { return r.checkRoutedIntentV2(in, key, state, depth) })
	}
	return r.checkRoutedIntentV2(in, key, state, depth)
}
func (r *v2ReachabilityReader) checkRoutedIntentV2(in *v2CoordinatorIntent, key string, state v2State, depth int) error {
	plan, err := r.selectedRoutedWorkV2(in.RoutedWork, state.Lineage)
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
