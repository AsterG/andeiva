package configpoc

import "reflect"

type routedDHCPConfigurationHeaderOfV4 func(v2State) *v4RoutedDHCPConfigurationState
type routedDHCPConfigurationViewV4 struct {
	current *routedDHCPConfigurationContextV4
	pending *routedDHCPConfigurationContextV4
}

func routedDHCPConfigurationViewV4Read(h *v4RoutedDHCPConfigurationState, st v2State, load func(string, any) error, lookup func(string, string) (v2Operation, error), headerOf routedDHCPConfigurationHeaderOfV4) (out routedDHCPConfigurationViewV4, result error) {
	bad := func() (routedDHCPConfigurationViewV4, error) { return routedDHCPConfigurationViewV4{}, ErrRecovery }
	if h == nil || headerOf == nil || !validRoutedDHCPConfigurationHeaderV4(h, st) {
		return bad()
	}
	if h.Continuation != "" {
		c, err := routedDHCPConfigurationContinuationV4Read(h.Continuation, st, load)
		generation := c.transition.Generation
		if c.closing != nil {
			generation = c.closing.Intent.TargetGeneration
		}
		if err != nil || !validRoutedDHCPOriginalScopeV4(st, c.sourceWork) || st.Generation != generation {
			return bad()
		}
		out.current = &c
	}
	if h.Transition != "" {
		var x v4RoutedDHCPConfiguration
		if load(h.Transition, &x) != nil {
			return bad()
		}
		c, err := routedDHCPConfigurationContextV4Read(x, st, load, lookup)
		if err != nil || !validRoutedDHCPOriginalScopeV4(st, c.sourceWork) || st.Generation != x.Expected || !exactDHCPConfigurationIntentV4(c, *st.Configuration) || (st.Configuration.Intent != nil && c.operation.State != "pending" && c.operation.State != "uncertain") {
			return bad()
		}
		if st.Configuration.Intent == nil && c.operation.State != "accepted" {
			return bad()
		}
		sourceHeader := headerOf(c.sourceState)
		if sourceHeader != nil && (sourceHeader.Transition != "" || sourceHeader.Continuation != h.Continuation) || sourceHeader == nil && h.Continuation != "" {
			return bad()
		}
		if out.current == nil {
			if validateRoutedDHCPSelectedV3(c.sourceState, load) != nil {
				return bad()
			}
		} else if !reflect.DeepEqual(out.current.target, c.before) {
			return bad()
		}
		out.pending = &c
	} else if out.current == nil || !reflect.DeepEqual(*st.Configuration, out.current.target) {
		if out.current == nil || !retainedDHCPClosingPendingV4(*out.current, *st.Configuration, load) {
			return bad()
		}
		if in := st.Configuration.Intent; !in.Recovery {
			op, err := lookup(in.Subject, in.Operation)
			pending := out.current.target.Pending
			if err != nil || op.State != "pending" && op.State != "uncertain" ||
				op.Request.Kind != OpConfirm || op.Request.Origin != pending.OriginCommit || op.Request.Target != pending.Target ||
				op.Expected != st.Generation || op.ClosingCredit == "" || op.Reserve == nil || op.Reserve.PlanIntent == nil ||
				!reflect.DeepEqual(*op.Reserve.PlanIntent, *in) {
				return bad()
			}
		}
	}
	return out, nil
}

// This bridge is shared by selector verification and checked publication.
// The next full state is read on demand; historical summaries stay compact.
func preservesRoutedDHCPConfigurationReadV4(previous v2State, previousHeader *v4RoutedDHCPConfigurationState, next v2State, nextHeader *v4RoutedDHCPConfigurationState, source SelectionReferenceV2, load func(string, any) error, lookup func(string, string) (v2Operation, error), headerOf routedDHCPConfigurationHeaderOfV4) bool {
	if !preservesRoutedBootMarkCursorV1(previous, next) {
		return false
	}
	if !preservesRoutedCompensationV1(previous, next) {
		return false
	}
	legacy := preservesFeaturesV2(previous, next)
	if reflect.DeepEqual(previousHeader, nextHeader) {
		return legacy
	}
	if nextHeader == nil {
		return validatesRetainedDHCPColdEdgeV1(previous, next, source, load)
	}
	if !hasFeatureV2(next, v4RoutedDHCPConfigurationFeature) || previous.RoutedDHCPLast != next.RoutedDHCPLast || !reflect.DeepEqual(previous.RoutedDHCP, next.RoutedDHCP) || previous.RoutedDHCP == nil || previous.RoutedDHCP.Phase != "applied" {
		return false
	}
	// Retain every non-DHCP freeze condition from preservesFeaturesV2.
	if !preservesGuardDeadlineV2(previous, next) {
		return false
	}
	for _, f := range previous.RequiredFeatures {
		if !hasFeatureV2(next, f) {
			return false
		}
	}
	if previous.Configuration != nil && next.Configuration != nil {
		p, n := previous.Configuration.Intent, next.Configuration.Intent
		if p != nil && n != nil && p.RoutedWork != "" && !reflect.DeepEqual(p, n) && !preservesRoutedBootBoundaryV2(previous, next) {
			return false
		}
	}
	v, err := routedDHCPConfigurationViewV4Read(nextHeader, next, load, lookup, headerOf)
	if err != nil {
		return false
	}
	if previousHeader == nil || previousHeader.Transition == "" {
		if previousHeader != nil && nextHeader.Transition == "" && v.current != nil && v.current.closing != nil {
			var prior, closed v4RoutedDHCPConfigurationContinuation
			return previous.Configuration != nil && previous.Configuration.Intent != nil &&
				load(previousHeader.Continuation, &prior) == nil && prior.Closing == nil &&
				load(nextHeader.Continuation, &closed) == nil && closed.Closing != nil &&
				*previous.Configuration.Intent == closed.Closing.Intent &&
				previous.Generation != ^uint64(0) && next.Generation == previous.Generation+1 &&
				prior.Transition == closed.Transition && prior.Operation == closed.Operation && prior.Configuration == closed.Configuration
		}
		if !legacy || nextHeader.Transition == "" || v.pending == nil {
			return false
		}
		oldContinuation := ""
		if previousHeader != nil {
			oldContinuation = previousHeader.Continuation
		}
		_, stateHash, e := v2Canonical(previous)
		return e == nil && nextHeader.Continuation == oldContinuation && v.pending.transition.SourceSelection.State == stateHash && reflect.DeepEqual(v.pending.transition.SourceSelection, source)
	}
	if nextHeader.Transition != "" {
		return legacy && nextHeader.Transition == previousHeader.Transition && nextHeader.Continuation == previousHeader.Continuation
	}
	if v.current == nil || nextHeader.Continuation == previousHeader.Continuation {
		return false
	}
	var receipt v4RoutedDHCPConfigurationContinuation
	return load(nextHeader.Continuation, &receipt) == nil && receipt.Transition == previousHeader.Transition && previous.Generation == v.current.transition.Expected && next.Generation == v.current.transition.Generation && exactDHCPConfigurationIntentV4(*v.current, *previous.Configuration)
}
