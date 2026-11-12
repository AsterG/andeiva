package configpoc

import (
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"reflect"
	"time"
)

const v2GuardDeadlineFeature = "configuration.guard-deadline.v1"

func validGuardDeadlineShapeV2(in *v2CoordinatorIntent) bool {
	if in == nil || in.GuardDeadline == nil {
		return true
	}
	d := in.GuardDeadline
	return !d.IsZero() && d.Location() == time.UTC && !in.Recovery && in.BootID == nil && in.OriginCommit == "" && in.Lease == "" && (in.Kind == OpCommit || in.Kind == OpRollback || in.Kind == OpRecover)
}
func immediateGuardIntentV2(in *v2CoordinatorIntent, previous, target v2Configuration) bool {
	return in != nil && !in.Recovery && in.Kind != OpConfirm && previous.Pending == nil && target.Pending == nil && guardEffectV2(v2Operation{Domain: in.Domain, Request: v2Request{Kind: in.Kind}}, previous, target)
}
func validateGuardDeadlineContextV2(in *v2CoordinatorIntent, previous, target v2Configuration, feature, live bool) error {
	if in == nil || !validGuardDeadlineShapeV2(in) {
		return errV2Unavailable
	}
	immediate := immediateGuardIntentV2(in, previous, target)
	if in.GuardDeadline != nil && (!feature || !immediate) {
		return errV2Unavailable
	}
	if live && feature && immediate && in.GuardDeadline == nil {
		return errV2Unavailable
	}
	return nil
}
func validGuardDeadlineFeatureV2(st v2State) bool {
	check := func(in *v2CoordinatorIntent) bool {
		return validGuardDeadlineShapeV2(in) && (in == nil || in.GuardDeadline == nil || hasFeatureV2(st, v2GuardDeadlineFeature))
	}
	if st.Configuration != nil && !check(st.Configuration.Intent) {
		return false
	}
	for _, active := range st.ActiveReserves {
		if active.Bundle != nil && !check(active.Bundle.PlanIntent) {
			return false
		}
	}
	return st.SystemBundle == nil || st.SystemBundle.Bundle == nil || check(st.SystemBundle.Bundle.PlanIntent)
}
func preservesGuardDeadlineV2(previous, next v2State) bool {
	if previous.Configuration == nil || next.Configuration == nil {
		return true
	}
	p, n := previous.Configuration.Intent, next.Configuration.Intent
	if p == nil || n == nil {
		return true
	}
	if p.GuardDeadline == nil {
		return n.GuardDeadline == nil
	}
	if n.GuardDeadline == nil || !p.GuardDeadline.Equal(*n.GuardDeadline) {
		return false
	}
	left, right := *p, *n
	left.GuardDeadline, right.GuardDeadline = nil, nil
	return reflect.DeepEqual(left, right)
}

func (c *v2Coordinator) guardDeadlineOpenV2() error {
	s := c.store
	if hasFeatureV2(s.state, v2GuardDeadlineFeature) && !c.options.GuardDeadlines {
		return ErrRecovery
	}
	if !c.options.GuardDeadlines {
		s.guardDeadlines = false
		return nil
	}
	in := s.state.Configuration.Intent
	if in != nil && !in.Recovery {
		var previous, target v2Configuration
		if s.readObject(in.Previous, &previous) != nil || s.readObject(in.Target, &target) != nil || !validV2Configuration(&previous) || !validV2Configuration(&target) {
			return errV2Unavailable
		}
		if immediateGuardIntentV2(in, previous, target) && in.GuardDeadline == nil {
			return ErrRecovery
		}
	}
	s.guardDeadlines = true
	return nil
}

func (c *v2Coordinator) guardDeadlineLockedV2(id, domain string, previous, target v2Configuration) (time.Time, error) {
	if d, e := guardDeadlineV2(id, domain, previous, target); e == nil {
		return d, nil
	}
	in := c.store.state.Configuration.Intent
	if in == nil || in.Operation != id || in.Domain != domain || in.GuardDeadline == nil || !hasFeatureV2(c.store.state, v2GuardDeadlineFeature) || validateGuardDeadlineContextV2(in, previous, target, true, true) != nil {
		return time.Time{}, ErrRecovery
	}
	return *in.GuardDeadline, nil
}

func validateArchiveGuardDeadlinesV2(a v2ReserveArchive, state v2State, load func(string, any) error) error {
	for _, entry := range a.Entries {
		if entry.Binding == nil || entry.Claim.Role != recoveryreserve.PlanV2 {
			continue
		}
		var plan v2ReservePlan
		if checkpointDecode(entry.Raw, &plan) != nil {
			return errV2Unavailable
		}
		if plan.Intent.GuardDeadline == nil {
			continue
		}
		if load == nil {
			return errV2Unavailable
		}
		var p, t v2Configuration
		if load(plan.Intent.Previous, &p) != nil || load(plan.Intent.Target, &t) != nil || !validV2Configuration(&p) || !validV2Configuration(&t) || validateGuardDeadlineContextV2(&plan.Intent, p, t, hasFeatureV2(state, v2GuardDeadlineFeature), false) != nil {
			return errV2Unavailable
		}
	}
	return nil
}

func reserveGuardFeatureBudgetV2(s *v2Store, st *v2State) {
	if s.guardDeadlines || hasFeatureV2(s.state, v2GuardDeadlineFeature) {
		st.RequiredFeatures = append([]string(nil), st.RequiredFeatures...)
		addFeatureV2(st, v2GuardDeadlineFeature)
	}
}
