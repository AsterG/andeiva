package configpoc

import "time"

// routedTargetV2 prepares a complete joint projection without writing objects
// or invoking engines. The caller supplies a lease only for a confirmed effect.
func routedTargetV2(s *v2Store, op v2Operation, state v2Configuration, now time.Time, lease string) (v2Configuration, bool, error) {
	target := clone(state)
	target.Intent = nil
	if !hasFeatureV2(s.state, v2RoutedFeature) || state.Running.Config.SchemaVersion != 7 || !routedRequestValidV2(op.Request) {
		return target, false, ErrInvalid
	}
	changed := true
	incFirewall, incLocal := false, false
	group := state.CandidateGroup
	matchingGroup := func() bool {
		return group != nil && group.Owner == op.Subject && validCandidateGroupV2(&state, true)
	}
	switch op.Request.Kind {
	case OpStage:
		if state.CandidateGroup != nil || state.Firewall.Candidate != nil || state.LocalServices.Candidate != nil || state.Pending != nil || state.Intent != nil || state.RecoveryRequired {
			return target, false, ErrConflict
		}
		firewall, err := CanonicalRouted(*op.Request.Config)
		if err != nil {
			return target, false, err
		}
		local := clone(state.LocalServices.Running)
		if op.Request.LocalServicesConfig != nil {
			local, err = Canonical(*op.Request.LocalServicesConfig)
			if err != nil {
				return target, false, err
			}
			if local.Hash != state.LocalServices.Running.Hash {
				// The routed transport has not yet supplied the existing local
				// access-recovery proof. A group label cannot bypass that proof.
				return target, false, ErrDenied
			}
		}
		target.Firewall.Candidate = &v2DomainCandidate{Owner: op.Subject, Base: state.Firewall.Running.Hash, Revision: firewall}
		target.LocalServices.Candidate = &v2DomainCandidate{Owner: op.Subject, Base: state.LocalServices.Running.Hash, Revision: local}
		target.CandidateGroup = &v2CandidateGroup{Operation: op.ID, Owner: op.Subject, Base: state.Running.Hash, Domains: []string{"firewall", "local_services"}}
		incFirewall, incLocal = true, true
	case OpValidate:
		if !matchingGroup() {
			return target, false, ErrConflict
		}
		changed = false
	case OpCommit:
		if !matchingGroup() || state.Pending != nil {
			return target, false, ErrConflict
		}
		target.Firewall.Running = clone(state.Firewall.Candidate.Revision)
		target.LocalServices.Running = clone(state.LocalServices.Candidate.Revision)
		target.Firewall.Candidate, target.LocalServices.Candidate, target.CandidateGroup = nil, nil, nil
		incFirewall, incLocal = true, true
	case OpConfirm:
		pending := state.Pending
		if pending == nil || pending.Domain != "routed" || pending.Owner != op.Subject || pending.OriginCommit != op.Request.Origin || pending.Target != op.Request.Target || !now.Before(pending.Deadline) {
			return target, false, ErrConflict
		}
		origin, err := s.lookupRetained(op.Subject, pending.OriginCommit)
		if err != nil || origin.Domain != "routed" || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.Code != "applied_pending_confirmation" || origin.Outcome.ConfirmationLease != pending.Lease || origin.Outcome.RunningRevision != pending.Target || origin.Outcome.ConfirmationDeadline == nil || !origin.Outcome.ConfirmationDeadline.Equal(pending.Deadline) {
			return target, false, ErrConflict
		}
		target.Firewall.LastGood, target.LocalServices.LastGood = clone(state.Firewall.Running), clone(state.LocalServices.Running)
		target.Pending = nil
		incFirewall, incLocal = true, state.LocalServices.LastGood.Hash != state.LocalServices.Running.Hash
	case OpSave:
		if state.Pending != nil || state.CandidateGroup != nil || state.Firewall.Candidate != nil || state.LocalServices.Candidate != nil {
			return target, false, ErrConflict
		}
		incFirewall = state.Firewall.Startup.Hash != state.Firewall.Running.Hash
		incLocal = state.LocalServices.Startup.Hash != state.LocalServices.Running.Hash
		changed = incFirewall || incLocal
		target.Firewall.Startup, target.LocalServices.Startup = clone(state.Firewall.Running), clone(state.LocalServices.Running)
	case OpRollback:
		if state.Pending != nil || state.CandidateGroup != nil || state.Firewall.Candidate != nil || state.LocalServices.Candidate != nil {
			return target, false, ErrConflict
		}
		bundle, err := (&v2Coordinator{store: s}).loadRoutedBundleV2(op.Request.Target)
		if err != nil {
			return target, false, err
		}
		if bundle.LocalServices.Hash != state.LocalServices.Running.Hash {
			return target, false, ErrDenied
		}
		incFirewall = true
		incLocal = state.LocalServices.Running.Hash != bundle.LocalServices.Hash
		target.Firewall.Running, target.LocalServices.Running = bundle.Firewall, bundle.LocalServices
	default:
		return target, false, ErrInvalid
	}
	if incFirewall {
		if target.Firewall.Generation == ^uint64(0) {
			return target, false, errV2Limited
		}
		target.Firewall.Generation++
	}
	if incLocal {
		if target.LocalServices.Generation == ^uint64(0) {
			return target, false, errV2Limited
		}
		target.LocalServices.Generation++
	}
	if err := target.refresh(); err != nil {
		return target, false, err
	}
	if op.Request.Kind == OpCommit || op.Request.Kind == OpRollback {
		seconds := *op.Request.ConfirmSeconds
		if seconds < 30 || seconds > 120 {
			return target, false, ErrInvalid
		}
		_, previous, err := v2Canonical(state)
		if err != nil || lease == "" {
			return target, false, ErrInvalid
		}
		target.Pending = &v2Confirmation{OriginCommit: op.ID, Lease: lease, Owner: op.Subject, Domain: "routed", Previous: previous, Target: target.Running.Hash, Deadline: now.Add(time.Duration(seconds) * time.Second)}
	}
	return target, changed, nil
}

func (c *v2Coordinator) loadRoutedBundleV2(hash string) (RoutedActivationBundleV1, error) {
	if !validHash(hash) {
		return RoutedActivationBundleV1{}, ErrInvalid
	}
	proof, known, err := c.verifiedLookup(c.store.state.Configuration.VerifiedIndex, hash)
	if err != nil || !known {
		return RoutedActivationBundleV1{}, ErrInvalid
	}
	if err = c.verifyWitness(proof); err != nil {
		return RoutedActivationBundleV1{}, err
	}
	var document v2CompositeConfig
	if c.store.readObject(hash, &document) != nil {
		return RoutedActivationBundleV1{}, errV2Unavailable
	}
	var firewall, local Config
	if c.store.readObject(document.Domains.Firewall.Revision, &firewall) != nil || c.store.readObject(document.Domains.LocalServices.Revision, &local) != nil {
		return RoutedActivationBundleV1{}, errV2Unavailable
	}
	canonicalFirewall, err := canonicalDomainRevisionV2(firewall, true)
	if err != nil {
		return RoutedActivationBundleV1{}, err
	}
	canonicalLocal, err := Canonical(local)
	if err != nil {
		return RoutedActivationBundleV1{}, err
	}
	bundle, err := NewRoutedActivationBundleV1(canonicalFirewall, canonicalLocal)
	if err != nil || bundle.Composite.Hash != hash {
		return RoutedActivationBundleV1{}, ErrInvalid
	}
	return bundle, nil
}
