package configpoc

const v2RoutedFeature = "configuration.routed-composite.v1"

type v2CandidateGroup struct {
	Operation string   `json:"stage_operation_id"`
	Owner     string   `json:"owner"`
	Base      string   `json:"base_composite_revision"`
	Domains   []string `json:"domains"`
}

func configurationDomainV2(domain string, routed bool) bool {
	return domain == "firewall" || domain == "local_services" || routed && domain == "routed"
}

func canonicalDomainRevisionV2(config Config, routed bool) (Revision, error) {
	if routed && config.SchemaVersion == 6 {
		return CanonicalRouted(config)
	}
	return Canonical(config)
}

func routedCompositeFromDomainsV2(firewall, local Revision) (v2CompositeRevision, error) {
	bundle, err := NewRoutedActivationBundleV1(firewall, local)
	return bundle.Composite, err
}

func compositeFromConfigurationV2(config v2CompositeConfig, state *v2Configuration) (v2CompositeRevision, error) {
	if config.SchemaVersion != 7 {
		return CanonicalComposite(config)
	}
	return resolveRoutedCompositeV1(config, func(hash string, value any) error {
		out, ok := value.(*Revision)
		if !ok || state == nil {
			return ErrInvalid
		}
		for _, domain := range []v2DomainSnapshot{state.Firewall, state.LocalServices} {
			revisions := []Revision{domain.Running, domain.Startup, domain.LastGood}
			if domain.Candidate != nil {
				revisions = append(revisions, domain.Candidate.Revision)
			}
			for _, revision := range revisions {
				if revision.Hash == hash {
					*out = revision
					return nil
				}
			}
		}
		return ErrInvalid
	})
}

func validCandidateGroupV2(state *v2Configuration, routed bool) bool {
	group := state.CandidateGroup
	if group == nil {
		return true
	}
	if !routed || group.Operation == "" || len(group.Operation) > 128 || group.Owner == "" || len(group.Owner) > 128 || !validHash(group.Base) || len(group.Domains) != 2 || group.Domains[0] != "firewall" || group.Domains[1] != "local_services" {
		return false
	}
	for _, domain := range []v2DomainSnapshot{state.Firewall, state.LocalServices} {
		if domain.Candidate == nil || domain.Candidate.Owner != group.Owner || !validHash(domain.Candidate.Base) {
			return false
		}
	}
	return state.Firewall.Candidate.Revision.Config.SchemaVersion == 6
}

func routedRequestValidV2(r v2Request) bool {
	if r.Kind == OpStage {
		if r.Config == nil || r.Config.SchemaVersion != 6 || r.ConfirmSeconds != nil || r.Target != "" || r.Origin != "" || r.Subject != "" {
			return false
		}
		if _, err := CanonicalRouted(*r.Config); err != nil {
			return false
		}
		if r.LocalServicesConfig != nil {
			if r.LocalServicesConfig.SchemaVersion != 3 || len(r.LocalServicesConfig.Rules) != 0 {
				return false
			}
			_, err := Canonical(*r.LocalServicesConfig)
			return err == nil
		}
		return true
	}
	if r.LocalServicesConfig != nil || r.Config != nil || r.Subject != "" {
		return false
	}
	switch r.Kind {
	case OpCommit:
		return r.ConfirmSeconds != nil && *r.ConfirmSeconds >= 30 && *r.ConfirmSeconds <= 120 && r.Target == "" && r.Origin == ""
	case OpRollback:
		return r.ConfirmSeconds != nil && *r.ConfirmSeconds >= 30 && *r.ConfirmSeconds <= 120 && validHash(r.Target) && r.Origin == ""
	case OpConfirm:
		return r.ConfirmSeconds == nil && validHash(r.Target) && r.Origin != ""
	case OpValidate, OpSave:
		return r.ConfirmSeconds == nil && r.Target == "" && r.Origin == ""
	}
	return false
}

func validRoutedFeatureV2(state v2State) bool {
	enabled := hasFeatureV2(state, v2RoutedFeature)
	if active := state.RoutedActive; active != nil && (!enabled || !validHash(active.Work) || active.Side != "before" && active.Side != "target") {
		return false
	}
	check := func(in *v2CoordinatorIntent) bool {
		return in == nil || in.RoutedWork == "" || enabled && in.Domain == "routed" && validHash(in.RoutedWork)
	}
	if state.Configuration != nil {
		if enabled != (state.Configuration.Running.Config.SchemaVersion == 7) {
			return false
		}
		if !enabled && state.Configuration.CandidateGroup != nil {
			return false
		}
		if !check(state.Configuration.Intent) {
			return false
		}
	}
	for _, active := range state.ActiveReserves {
		if active.Bundle != nil && !check(active.Bundle.PlanIntent) {
			return false
		}
	}
	if state.SystemBundle != nil && state.SystemBundle.Bundle != nil && !check(state.SystemBundle.Bundle.PlanIntent) {
		return false
	}
	for _, ns := range state.Namespaces {
		if ns.Domain == "routed" && !enabled {
			return false
		}
	}
	return true
}

// The group is selected configuration, not a permanent catalogue pin. Its
// stage identity remains bound to protected audit after catalogue retirement.
func validateCandidateGroupEvidenceV2(state v2Configuration, load func(string, any) error) error {
	group := state.CandidateGroup
	if group == nil {
		return nil
	}
	if load == nil || !validCandidateGroupV2(&state, true) {
		return errV2Unavailable
	}
	var base v2CompositeConfig
	if load(group.Base, &base) != nil || base.SchemaVersion != 7 || base.Domains.Firewall.Revision != state.Firewall.Candidate.Base || base.Domains.LocalServices.Revision != state.LocalServices.Candidate.Base {
		return errV2Unavailable
	}
	hash, sequence := state.AuditTip, state.AuditSequence
	for sequence > 0 && validHash(hash) {
		var audit v2CoordinatorAudit
		if load(hash, &audit) != nil || audit.Format != v2Format || audit.Sequence != sequence || (audit.Previous == "") != (sequence == 1) {
			return errV2Unavailable
		}
		if audit.Operation == group.Operation {
			if audit.Kind != OpStage || audit.Subject != group.Owner || audit.Result != "applied" || audit.Running != group.Base {
				return errV2Unavailable
			}
			return nil
		}
		hash, sequence = audit.Previous, sequence-1
	}
	return errV2Unavailable
}
