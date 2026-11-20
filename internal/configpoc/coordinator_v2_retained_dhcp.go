package configpoc

import (
	"reflect"
	"time"
)

func retainedDHCPRuleEditV4(before, target Revision) bool {
	if before.Config.Routed == nil || target.Config.Routed == nil {
		return false
	}
	a, b := *before.Config.Routed, *target.Config.Routed
	a.Rules, b.Rules = nil, nil
	return reflect.DeepEqual(a, b)
}

// Alpha can build a rule candidate while retaining the selected DHCP work.
// Every metadata operation is authenticated using the existing R2 reserves.
func (s *v2Store) retainedDHCPMetadataAllowedV4(op v2Operation) bool {
	cfg := s.state.Configuration
	if !s.retainDHCPV4 || op.Domain != "routed" || s.state.RoutedDHCP == nil || s.state.RoutedDHCP.Phase != "applied" ||
		cfg == nil || cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired {
		return false
	}
	switch op.Request.Kind {
	case OpStage, OpReplaceCandidate:
		if op.Request.Config == nil || op.Request.LocalServicesConfig != nil {
			return false
		}
		return retainedDHCPRuleEditV4(cfg.Firewall.Running, Revision{Config: *op.Request.Config})
	case OpDiscardCandidate:
		return cfg.CandidateGroup != nil
	case OpValidate:
		return cfg.Firewall.Candidate != nil &&
			retainedDHCPRuleEditV4(cfg.Firewall.Running, cfg.Firewall.Candidate.Revision) &&
			cfg.LocalServices.Candidate != nil && cfg.LocalServices.Candidate.Revision.Hash == cfg.LocalServices.Running.Hash
	default:
		return false
	}
}

func (s *v2Store) retainedDHCPMetadataRetryV4(op v2Operation) bool {
	header := s.state.RoutedDHCPConfiguration
	if header == nil || header.Transition == "" {
		return true
	}
	var transition v4RoutedDHCPConfiguration
	return s.readObject(header.Transition, &transition) == nil && transition.Kind == "metadata" &&
		transition.Operation == op.ID && transition.Fingerprint == op.Fingerprint
}

func (c *v2Coordinator) executeRetainedDHCPMetadataV4(op v2Operation, before, target v2Configuration, changed bool, now time.Time) (v2Operation, error) {
	s := c.store
	if before.Running.Hash != target.Running.Hash || !s.retainedDHCPMetadataRetryV4(op) || !s.retainedDHCPMetadataAllowedV4(op) {
		return op, ErrRecovery
	}
	generation := s.state.Generation
	if changed {
		if generation == ^uint64(0) {
			return op, errV2Limited
		}
		generation++
	}
	if header := s.state.RoutedDHCPConfiguration; header == nil || header.Transition == "" {
		if err := c.persistRevisions(target); err != nil {
			return op, err
		}
		if err := c.selectRetainedDHCPMetadataV4(op, before, target, generation, now); err != nil {
			return op, err
		}
	}
	return c.completeLocked(op, target, generation, "applied", "", false, now)
}

func (c *v2Coordinator) selectRetainedDHCPMetadataV4(op v2Operation, before, target v2Configuration, generation uint64, now time.Time) error {
	s := c.store
	left, err := s.object(before)
	if err != nil {
		return err
	}
	right, err := s.object(target)
	if err != nil {
		return err
	}
	ref := actualDHCPConfigurationSourceV4(s.selector.Current, s.selection, s.state)
	transition, err := s.object(v4RoutedDHCPConfiguration{
		Version: 4, Lineage: ref.Lineage, Kind: "metadata", Impact: "preserve",
		SourceWork: ref.WorkHash, SourceSelection: ref,
		Operation: op.ID, Subject: op.Subject, Namespace: op.Namespace, Fingerprint: op.Fingerprint,
		Expected: op.Expected, Generation: generation, Before: left, Target: right,
	})
	if err != nil {
		return err
	}
	next := clone(s.state)
	if next.RoutedDHCPConfiguration == nil {
		next.RoutedDHCPConfiguration = &v4RoutedDHCPConfigurationState{Version: 4}
	}
	next.RoutedDHCPConfiguration.Transition = transition
	addFeatureV2(&next, v4RoutedDHCPConfigurationFeature)
	next.Clock = now
	return s.publish(next)
}

func (s *v2Store) finishRetainedDHCPConfigurationV4(next *v2State, op v2Operation) error {
	h := next.RoutedDHCPConfiguration
	if h == nil || h.Transition == "" {
		return nil
	}
	var transition v4RoutedDHCPConfiguration
	if s.readObject(h.Transition, &transition) != nil || op.ID != transition.Operation {
		return ErrRecovery
	}
	operation, err := s.object(op)
	if err != nil {
		return err
	}
	cfg, err := s.object(*next.Configuration)
	if err != nil {
		return err
	}
	h.Continuation, err = s.object(v4RoutedDHCPConfigurationContinuation{Version: 4, Transition: h.Transition, Operation: operation, Configuration: cfg})
	if err == nil {
		h.Transition = ""
	}
	return err
}
