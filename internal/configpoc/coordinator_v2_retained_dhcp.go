package configpoc

import (
	"reflect"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

const retainedDHCPBaselineMarksV4 = "retained-wan-baseline"

func (s *v2Store) reserveRetainedDHCPBaselineV4(identity networkexecutor.OwnedNamespaceIdentity) error {
	cfg := s.state.Configuration.Firewall.Running.Config.Routed
	if cfg == nil {
		return ErrRecovery
	}
	rev, err := routedmodel.Canonical(*cfg)
	if err != nil {
		return err
	}
	_, _, _, err = s.reserveRoutedBootMarksLocked(identity, retainedDHCPBaselineMarksV4, nil, rev, rev)
	return err
}

func (s *v2Store) retainedDHCPCommitAllowedV4(op v2Operation) bool {
	cfg := s.state.Configuration
	return s.retainDHCPV4 && op.Domain == "routed" && op.Request.Kind == OpCommit &&
		s.state.RoutedDHCP != nil && s.state.RoutedDHCP.Phase == "applied" &&
		cfg != nil && cfg.Intent == nil && cfg.Pending == nil && !cfg.RecoveryRequired &&
		cfg.CandidateGroup != nil && cfg.CandidateGroup.Owner == op.Subject &&
		cfg.Firewall.Candidate != nil && cfg.LocalServices.Candidate != nil &&
		cfg.LocalServices.Candidate.Revision.Hash == cfg.LocalServices.Running.Hash &&
		cfg.Firewall.Candidate.Revision.Hash != cfg.Firewall.Running.Hash &&
		retainedDHCPRuleEditV4(cfg.Firewall.Running, cfg.Firewall.Candidate.Revision) &&
		(s.state.RoutedDHCPConfiguration == nil || s.state.RoutedDHCPConfiguration.Transition == "")
}

func (s *v2Store) retainedDHCPConfirmAllowedV4(op v2Operation) bool {
	cfg := s.state.Configuration
	return s.retainDHCPV4 && op.Domain == "routed" && op.Request.Kind == OpConfirm && op.ClosingCredit != "" &&
		s.state.RoutedDHCP != nil && s.state.RoutedDHCP.Phase == "applied" &&
		cfg != nil && cfg.Intent == nil && cfg.Pending != nil && !cfg.RecoveryRequired &&
		cfg.Pending.OriginCommit == op.Request.Origin && cfg.Pending.Owner == op.Subject &&
		s.state.RoutedDHCPConfiguration != nil && s.state.RoutedDHCPConfiguration.Transition == ""
}

func (s *v2Store) currentRetainedDHCPMarksV4(before routedmodel.Revision) (*routedmodel.AdmissionMarks, error) {
	if s.state.RoutedBootMarks == nil || s.state.RoutedActive == nil {
		return nil, ErrRecovery
	}
	reservation, err := loadRoutedBootMarkReservationV1(s.state.RoutedBootMarks, s.state.Lineage, s.readObject)
	if err != nil || reservation.Work != s.state.RoutedDHCP.Work {
		return nil, ErrRecovery
	}
	active, err := loadRoutedWorkV2(s.state.RoutedActive.Work, s.state.Lineage, s.readObject)
	if err != nil || active.Scope().Identity != reservation.Scope {
		return nil, ErrRecovery
	}
	var marks *routedmodel.AdmissionMarks
	switch {
	case active.Transition().Operation == reservation.Operation && s.state.RoutedActive.Side == "target":
		marks = &reservation.Applied
	case active.Transition().Operation == reservation.Operation && s.state.RoutedActive.Side == "before":
		marks = &reservation.Restored
	case reservation.Before == reservation.Target && sameRoutedAdmissionMarksV1(reservation.Applied, reservation.Restored):
		marks = &reservation.Applied
	default:
		marks = reservation.Prior
	}
	if marks == nil {
		return nil, ErrRecovery
	}
	if _, err = marks.MarkIndex(before); err != nil {
		return nil, ErrRecovery
	}
	return marks, nil
}

func (s *v2Store) reserveRetainedDHCPCommitV4(op v2Operation, before, target v2Configuration) error {
	if !s.retainedDHCPCommitAllowedV4(op) || target.Pending == nil || target.Pending.OriginCommit != op.ID {
		return ErrRecovery
	}
	start, err := routedmodel.Canonical(*before.Firewall.Running.Config.Routed)
	if err != nil {
		return err
	}
	end, err := routedmodel.Canonical(*target.Firewall.Running.Config.Routed)
	if err != nil {
		return err
	}
	prior, err := s.currentRetainedDHCPMarksV4(start)
	if err != nil {
		return err
	}
	work, err := loadRoutedDHCPWorkV3(s.state.RoutedDHCP.Work, s.state.Lineage, s.readObject)
	if err != nil {
		return err
	}
	_, _, _, err = s.reserveRoutedBootMarksLocked(work.Snapshot.Identity, op.ID, prior, start, end)
	return err
}

func (s *v2Store) preflightRetainedDHCPCommitV4(subject, domain string, expected uint64, request v2Request) error {
	if expected != s.state.Generation || !s.retainedDHCPCommitAllowedV4(v2Operation{Subject: subject, Domain: domain, Request: request}) {
		return nil
	}
	cfg := s.state.Configuration
	before, err := routedmodel.Canonical(*cfg.Firewall.Running.Config.Routed)
	if err != nil {
		return ErrRecovery
	}
	target, err := routedmodel.Canonical(*cfg.Firewall.Candidate.Revision.Config.Routed)
	if err != nil {
		return ErrRecovery
	}
	prior, err := s.currentRetainedDHCPMarksV4(before)
	if err != nil {
		return err
	}
	_, _, _, err = reserveRoutedMarkPairV1(prior.Boot, s.state.RoutedBootMarks.Issued, prior, before, target)
	return err
}

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

func (s *v2Store) selectRetainedDHCPCommitV4(next *v2State, op v2Operation) error {
	in := next.Configuration.Intent
	if in == nil || s.state.RoutedBootMarks == nil {
		return ErrRecovery
	}
	ref := actualDHCPConfigurationSourceV4(s.selector.Current, s.selection, s.state)
	group := &v4RoutedDHCPConfigurationGroup{Work: in.RoutedWork, Side: "target", MarkReservation: s.state.RoutedBootMarks.Reservation}
	transition, err := s.object(v4RoutedDHCPConfiguration{
		Version: 4, Lineage: ref.Lineage, Kind: "grouped", Impact: "preserve",
		SourceWork: ref.WorkHash, SourceSelection: ref, Operation: op.ID, Subject: op.Subject,
		Namespace: op.Namespace, Fingerprint: op.Fingerprint, Expected: op.Expected, Generation: in.TargetGeneration,
		Before: in.Previous, Target: in.Target, Group: group,
	})
	if err != nil {
		return err
	}
	if next.RoutedDHCPConfiguration == nil {
		next.RoutedDHCPConfiguration = &v4RoutedDHCPConfigurationState{Version: 4}
	}
	next.RoutedDHCPConfiguration.Transition = transition
	addFeatureV2(next, v4RoutedDHCPConfigurationFeature)
	return nil
}

func (s *v2Store) finishRetainedDHCPConfigurationV4(next *v2State, op v2Operation) error {
	h := next.RoutedDHCPConfiguration
	if h == nil {
		return nil
	}
	if h.Transition == "" {
		if op.Request.Kind != OpConfirm || op.Outcome == nil || op.Outcome.Code != "applied" {
			return ErrRecovery
		}
		receipt, err := s.object(op)
		if err != nil {
			return err
		}
		return s.finishRetainedDHCPClosingV4(next, receipt)
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

func (s *v2Store) finishRetainedDHCPClosingV4(next *v2State, result string) error {
	h := next.RoutedDHCPConfiguration
	if h == nil {
		return nil
	}
	intent := s.state.Configuration.Intent
	var current v4RoutedDHCPConfigurationContinuation
	if h.Transition != "" || intent == nil || s.readObject(h.Continuation, &current) != nil || current.Closing != nil {
		return ErrRecovery
	}
	cfg, err := s.object(*next.Configuration)
	if err != nil {
		return err
	}
	current.Closing = &v4RoutedDHCPClosing{Intent: *intent, Result: result, Final: cfg}
	h.Continuation, err = s.object(current)
	return err
}
