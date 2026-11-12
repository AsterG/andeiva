package configpoc

import (
	"context"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

type GlobalV2 struct {
	Lineage    string `json:"lineage_id"`
	Generation uint64 `json:"generation,string"`
	Running    string `json:"running_revision"`
	Startup    string `json:"startup_revision"`
}
type CurrentV2 struct {
	DomainGenerations *DomainGenerationsV2 `json:"domain_generations,omitempty"`
	Routed            *RoutedCurrentV2     `json:"routed,omitempty"`
	Global            GlobalV2             `json:"global"`
	Domain            string               `json:"domain"`
	Snapshot          Snapshot             `json:"snapshot"`
}

type DomainGenerationsV2 struct {
	Firewall      uint64 `json:"firewall,string"`
	LocalServices uint64 `json:"local_services,string"`
	Network       uint64 `json:"network,string"`
}

type CandidateGroupV2 = v2CandidateGroup

type RoutedCurrentV2 struct {
	Confirmation   *RoutedConfirmationV2 `json:"confirmation,omitempty"`
	SchemaVersion  int                   `json:"schema_version"`
	LocalServices  Snapshot              `json:"local_services"`
	Running        CompositeRevisionV1   `json:"running"`
	Startup        CompositeRevisionV1   `json:"startup"`
	LastGood       CompositeRevisionV1   `json:"last_good"`
	Candidate      *CompositeRevisionV1  `json:"candidate,omitempty"`
	CandidateGroup *CandidateGroupV2     `json:"candidate_group,omitempty"`
}

type RoutedConfirmationV2 struct {
	Origin   string    `json:"origin_commit_operation_id"`
	Target   string    `json:"target_revision"`
	Deadline time.Time `json:"confirmation_deadline"`
}
type ObservationV2 struct {
	Operation OperationV2
	Current   CurrentV2
}
type OperationPageV2 struct {
	Operations []OperationV2
	Cursor     uint64
	Current    CurrentV2
}

func (s *ServiceV2) currentLocked(domain string) (CurrentV2, error) {
	store := s.coordinator.store
	projectionDomain := domain
	if domain == "routed" {
		if !hasFeatureV2(store.state, v2RoutedFeature) {
			return CurrentV2{}, ErrDenied
		}
		projectionDomain = "firewall"
	}
	view, err := store.currentLegacyProjectionV2(projectionDomain, Snapshot{})
	if err != nil {
		return CurrentV2{}, err
	}
	// V2 projects durable retired subject incarnations, not imported v1 names.
	view.Revoked = []string{}
	for _, subject := range store.state.Subjects {
		if subject.Retired {
			view.Revoked = append(view.Revoked, subject.ID)
		}
	}
	state := store.state.Configuration
	current := CurrentV2{Global: GlobalV2{Lineage: store.state.Lineage, Generation: store.state.Generation, Running: state.Running.Hash, Startup: state.Startup.Hash}, Domain: domain, Snapshot: view}
	if hasFeatureV2(store.state, v2RoutedFeature) {
		local, err := store.currentLegacyProjectionV2("local_services", Snapshot{})
		if err != nil {
			return CurrentV2{}, err
		}
		current.DomainGenerations = &DomainGenerationsV2{Firewall: state.Firewall.Generation, LocalServices: state.LocalServices.Generation, Network: state.Firewall.Generation}
		current.Routed = &RoutedCurrentV2{SchemaVersion: 7, LocalServices: local, Running: state.Running, Startup: state.Startup, LastGood: state.LastGood, Candidate: state.Candidate, CandidateGroup: state.CandidateGroup}
		if pending := state.Pending; pending != nil && pending.Domain == "routed" {
			current.Routed.Confirmation = &RoutedConfirmationV2{Origin: pending.OriginCommit, Target: pending.Target, Deadline: pending.Deadline}
		}
	}
	return clone(current), nil
}
func (s *ServiceV2) Observe(binding adminauth.SessionBinding, id string) (ObservationV2, error) {
	var result ObservationV2
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		op, lookupErr := store.lookupLocked(p.Subject, id)
		result.Operation, err = operationDTOv2(op), lookupErr
		if err != nil {
			return err
		}
		if !store.observableDomainV2(result.Operation.Domain) {
			return ErrDenied
		}
		result.Current, err = s.currentLocked(result.Operation.Domain)
		return err
	})
	if err != nil {
		return ObservationV2{}, err
	}
	return result, nil
}
func (s *ServiceV2) AdmitObserved(binding adminauth.SessionBinding, namespace string, expected uint64, request OperationRequestV2) (ObservationV2, error) {
	var result ObservationV2
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		// Revoke has a reserved union member but no D execution implementation.
		// Do not reserve an operation that this prepared adapter cannot execute.
		switch request.Kind {
		case OpStage, OpValidate, OpCommit, OpConfirm, OpSave, OpRollback, OpRecover:
		default:
			return errV2Invalid
		}
		i := store.namespaceIndex(p.Subject, namespace)
		if i < 0 {
			return errV2NotFound
		}
		if !store.observableDomainV2(store.state.Namespaces[i].Domain) {
			return ErrDenied
		}
		op, admitErr := store.admitLocked(p.Subject, namespace, expected, request, s.coordinator.now())
		result.Operation, err = operationDTOv2(op), admitErr
		if err != nil {
			return err
		}
		result.Current, err = s.currentLocked(result.Operation.Domain)
		return err
	})
	if err != nil {
		return ObservationV2{}, err
	}
	return result, nil
}
func (s *ServiceV2) ExecuteObserved(ctx context.Context, binding adminauth.SessionBinding, id string) (ObservationV2, error) {
	var result ObservationV2
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		executed, executeErr := s.coordinator.executeLocked(ctx, p, id)
		if executed.GlobalGeneration == 0 {
			return executeErr
		}
		result.Operation = operationDTOv2(executed.Operation)
		result.Current, err = s.currentLocked(executed.Operation.Domain)
		if err != nil {
			return err
		}
		return executeErr
	})
	return result, err
}
func (s *ServiceV2) ObserveList(binding adminauth.SessionBinding, namespace, state string, after uint64, limit int) (OperationPageV2, error) {
	var result OperationPageV2
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		i := store.namespaceIndex(p.Subject, namespace)
		if i < 0 {
			return errV2NotFound
		}
		if !store.observableDomainV2(store.state.Namespaces[i].Domain) {
			return ErrDenied
		}
		if state != "" && state != "accepted" && state != "pending" && state != "final" && state != "uncertain" {
			return errV2Invalid
		}
		if after > store.state.HighWater {
			return errV2Invalid
		}
		ops, cursor, err := store.listLocked(p.Subject, namespace, after, limit)
		if err != nil {
			return err
		}
		result.Operations = []OperationV2{}
		for _, op := range ops {
			if state == "" || op.State == state {
				result.Operations = append(result.Operations, operationDTOv2(op))
			}
		}
		result.Cursor = cursor
		result.Current, err = s.currentLocked(store.state.Namespaces[i].Domain)
		return err
	})
	if err != nil {
		return OperationPageV2{}, err
	}
	return result, nil
}

// Standalone Local Service admission/closure remains unavailable until its
// transport proof mapping exists. Routed observations require the selected gate.
func (s *ServiceV2) CloseObservedNamespace(binding adminauth.SessionBinding, namespace string) error {
	return s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) error {
		i := store.namespaceIndex(p.Subject, namespace)
		if i < 0 {
			return errV2NotFound
		}
		if !store.observableDomainV2(store.state.Namespaces[i].Domain) {
			return ErrDenied
		}
		return store.closeNamespaceLocked(p.Subject, namespace, s.coordinator.now())
	})
}

func (s *v2Store) observableDomainV2(domain string) bool {
	return domain == "firewall" || domain == "routed" && hasFeatureV2(s.state, v2RoutedFeature)
}
