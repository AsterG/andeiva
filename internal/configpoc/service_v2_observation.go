package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/adminauth"
)

type GlobalV2 struct {
	Lineage    string `json:"lineage_id"`
	Generation uint64 `json:"generation,string"`
	Running    string `json:"running_revision"`
	Startup    string `json:"startup_revision"`
}
type CurrentV2 struct {
	Global   GlobalV2 `json:"global"`
	Domain   string   `json:"domain"`
	Snapshot Snapshot `json:"snapshot"`
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
	view, err := store.currentLegacyProjectionV2(domain, Snapshot{})
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
	return CurrentV2{Global: GlobalV2{Lineage: store.state.Lineage, Generation: store.state.Generation, Running: state.Running.Hash, Startup: state.Startup.Hash}, Domain: domain, Snapshot: view}, nil
}
func (s *ServiceV2) Observe(binding adminauth.SessionBinding, id string) (ObservationV2, error) {
	var result ObservationV2
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		op, lookupErr := store.lookupLocked(p.Subject, id)
		result.Operation, err = operationDTOv2(op), lookupErr
		if err != nil {
			return err
		}
		if result.Operation.Domain != "firewall" {
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
		if store.state.Namespaces[i].Domain != "firewall" {
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
		if store.state.Namespaces[i].Domain != "firewall" {
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

// Prepared observation endpoints are qualified for firewall only. Local Service
// admission/closure remains unavailable until its transport proof mapping exists.
func (s *ServiceV2) CloseObservedNamespace(binding adminauth.SessionBinding, namespace string) error {
	return s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) error {
		i := store.namespaceIndex(p.Subject, namespace)
		if i < 0 {
			return errV2NotFound
		}
		if store.state.Namespaces[i].Domain != "firewall" {
			return ErrDenied
		}
		return store.closeNamespaceLocked(p.Subject, namespace, s.coordinator.now())
	})
}
