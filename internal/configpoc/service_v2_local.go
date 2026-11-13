package configpoc

import (
	"context"

	"github.com/AsterG/andeiva/internal/adminauth"
)

func (s *ServiceV2) localAccessV2(binding adminauth.SessionBinding, receiver LocalReceiverV2, evidence LocalEvidenceV2) (v2TrustedPrincipal, LocalHandleV2, error) {
	p, err := s.principal(binding)
	if err != nil {
		return p, nil, err
	}
	policy := s.coordinator.options.LocalPolicy
	if policy == nil || policy.AuthenticationAuthority() != s.auth {
		return p, nil, ErrDenied
	}
	evidence.Endpoints = append([]string{}, evidence.Endpoints...)
	handle, err := policy.Authenticate(binding, receiver, evidence)
	return p, handle, err
}

func (s *ServiceV2) AdmitLocalV2(binding adminauth.SessionBinding, namespace string, expected uint64, request OperationRequestV2) (OperationV2, error) {
	var result v2Operation
	err := s.catalogueMutationV1(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		if s.coordinator.options.LocalPolicy == nil {
			return ErrDenied
		}
		i := store.namespaceIndex(p.Subject, namespace)
		if i < 0 {
			return errV2NotFound
		}
		if store.state.Namespaces[i].Domain != "local_services" {
			return ErrDenied
		}
		switch request.Kind {
		case OpStage, OpValidate, OpConfirm, OpSave, OpRollback:
		case OpCommit:
			if request.ConfirmSeconds == nil || *request.ConfirmSeconds < 30 || *request.ConfirmSeconds > 120 {
				return ErrInvalid
			}
		default:
			return ErrDenied
		}
		result, err = store.admitLocked(p.Subject, namespace, expected, request, s.coordinator.now())
		return err
	})
	return operationDTOv2(result), err
}

// IssueLocalProofV2 accepts only an operation ID. Scope, subject incarnation,
// namespace, revisions, generations and the pending lease come from this store.
func (s *ServiceV2) IssueLocalProofV2(binding adminauth.SessionBinding, id, purpose string, receiver LocalReceiverV2) (LocalTokenV2, error) {
	p, handle, err := s.localAccessV2(binding, receiver, LocalEvidenceV2{})
	if err != nil {
		return LocalTokenV2{}, err
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	op, err := c.store.lookupLocked(p.Subject, id)
	if err != nil {
		return LocalTokenV2{}, err
	}
	scope, err := c.localScopeLocked(op, p)
	if err != nil {
		return LocalTokenV2{}, err
	}
	if purpose != scope.Binding().Purpose {
		return LocalTokenV2{}, ErrInvalid
	}
	if !c.readback(*c.store.state.Configuration) {
		c.invalidateLocalLocked()
		return LocalTokenV2{}, ErrRecovery
	}
	if purpose == "confirm" {
		if err = c.publishLocalLocked(); err != nil {
			return LocalTokenV2{}, err
		}
	}
	return c.options.LocalPolicy.Issue(handle, scope)
}

// ExecuteLocalV2 reauthenticates before store.mu, then revalidates the canonical
// registry and exact admitted operation while holding that same mutation lock.
func (s *ServiceV2) ExecuteLocalV2(ctx context.Context, binding adminauth.SessionBinding, id string, receiver LocalReceiverV2, evidence LocalEvidenceV2) (ObservationV2, error) {
	p, handle, err := s.localAccessV2(binding, receiver, evidence)
	if err != nil {
		return ObservationV2{}, err
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if ctx == nil {
		return ObservationV2{}, ErrInvalid
	}
	op, err := c.store.lookupLocked(p.Subject, id)
	if err != nil {
		return ObservationV2{}, err
	}
	if op.Domain != "local_services" {
		return ObservationV2{}, ErrDenied
	}
	executed, err := c.executeLocalLocked(ctx, p, id, handle)
	if executed.GlobalGeneration == 0 {
		return ObservationV2{}, err
	}
	current, viewErr := s.currentLocked("local_services")
	if viewErr != nil {
		return ObservationV2{}, viewErr
	}
	return ObservationV2{Operation: operationDTOv2(executed.Operation), Current: current}, err
}
