package configpoc

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

// Catalogue DTOs contain durable business requests/results, never credentials,
// transport evidence or a handle to the storage/coordinator implementation.
type OperationV2 = v2Operation
type OperationRequestV2 = v2Request
type NamespaceV2 = v2Namespace

type BudgetV2 struct{ Bytes, Inodes uint64 }
type StatusV2 struct {
	GlobalGeneration  uint64          `json:"global_generation,string"`
	RunningRevision   string          `json:"running_revision"`
	StartupRevision   string          `json:"startup_revision"`
	CandidateRevision string          `json:"candidate_revision,omitempty"`
	RecoveryRequired  bool            `json:"recovery_required"`
	Confirmation      *ConfirmationV2 `json:"confirmation,omitempty"`
}
type ConfirmationV2 struct {
	Origin   string    `json:"origin_commit_operation_id"`
	Lease    string    `json:"lease"`
	Domain   string    `json:"domain"`
	Target   string    `json:"target_revision"`
	Deadline time.Time `json:"deadline"`
}
type ResultV2 struct {
	Operation OperationV2 `json:"operation"`
	Current   StatusV2    `json:"current"`
}

// ServiceV2 is an opt-in adapter for an already prepared v2 store. There is no
// runtime cutover, migration, subject creation or begin/finish bypass here.
// Transports must still enforce their TLS/origin/CSRF and evidence contracts.
type ServiceV2 struct {
	coordinator         *v2Coordinator
	auth                *adminauth.Manager
	closeMu             sync.Mutex
	closeErr            error
	closed              bool
	afterAuthentication func()
}

// OpenServiceV2 never creates a configuration database. Engine sets are fixed
// by the trusted installer. Opening may reconcile a durable interrupted intent
// through those engines; it never promotes an unverified state to Running.
func OpenServiceV2(ctx context.Context, area *os.Root, budget BudgetV2, auth *adminauth.Manager, firewall, local []Engine) (*ServiceV2, error) {
	if auth == nil {
		return nil, ErrDenied
	}
	store, err := openV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes})
	if err != nil {
		return nil, err
	}
	c, err := openCoordinatorV2(ctx, store, firewall, local, v2CoordinatorOptions{})
	if err != nil {
		if c != nil {
			c.close()
		}
		_ = store.close()
		return nil, err
	}
	return &ServiceV2{coordinator: c, auth: auth}, nil
}

func (s *ServiceV2) Close() error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if !s.closed {
		if s.coordinator != nil && s.coordinator.store != nil {
			s.coordinator.close()
			s.closeErr = s.coordinator.store.close()
		}
		s.closed = true
	}
	return s.closeErr
}

func (s *ServiceV2) principal(binding adminauth.SessionBinding) (v2TrustedPrincipal, error) {
	if s == nil || s.auth == nil || s.coordinator == nil || s.coordinator.store == nil {
		return v2TrustedPrincipal{}, ErrDenied
	}
	verified, err := s.auth.VerifySession(binding)
	if err != nil {
		if err == adminauth.ErrUnavailable {
			return v2TrustedPrincipal{}, errV2Unavailable
		}
		return v2TrustedPrincipal{}, ErrDenied
	}
	p := v2TrustedPrincipal{Subject: verified.SubjectID(), Role: Role(verified.Role()), Login: verified.Login(), CredentialRevision: verified.CredentialRevision()}
	if p.Subject == "" || p.Login == "" || !v2HashPattern.MatchString(p.CredentialRevision) {
		return v2TrustedPrincipal{}, ErrDenied
	}
	if s.afterAuthentication != nil {
		s.afterAuthentication()
	}
	return p, nil
}

// Caller holds store.mu. Legacy/internal D callers omit both mirror fields;
// the public adapter always requires both from its pinned session authority.
func (s *v2Store) principalV2Locked(p v2TrustedPrincipal) bool {
	for _, sub := range s.state.Subjects {
		if sub.ID == p.Subject && !sub.Retired {
			if p.Login == "" && p.CredentialRevision == "" {
				return true
			}
			return p.Login != "" && p.CredentialRevision != "" && sub.Login == p.Login && sub.CredentialRevision == p.CredentialRevision
		}
	}
	return false
}

// Authentication linearizes before the store lock; a later logout cannot
// cancel already admitted work. Registry identity/revision/retirement is checked
// under the same lock as each catalogue action, preventing rotation TOCTOU.
// No path acquires the authentication lock while holding the store lock.
func (s *ServiceV2) catalogue(binding adminauth.SessionBinding, call func(*v2Store, v2TrustedPrincipal) error) error {
	p, err := s.principal(binding)
	if err != nil {
		return err
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked {
		return errV2Unavailable
	}
	if p.Role != RoleAdmin || !c.store.principalV2Locked(p) {
		return ErrDenied
	}
	return call(c.store, p)
}

func (s *ServiceV2) Namespace(binding adminauth.SessionBinding, domain string, lifetime time.Duration) (NamespaceV2, error) {
	var result v2Namespace
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		result, err = store.namespaceLocked(p.Subject, domain, s.coordinator.now(), lifetime)
		return err
	})
	return clone(result), err
}
func (s *ServiceV2) Admit(binding adminauth.SessionBinding, namespace string, expected uint64, request OperationRequestV2) (OperationV2, error) {
	var result v2Operation
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		result, err = store.admitLocked(p.Subject, namespace, expected, request, s.coordinator.now())
		return err
	})
	return clone(result), err
}
func (s *ServiceV2) Query(binding adminauth.SessionBinding, id string) (OperationV2, error) {
	var result v2Operation
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		result, err = store.lookupLocked(p.Subject, id)
		return err
	})
	return clone(result), err
}
func (s *ServiceV2) List(binding adminauth.SessionBinding, namespace string, after uint64, limit int) ([]OperationV2, uint64, error) {
	var result []v2Operation
	var cursor uint64
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		result, cursor, err = store.listLocked(p.Subject, namespace, after, limit)
		return err
	})
	return clone(result), cursor, err
}
func (s *ServiceV2) CloseNamespace(binding adminauth.SessionBinding, namespace string) error {
	return s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) error {
		return store.closeNamespaceLocked(p.Subject, namespace, s.coordinator.now())
	})
}
func (s *ServiceV2) Execute(ctx context.Context, binding adminauth.SessionBinding, id string) (ResultV2, error) {
	p, err := s.principal(binding)
	if err != nil {
		return ResultV2{}, err
	}
	result, err := s.coordinator.execute(ctx, p, id)
	if result.GlobalGeneration == 0 {
		return ResultV2{}, err
	}
	return ResultV2{Operation: result.Operation, Current: serviceStatusV2(result.Current, result.GlobalGeneration)}, err
}
func (s *ServiceV2) Status(binding adminauth.SessionBinding) (StatusV2, error) {
	p, err := s.principal(binding)
	if err != nil {
		return StatusV2{}, err
	}
	state, generation, err := s.coordinator.status(p)
	if err != nil {
		return StatusV2{}, err
	}
	return serviceStatusV2(state, generation), nil
}
func serviceStatusV2(state v2Configuration, generation uint64) StatusV2 {
	result := StatusV2{GlobalGeneration: generation, RunningRevision: state.Running.Hash, StartupRevision: state.Startup.Hash, RecoveryRequired: state.RecoveryRequired || state.Intent != nil}
	if state.Candidate != nil {
		result.CandidateRevision = state.Candidate.Hash
	}
	if pending := state.Pending; pending != nil {
		result.Confirmation = &ConfirmationV2{Origin: pending.OriginCommit, Lease: pending.Lease, Domain: pending.Domain, Target: pending.Target, Deadline: pending.Deadline}
	}
	return result
}

// Projection is a read-only domain view with its persisted projection counter.
// It does not reinterpret the global storage generation as a domain revision.
func (s *ServiceV2) Projection(binding adminauth.SessionBinding, domain string) (Snapshot, error) {
	p, err := s.principal(binding)
	if err != nil {
		return Snapshot{}, err
	}
	c := s.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked {
		return Snapshot{}, errV2Unavailable
	}
	if !c.store.principalV2Locked(p) || (p.Role != RoleAdmin && p.Role != RoleViewer) {
		return Snapshot{}, ErrDenied
	}
	return c.store.currentLegacyProjectionV2(domain, Snapshot{})
}
