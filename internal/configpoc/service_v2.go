package configpoc

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

// Catalogue DTOs contain durable business requests/results, never credentials,
// transport evidence or a handle to the storage/coordinator implementation.
type OperationV2 struct {
	ID            string             `json:"id"`
	Namespace     string             `json:"namespace_id"`
	Subject       string             `json:"subject"`
	Lineage       string             `json:"lineage"`
	Domain        string             `json:"domain"`
	Sequence      uint64             `json:"sequence,string"`
	Expected      uint64             `json:"expected_generation,string"`
	Request       OperationRequestV2 `json:"request"`
	Fingerprint   string             `json:"fingerprint"`
	State         string             `json:"state"`
	Accepted      time.Time          `json:"accepted_at"`
	ExecuteBefore time.Time          `json:"execute_before"`
	Completed     *time.Time         `json:"completed_at,omitempty"`
	RetainUntil   *time.Time         `json:"retain_until,omitempty"`
	Outcome       *OutcomeV2         `json:"outcome,omitempty"`
	Pinned        bool               `json:"pinned"`
	Retired       bool               `json:"retired"`
}
type OutcomeV2 struct {
	Code                 string     `json:"code"`
	ErrorCode            string     `json:"error_code,omitempty"`
	Generation           uint64     `json:"generation,string"`
	AuditHash            string     `json:"audit_hash"`
	DomainGeneration     uint64     `json:"domain_generation,string,omitempty"`
	RunningRevision      string     `json:"running_revision,omitempty"`
	StartupRevision      string     `json:"startup_revision,omitempty"`
	ConfirmationDeadline *time.Time `json:"confirmation_deadline,omitempty"`
	ConfirmationLease    string     `json:"confirmation_lease,omitempty"`
	AuditFirst           uint64     `json:"audit_first_sequence,string,omitempty"`
	AuditLast            uint64     `json:"audit_last_sequence,string,omitempty"`
}
type OperationRequestV2 = v2Request
type NamespaceV2 struct {
	ID         string    `json:"id"`
	Subject    string    `json:"subject"`
	Domain     string    `json:"domain"`
	Closed     bool      `json:"closed"`
	AdmitUntil time.Time `json:"admit_until"`
	Open       []string  `json:"open"`
}

func operationDTOv2(op v2Operation) OperationV2 {
	op = clone(op)
	result := OperationV2{ID: op.ID, Namespace: op.Namespace, Subject: op.Subject, Lineage: op.Lineage, Domain: op.Domain, Sequence: op.Sequence, Expected: op.Expected, Request: op.Request, Fingerprint: op.Fingerprint, State: op.State, Accepted: op.Accepted, ExecuteBefore: op.ExecuteBefore, Completed: op.Completed, RetainUntil: op.RetainUntil, Pinned: op.Pinned, Retired: op.Retired}
	if op.Outcome != nil {
		outcome := OutcomeV2(*op.Outcome)
		result.Outcome = &outcome
	}
	return result
}
func operationsDTOv2(ops []v2Operation) []OperationV2 {
	if ops == nil {
		return nil
	}
	result := make([]OperationV2, len(ops))
	for i, op := range ops {
		result[i] = operationDTOv2(op)
	}
	return result
}

func namespaceDTOv2(ns v2Namespace) NamespaceV2 {
	return NamespaceV2{ID: ns.ID, Subject: ns.Subject, Domain: ns.Domain, Closed: ns.Closed, AdmitUntil: ns.AdmitUntil, Open: clone(ns.Open)}
}

func operationDTOFingerprintV2(op OperationV2) string {
	return v2OperationFingerprint(v2Operation{ID: op.ID, Namespace: op.Namespace, Subject: op.Subject, Lineage: op.Lineage, Domain: op.Domain, Expected: op.Expected, Request: op.Request})
}

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
	return openServiceV2(ctx, area, budget, auth, firewall, local, nil)
}
func openServiceV2(ctx context.Context, area *os.Root, budget BudgetV2, auth *adminauth.Manager, firewall, local []Engine, policy LocalPolicyV2) (*ServiceV2, error) {
	return openServiceCoordinatorV2(ctx, area, budget, auth, firewall, local, v2CoordinatorOptions{LocalPolicy: policy})
}
func openServiceCoordinatorV2(ctx context.Context, area *os.Root, budget BudgetV2, auth *adminauth.Manager, firewall, local []Engine, options v2CoordinatorOptions) (*ServiceV2, error) {
	if auth == nil {
		return nil, ErrDenied
	}
	var store *v2Store
	var err error
	if options.SharedReader != nil {
		store, err = openSharedStoreV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes}, *options.SharedReader)
	} else {
		store, err = openV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes})
	}
	if err != nil {
		return nil, fmt.Errorf("selected configuration open: %w", err)
	}
	if options.Integrity != nil {
		store.mu.Lock()
		reference, attachErr := selectedReferenceV2(store)
		if attachErr == nil {
			attachCtx, cancel := context.WithTimeout(ctx, IntegrityInspectionDeadlineV1)
			attachErr = options.Integrity.Attach(attachCtx, reference)
			cancel()
		}
		store.mu.Unlock()
		if attachErr != nil {
			_ = store.close()
			return nil, fmt.Errorf("configuration integrity attach: %w", attachErr)
		}
		options.integrityAttached = true
	}
	c, err := openCoordinatorV2(ctx, store, firewall, local, options)
	if err != nil {
		if c != nil {
			c.close()
		}
		_ = store.close()
		return nil, fmt.Errorf("configuration coordinator open: %w", err)
	}
	service := &ServiceV2{coordinator: c, auth: auth}
	if options.Integrity != nil {
		if err := service.qualifyRuntimeIntegrityV1(ctx); err != nil {
			_ = service.Close()
			return nil, fmt.Errorf("configuration integrity qualification: %w", err)
		}
	}
	return service, nil
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
	return s.catalogueAccessV1(binding, false, call)
}

func (s *ServiceV2) catalogueMutationV1(binding adminauth.SessionBinding, call func(*v2Store, v2TrustedPrincipal) error) error {
	return s.catalogueAccessV1(binding, true, call)
}

func (s *ServiceV2) catalogueAccessV1(binding adminauth.SessionBinding, mutation bool, call func(*v2Store, v2TrustedPrincipal) error) error {
	p, err := s.principal(binding)
	if err != nil {
		return err
	}
	c := s.coordinator
	if c.options.Integrity != nil && c.integrity.inspecting.Load() {
		return ErrRecovery
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked {
		return errV2Unavailable
	}
	if p.Role != RoleAdmin || !c.store.principalV2Locked(p) {
		return ErrDenied
	}
	if mutation && !c.integrityAllowsV1(false) {
		return ErrRecovery
	}
	return call(c.store, p)
}

func (s *ServiceV2) Namespace(binding adminauth.SessionBinding, domain string, lifetime time.Duration) (NamespaceV2, error) {
	var result v2Namespace
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		if s.coordinator.options.Routed != nil && hasFeatureV2(store.state, v2RoutedFeature) && domain != "routed" {
			return ErrDenied
		}
		if !s.coordinator.integrityAllowsV1(false) {
			if !s.coordinator.integrityAllowsV1(true) || lifetime <= 0 || lifetime > 24*time.Hour || s.coordinator.now().Before(store.state.Clock) {
				return ErrRecovery
			}
			pending := store.state.Configuration.Pending
			if pending.Owner != p.Subject || pending.Domain != domain {
				return ErrDenied
			}
			for _, namespace := range store.state.Namespaces {
				if namespace.Subject == p.Subject && namespace.Domain == domain && namespace.ClosingOrigin == pending.OriginCommit && !namespace.Closed && s.coordinator.now().Before(namespace.AdmitUntil) {
					result = clone(namespace)
					return nil
				}
			}
			// Only a reserved closing namespace may be published while a live
			// confirmation prevents the next quiescent integrity inspection.
			result, err = store.closingNamespaceLocked(p.Subject, domain, s.coordinator.now(), lifetime)
			return err
		}
		result, err = store.namespaceLocked(p.Subject, domain, s.coordinator.now(), lifetime)
		return err
	})
	return namespaceDTOv2(result), err
}
func (s *ServiceV2) Admit(binding adminauth.SessionBinding, namespace string, expected uint64, request OperationRequestV2) (OperationV2, error) {
	var result v2Operation
	err := s.catalogueAdmissionV1(binding, namespace, request, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		if i := store.namespaceIndex(p.Subject, namespace); s.coordinator.options.Routed != nil && hasFeatureV2(store.state, v2RoutedFeature) && i >= 0 && store.state.Namespaces[i].Domain != "routed" {
			return ErrDenied
		}
		result, err = store.admitLocked(p.Subject, namespace, expected, request, s.coordinator.now())
		return err
	})
	return operationDTOv2(result), err
}
func (s *ServiceV2) Query(binding adminauth.SessionBinding, id string) (OperationV2, error) {
	var result v2Operation
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		result, err = store.lookupLocked(p.Subject, id)
		return err
	})
	return operationDTOv2(result), err
}
func (s *ServiceV2) List(binding adminauth.SessionBinding, namespace string, after uint64, limit int) ([]OperationV2, uint64, error) {
	var result []v2Operation
	var cursor uint64
	err := s.catalogue(binding, func(store *v2Store, p v2TrustedPrincipal) (err error) {
		result, cursor, err = store.listLocked(p.Subject, namespace, after, limit)
		return err
	})
	return operationsDTOv2(result), cursor, err
}
func (s *ServiceV2) CloseNamespace(binding adminauth.SessionBinding, namespace string) error {
	return s.catalogueMutationV1(binding, func(store *v2Store, p v2TrustedPrincipal) error {
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
	return ResultV2{Operation: operationDTOv2(result.Operation), Current: serviceStatusV2(result.Current, result.GlobalGeneration)}, err
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
