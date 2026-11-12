package configpoc

import (
	"context"
	"os"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

type LocalReceiverV2 struct {
	Run, Instance, Endpoint, ActivationHash string
	Namespace                               uint64
	Surface                                 Surface
}
type LocalEvidenceV2 struct {
	Recovery  string   `json:"-"`
	Endpoints []string `json:"-"`
}

func (LocalEvidenceV2) String() string   { return "<local evidence>" }
func (LocalEvidenceV2) GoString() string { return "<local evidence>" }

type LocalTokenV2 struct {
	Token     string    `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

func (LocalTokenV2) String() string   { return "<local proof>" }
func (LocalTokenV2) GoString() string { return "<local proof>" }

// Implementations retain opaque authenticated observations; marker interfaces
// convey no authorization. Only the configured policy interprets their values.
type LocalHandleV2 interface{ LocalProofHandleV2() }
type LocalReservationV2 interface{ Finish(consume bool) }
type LocalPendingViewV2 struct {
	Lineage, Subject, Login, CredentialRevision string
	Generation, LocalGeneration                 uint64
	Origin, Lease, Target                       string
	Deadline                                    time.Time
	Local                                       Revision
	Firewall                                    Revision
}

func (v LocalPendingViewV2) Valid() bool {
	global, err := v2CompositeFromDomains(v.Firewall, v.Local)
	return err == nil && global.Hash == v.Target && localProofRevision(v.Local, 3) && localProofRevision(v.Firewall, 4) && v.Lineage != "" && v.Subject != "" && identifier.MatchString(v.Login) && v2HashPattern.MatchString(v.CredentialRevision) && v.Generation > 0 && v.LocalGeneration > 0 && v.Origin != "" && len(v.Lease) > 0 && len(v.Lease) <= 64 && !v.Deadline.IsZero()
}

// Authenticate runs before store.mu. Every other callback runs under store.mu
// and may take only its proof-book lock: no auth, storage, engine or network I/O.
type LocalPolicyV2 interface {
	AuthenticationAuthority() *adminauth.Manager
	Authenticate(adminauth.SessionBinding, LocalReceiverV2, LocalEvidenceV2) (LocalHandleV2, error)
	Validate(LocalProofScopeV2) error
	Issue(LocalHandleV2, LocalProofScopeV2) (LocalTokenV2, error)
	Reserve(LocalHandleV2, LocalProofScopeV2) (LocalReservationV2, error)
	PublishPending(LocalPendingViewV2) error
	Invalidate()
}

func (c *v2Coordinator) localScopeLocked(op v2Operation, p v2TrustedPrincipal) (LocalProofScopeV2, error) {
	s := c.store
	if c.options.LocalPolicy == nil || c.closed || s.blocked || s.state.Configuration == nil || !s.principalV2Locked(p) || p.Role != RoleAdmin || op.Subject != p.Subject {
		return LocalProofScopeV2{}, ErrDenied
	}
	state := s.state.Configuration
	if state.Intent != nil || state.RecoveryRequired {
		return LocalProofScopeV2{}, ErrRecovery
	}
	i := s.namespaceIndex(op.Subject, op.Namespace)
	if i < 0 {
		return LocalProofScopeV2{}, errV2NotFound
	}
	var subject SubjectV2
	for _, item := range s.state.Subjects {
		if item.ID == op.Subject {
			subject = item
			break
		}
	}
	fw, err := s.currentLegacyProjectionV2("firewall", Snapshot{})
	if err != nil {
		return LocalProofScopeV2{}, err
	}
	local, err := s.currentLegacyProjectionV2("local_services", Snapshot{})
	if err != nil {
		return LocalProofScopeV2{}, err
	}
	// The pure mapper receives the exact global confirmation separately. Its
	// component snapshots intentionally contain no duplicate legacy Pending view.
	fw.Pending, local.Pending = nil, nil
	in := LocalProofInputV2{Operation: clone(op), Namespace: clone(s.state.Namespaces[i]), Subject: subject, Global: GlobalV2{Lineage: s.state.Lineage, Generation: s.state.Generation, Running: state.Running.Hash, Startup: state.Startup.Hash}, Firewall: fw, Local: local}
	if pending := state.Pending; pending != nil {
		in.Confirmation = &ConfirmationV2{Origin: pending.OriginCommit, Lease: pending.Lease, Domain: pending.Domain, Target: pending.Target, Deadline: pending.Deadline}
		in.ConfirmationOwner = pending.Owner
		origin, e := s.lookupRetained(pending.Owner, pending.OriginCommit)
		if e != nil {
			return LocalProofScopeV2{}, e
		}
		in.Origin = &origin
		if op.Request.Kind != OpConfirm {
			in.Origin = nil
			in.ConfirmationOwner = ""
		}
	}
	if op.Request.Kind == OpRollback {
		historical, e := c.loadDomainRevision(op.Request.Target, "local_services")
		if e != nil {
			return LocalProofScopeV2{}, e
		}
		in.Historical = &historical
	}
	scope, err := ResolveLocalProofV2(in, c.now())
	if err != nil {
		return LocalProofScopeV2{}, err
	}
	if err = c.options.LocalPolicy.Validate(scope); err != nil {
		return LocalProofScopeV2{}, err
	}
	return scope, nil
}

func (c *v2Coordinator) invalidateLocalLocked() {
	if c.options.LocalPolicy != nil {
		c.options.LocalPolicy.Invalidate()
	}
}
func (c *v2Coordinator) publishLocalLocked() error {
	if c.options.LocalPolicy == nil {
		return nil
	}
	state := c.store.state.Configuration
	if state == nil || state.Intent != nil || state.RecoveryRequired || state.Pending == nil || state.Pending.Domain != "local_services" {
		c.options.LocalPolicy.Invalidate()
		return nil
	}
	if !c.readback(*state) {
		return ErrRecovery
	}
	pending := state.Pending
	var subject SubjectV2
	for _, sub := range c.store.state.Subjects {
		if sub.ID == pending.Owner && !sub.Retired {
			subject = sub
			break
		}
	}
	// Revocation never disables autonomous safety recovery; it prevents new
	// endpoint evidence. A later authorized registry lifecycle must requalify it.
	if subject.ID == "" {
		return nil
	}
	return c.options.LocalPolicy.PublishPending(LocalPendingViewV2{Lineage: c.store.state.Lineage, Subject: subject.ID, Login: subject.Login, CredentialRevision: subject.CredentialRevision, Generation: c.store.state.Generation, LocalGeneration: state.LocalServices.Generation, Origin: pending.OriginCommit, Lease: pending.Lease, Target: pending.Target, Deadline: pending.Deadline, Local: clone(state.LocalServices.Running), Firewall: clone(state.Firewall.Running)})
}

// OpenServiceV2WithLocalPolicy is a trusted prepared assembly constructor, not a
// public activation flag. An absent/mismatched authority never enables writes.
func OpenServiceV2WithLocalPolicy(ctx context.Context, area *os.Root, budget BudgetV2, auth *adminauth.Manager, firewall, local []Engine, policy LocalPolicyV2) (*ServiceV2, error) {
	if policy == nil || auth == nil || policy.AuthenticationAuthority() != auth {
		return nil, ErrDenied
	}
	return openServiceV2(ctx, area, budget, auth, firewall, local, policy)
}
