// Package firewalladmin coordinates authenticated adapters with the bounded
// transactional firewall engine. It contains no HTTP or privileged executables.
package firewalladmin

import (
	"context"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type LeaseState struct {
	Phase    string    `json:"phase"`
	ID       string    `json:"id"`
	Previous string    `json:"previous"`
	Target   string    `json:"target"`
	Deadline time.Time `json:"deadline"`
}

// LeaseAuthority independently authenticates its local channel and restricts
// policy scope. Confirm must retain an exact receipt for lost-ack reconciliation.
type LeaseAuthority interface {
	Arm(context.Context, string, configpoc.Revision, configpoc.Revision, time.Duration) error
	Confirm(context.Context, string, string) error
	Current(context.Context) (string, error)
	State(context.Context) (LeaseState, error)
}

type Service struct {
	mu        sync.Mutex
	core      *configpoc.Service
	authority LeaseAuthority
	blocked   bool
}

// New takes exclusive ownership of the coordinator. Startup/resume recovery is
// performed by the trusted runtime before construction; clients cannot select it.
func New(core *configpoc.Service, authority LeaseAuthority) (*Service, error) {
	if core == nil || authority == nil {
		return nil, configpoc.ErrInvalid
	}
	return &Service{core: core, authority: authority}, nil
}

func (s *Service) Execute(ctx context.Context, p configpoc.Principal, surface configpoc.Surface, r configpoc.Request) (configpoc.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Operation {
	case configpoc.OpStatus, configpoc.OpStage, configpoc.OpValidate, configpoc.OpCommit, configpoc.OpConfirm, configpoc.OpSave, configpoc.OpRollback:
	default:
		return configpoc.Snapshot{}, configpoc.ErrInvalid
	}
	if s.blocked && r.Operation != configpoc.OpStatus {
		return configpoc.Snapshot{}, configpoc.ErrRecovery
	}
	out, err := s.core.ExecuteManaged(ctx, p, surface, r, &activation{service: s})
	out.RecoveryRequired = out.RecoveryRequired || s.blocked
	return out, err
}

func (s *Service) History(p configpoc.Principal, before uint64, limit int) ([]configpoc.RevisionEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.Revisions(p, before, limit)
}

func (s *Service) Audit(p configpoc.Principal) ([]configpoc.Audit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.History(p)
}

type Observation struct {
	Hash             string `json:"hash"`
	Phase            string `json:"phase"`
	RecoveryRequired bool   `json:"recovery_required"`
}

// Observed authorizes before consulting authority and exposes no platform details.
func (s *Service) Observed(ctx context.Context, p configpoc.Principal) (Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.core.Execute(ctx, p, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if err != nil {
		return Observation{}, err
	}
	state, err := s.authority.State(ctx)
	if err != nil {
		return Observation{RecoveryRequired: true}, configpoc.ErrRecovery
	}
	hash, err := s.authority.Current(ctx)
	if err != nil {
		return Observation{RecoveryRequired: true}, configpoc.ErrRecovery
	}
	return Observation{Hash: hash, Phase: state.Phase, RecoveryRequired: s.blocked || snap.RecoveryRequired || hash != snap.Running.Hash}, nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.Close()
}

type activation struct{ service *Service }

func (a *activation) Arm(ctx context.Context, id string, previous, target configpoc.Revision, ttl time.Duration) error {
	s := a.service
	// Latch before crossing the authority boundary. Even an error can mean that
	// the remote side acted; callers must never continue with an ambiguous lease.
	s.blocked = true
	if err := s.authority.Arm(ctx, id, previous, target, ttl); err != nil {
		return configpoc.ErrRecovery
	}
	state, err := s.authority.State(ctx)
	if err != nil || state.Phase != "armed" || state.ID != id || state.Previous != previous.Hash || state.Target != target.Hash || !time.Now().Before(state.Deadline) {
		return configpoc.ErrRecovery
	}
	s.blocked = false
	return nil
}

func (a *activation) Confirm(ctx context.Context, id, hash string) error {
	s := a.service
	s.blocked = true
	// An error may only be reconciled by the exact authority receipt and current
	// effective revision, never by an idle phase alone.
	_ = s.authority.Confirm(ctx, id, hash)
	state, err := s.authority.State(ctx)
	if err != nil || state.Phase != "idle" || state.ID != id || state.Target != hash {
		return configpoc.ErrRecovery
	}
	current, err := s.authority.Current(ctx)
	if err != nil || current != hash {
		return configpoc.ErrRecovery
	}
	s.blocked = false
	return nil
}
