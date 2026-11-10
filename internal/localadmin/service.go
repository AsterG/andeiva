package localadmin

import (
	"context"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type Service struct {
	mu      sync.Mutex
	core    *configpoc.Service
	options Options
	proofs  proofBook
	blocked bool
}

// New takes exclusive ownership of a coordinator already recovered by the
// trusted runtime. It does not bootstrap, change policy or infer host inventory.
func New(core *configpoc.Service, options Options) (*Service, error) {
	if core == nil || options.Authority == nil || options.Observer == nil || !validHex(options.RunID, 16) ||
		!identifier.MatchString(options.RecoveryEndpointID) || len(options.Inventory) == 0 || len(options.Inventory) > 2 {
		return nil, configpoc.ErrInvalid
	}
	inventory, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: localpolicy.SchemaVersion, Interfaces: options.Inventory})
	if err != nil {
		return nil, configpoc.ErrInvalid
	}
	options.Inventory = inventory.Config.Interfaces
	return &Service{core: core, options: options, proofs: proofBook{runID: options.RunID, entries: make(map[[32]byte]attestation), now: time.Now}}, nil
}

func (s *Service) Execute(ctx context.Context, c Context, request Request) (configpoc.Snapshot, error) {
	if !validContext(c) {
		return configpoc.Snapshot{}, configpoc.ErrDenied
	}
	operation := request.Transaction.Operation
	if c.Principal.Role != configpoc.RoleAdmin && operation != configpoc.OpStatus {
		return configpoc.Snapshot{}, configpoc.ErrDenied
	}
	switch operation {
	case configpoc.OpStatus, configpoc.OpStage, configpoc.OpValidate, configpoc.OpCommit, configpoc.OpConfirm, configpoc.OpSave, configpoc.OpRollback:
	default:
		return configpoc.Snapshot{}, configpoc.ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return configpoc.Snapshot{}, err
	}
	// Once an authenticated request is admitted, retiring its own listening
	// connection must not cancel the transaction it requested. Preserve the
	// caller's deadline and a hard local bound; lost replies use durable replay.
	deadline := time.Now().Add(10 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	operationCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	if s.blocked && operation != configpoc.OpStatus {
		return configpoc.Snapshot{}, configpoc.ErrRecovery
	}
	g := &activation{service: s, caller: c, request: request}
	defer func() { s.proofs.finish(g.reserved, false) }()
	out, err := s.core.ExecuteManaged(operationCtx, c.Principal, c.Surface, request.Transaction, g)
	if err == nil && operation == configpoc.OpSave {
		s.proofs.finish(g.reserved, true)
	}
	out.RecoveryRequired = out.RecoveryRequired || s.blocked
	if err == nil {
		s.proofs.publish(out, s.options.RecoveryEndpointID)
	}
	if s.blocked {
		return out, configpoc.ErrRecovery
	}
	return out, err
}

func (s *Service) History(c Context, before uint64, limit int) ([]configpoc.RevisionEntry, error) {
	if !validContext(c) || c.Principal.Role != configpoc.RoleAdmin {
		return nil, configpoc.ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.Revisions(c.Principal, before, limit)
}

func (s *Service) Audit(c Context) ([]configpoc.Audit, error) {
	if !validContext(c) || c.Principal.Role != configpoc.RoleAdmin {
		return nil, configpoc.ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core.History(c.Principal)
}

func (s *Service) Status(ctx context.Context, c Context) (Status, error) {
	if !validContext(c) {
		return Status{}, configpoc.ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.core.Execute(ctx, c.Principal, c.Surface, configpoc.Request{Operation: configpoc.OpStatus})
	if err != nil {
		return Status{}, err
	}
	effective, _ := s.observe(ctx, snap.Running)
	effective.RecoveryRequired = effective.RecoveryRequired || snap.RecoveryRequired || s.blocked
	snap.RecoveryRequired = effective.RecoveryRequired
	s.proofs.publish(snap, s.options.RecoveryEndpointID)
	return Status{Snapshot: snap, Effective: effective}, nil
}

func (s *Service) Effective(ctx context.Context, c Context, filter Filter) (Effective, error) {
	if !validContext(c) {
		return Effective{}, configpoc.ErrDenied
	}
	if err := validateFilter(filter, s.options.Inventory); err != nil {
		return Effective{}, err
	}
	status, err := s.Status(ctx, c)
	if err != nil {
		return status.Effective, err
	}
	return FilterEffective(status.Effective, filter, s.options.Inventory)
}

func (s *Service) observe(ctx context.Context, revision configpoc.Revision) (Effective, error) {
	failure := Effective{Phase: "unavailable", RecoveryRequired: true, Rules: []localpolicy.EffectiveRule{}, Listeners: []localpolicy.Listener{}}
	if validateProfile(revision.Config, s.options.Inventory) != nil {
		return failure, configpoc.ErrRecovery
	}
	state, err := s.options.Authority.State(ctx)
	if err != nil {
		return failure, configpoc.ErrRecovery
	}
	hash, err := s.options.Authority.Current(ctx)
	if err != nil {
		return failure, configpoc.ErrRecovery
	}
	observed, err := s.options.Observer.Observe(ctx)
	if err != nil || hash != revision.Hash || observed.Hash != hash {
		return failure, configpoc.ErrRecovery
	}
	if revision.Config.LocalServices == nil {
		if len(observed.Local.Rules) != 0 || len(observed.Local.Listeners) != 0 {
			return failure, configpoc.ErrRecovery
		}
	} else {
		result, err := localpolicy.Reconcile(*revision.Config.LocalServices, observed.Local)
		if err != nil || !result.Consistent {
			return failure, configpoc.ErrRecovery
		}
	}
	if state.Phase != "idle" && state.Phase != "armed" && state.Phase != "pending" && state.Phase != "expired" {
		return failure, configpoc.ErrRecovery
	}
	return Effective{Hash: hash, Phase: state.Phase, Rules: copyValue(observed.Local.Rules), Listeners: copyValue(observed.Local.Listeners)}, nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.proofs.mu.Lock()
	s.proofs.closed = true
	clear(s.proofs.entries)
	s.proofs.mu.Unlock()
	return s.core.Close()
}

type activation struct {
	service  *Service
	caller   Context
	request  Request
	reserved [][32]byte
	target   configpoc.Revision
}

func (a *activation) Check(r configpoc.Request, snapshot configpoc.Snapshot, historical *configpoc.Revision) error {
	s := a.service
	if validateProfile(snapshot.Running.Config, s.options.Inventory) != nil {
		return configpoc.ErrInvalid
	}
	target := snapshot.Running
	switch r.Operation {
	case configpoc.OpStage:
		return validateProfile(*r.Config, s.options.Inventory)
	case configpoc.OpValidate, configpoc.OpCommit:
		target = snapshot.Candidate.Revision
	case configpoc.OpRollback:
		if historical == nil || historical.Hash != r.Target {
			return configpoc.ErrInvalid
		}
		target = *historical
	case configpoc.OpConfirm:
	case configpoc.OpSave:
	default:
		return configpoc.ErrInvalid
	}
	if validateProfile(target.Config, s.options.Inventory) != nil {
		return configpoc.ErrInvalid
	}
	if r.Operation == configpoc.OpValidate {
		return nil
	}
	if r.Operation != configpoc.OpCommit && r.Operation != configpoc.OpRollback && r.Operation != configpoc.OpConfirm && r.Operation != configpoc.OpSave {
		return configpoc.ErrInvalid
	}
	lease := r.Key
	if r.Operation == configpoc.OpConfirm {
		lease = snapshot.Pending.Lease
	}
	proofRequest := ProofRequest{Generation: snapshot.Generation, Target: target.Hash, Lease: lease}
	needs := []proofNeed{{token: a.request.RecoveryProof, endpoint: s.options.RecoveryEndpointID, sameSession: true}}
	if len(a.request.EndpointProofs) > 8 {
		return configpoc.ErrInvalid
	}
	if r.Operation == configpoc.OpConfirm {
		listeners := expectedListeners(target.Config)
		if len(a.request.EndpointProofs) != len(listeners) {
			return configpoc.ErrDenied
		}
		byEndpoint := make(map[string]string, len(a.request.EndpointProofs))
		for _, token := range a.request.EndpointProofs {
			id := s.proofs.endpoint(token)
			if _, exists := byEndpoint[id]; exists {
				return configpoc.ErrDenied
			}
			byEndpoint[id] = token
		}
		for _, listener := range listeners {
			id := BindingEndpointID(listener)
			needs = append(needs, proofNeed{token: byEndpoint[id], endpoint: id})
		}
	} else if len(a.request.EndpointProofs) != 0 {
		return configpoc.ErrInvalid
	}
	reserved, err := s.proofs.reserve(a.caller, proofRequest, needs)
	if err != nil {
		return err
	}
	a.reserved, a.target = reserved, target
	return nil
}

func (a *activation) Arm(ctx context.Context, id string, previous, target configpoc.Revision, ttl time.Duration) error {
	s := a.service
	if validateProfile(previous.Config, s.options.Inventory) != nil || validateProfile(target.Config, s.options.Inventory) != nil {
		return configpoc.ErrInvalid
	}
	s.proofs.finish(a.reserved, true)
	a.target = target
	s.blocked = true
	s.proofs.publish(configpoc.Snapshot{}, s.options.RecoveryEndpointID)
	if err := s.options.Authority.Arm(ctx, id, previous, target, ttl); err != nil {
		return configpoc.ErrRecovery
	}
	state, err := s.options.Authority.State(ctx)
	now := time.Now()
	if err != nil || state.Phase != "armed" || state.ID != id || state.Previous != previous.Hash || state.Target != target.Hash || !now.Before(state.Deadline) || state.Deadline.After(now.Add(ttl)) {
		return configpoc.ErrRecovery
	}
	s.blocked = false
	return nil
}

func (a *activation) Confirm(ctx context.Context, id, hash string) error {
	s := a.service
	s.proofs.finish(a.reserved, true)
	s.blocked = true
	s.proofs.publish(configpoc.Snapshot{}, s.options.RecoveryEndpointID)
	if _, err := s.observe(ctx, a.target); err != nil {
		return configpoc.ErrRecovery
	}
	_ = s.options.Authority.Confirm(ctx, id, hash)
	state, err := s.options.Authority.State(ctx)
	if err != nil || state.Phase != "idle" || state.ID != id || state.Target != hash {
		return configpoc.ErrRecovery
	}
	if _, err := s.observe(ctx, a.target); err != nil {
		return configpoc.ErrRecovery
	}
	s.blocked = false
	return nil
}
