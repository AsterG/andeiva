package configpoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

type Service struct {
	mu       sync.Mutex
	store    *fileStore
	state    durableState
	engines  []Engine
	hook     func(string) error
	timer    *time.Timer
	deadline time.Time
	halted   bool
	closed   bool
}

func Open(dir string, engines []Engine, options Options) (*Service, error) {
	if len(engines) < 1 || len(engines) > 8 {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, engine := range engines {
		if engine == nil || !identifier.MatchString(engine.Name()) || seen[engine.Name()] {
			return nil, ErrInvalid
		}
		seen[engine.Name()] = true
	}
	limit := options.MaxRecords
	if limit == 0 {
		limit = 2048
	}
	if limit < 8 || limit > 10000 {
		return nil, ErrInvalid
	}
	store, err := openStore(dir, limit)
	if err != nil {
		return nil, err
	}
	s := &Service{store: store, engines: append([]Engine{}, engines...), hook: options.Hook}
	if len(store.records) == 0 {
		initialConfig := Config{SchemaVersion: 1, DefaultAction: "deny"}
		if options.Initial != nil {
			initialConfig = *options.Initial
		}
		initial, initialErr := Canonical(initialConfig)
		if initialErr != nil {
			_ = store.lock.Close()
			return nil, initialErr
		}
		s.state = durableState{Snapshot: Snapshot{Generation: 1, Running: initial, Startup: initial, LastGood: initial, Revoked: []string{}}, Receipts: map[string]receipt{}}
		if err = s.persist("system", API, "initialize", "ok", true); err != nil {
			_ = store.lock.Close()
			return nil, err
		}
	} else {
		s.state = clone(store.records[len(store.records)-1].State)
	}
	// Unacknowledged transitions and unconfirmed commits are conservatively rolled back.
	target := s.state.Snapshot.Running
	if s.state.Snapshot.RecoveryRequired {
		target = s.state.Snapshot.LastGood
	}
	if s.state.Intent != nil {
		target = s.state.Intent.Previous
	}
	if s.state.Snapshot.Pending != nil {
		target = s.state.Snapshot.Pending.Previous
	}
	if options.Boot {
		target = s.state.Snapshot.Startup
	}
	operation := "resume"
	if s.state.Intent != nil || s.state.Snapshot.Pending != nil || s.state.Snapshot.RecoveryRequired {
		operation = "open-recovery"
	}
	if options.Boot {
		operation = "boot"
	}
	if err = s.transition(context.Background(), target, "system", API, operation, nil, true, "", ""); err != nil {
		_ = store.lock.Close()
		return nil, err
	}
	return s, nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	return s.store.lock.Close()
}
func (s *Service) persist(actor string, surface Surface, operation, result string, critical bool) error {
	// Rejections and revocations must not spend a pending transaction's reserved
	// resolution and recovery budget. No audit record is silently discarded.
	if !critical && !s.store.capacity(s.ordinaryReserve()) {
		return ErrStorage
	}
	audit := Audit{At: time.Now().UTC(), Actor: actor, Surface: surface, Operation: operation, Result: result, RunningHash: s.state.Snapshot.Running.Hash}
	if err := s.store.append(s.state, audit, critical, s.hook); err != nil {
		s.halted = true
		if s.state.Snapshot.Pending != nil {
			s.emergencyRollback(s.state.Snapshot.Pending.Previous)
		}
		if errors.Is(err, ErrInterrupted) {
			return ErrInterrupted
		}
		return ErrStorage
	}
	return nil
}
func (s *Service) authorized(principal Principal, operation string) bool {
	if !identifier.MatchString(principal.ID) || principal.ID == "system" {
		return false
	}
	for _, id := range s.state.Snapshot.Revoked {
		if principal.ID == id {
			return false
		}
	}
	switch principal.Role {
	case RoleAdmin:
		switch operation {
		case OpStatus, OpStage, OpValidate, OpCommit, OpConfirm, OpSave, OpRecover, OpRevoke, OpRollback, "history":
			return true
		}
	case RoleOperator:
		switch operation {
		case OpStatus, OpStage, OpValidate, OpCommit, OpConfirm, OpSave, OpRecover, OpRollback:
			return true
		}
	case RoleViewer:
		return operation == OpStatus
	default:
		return false
	}
	return false
}
func (s *Service) History(principal Principal) ([]Audit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.halted {
		return nil, ErrRecovery
	}
	if !s.authorized(principal, "history") {
		return nil, ErrDenied
	}
	out := make([]Audit, 0, len(s.store.records))
	for _, record := range s.store.records {
		out = append(out, record.Audit)
	}
	return out, nil
}
func (s *Service) snapshot() Snapshot {
	out := clone(s.state.Snapshot)
	out.RecoveryRequired = out.RecoveryRequired || s.halted
	return out
}
func (s *Service) reject(p Principal, surface Surface, operation string, reason error) (Snapshot, error) {
	actor := p.ID
	if !identifier.MatchString(actor) || actor == "system" {
		actor = "invalid"
	}
	if err := s.persist(actor, surface, operation, reason.Error(), false); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{}, reason
}
func (s *Service) Execute(ctx context.Context, p Principal, surface Surface, request Request) (Snapshot, error) {
	return s.execute(ctx, p, surface, request, nil)
}

// ObserveRuntime is a trusted, in-process readback barrier, not a transport
// operation. The callback receives an independent snapshot while the coordinator
// lock prevents a transaction or expiry timer from changing that revision. Due
// expiry is reconciled before the readback, as it is for authenticated status. The
// callback must only observe external state and must not reenter this service.
func (s *Service) ObserveRuntime(ctx context.Context, observe func(Snapshot) error) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.halted {
		return Snapshot{}, ErrRecovery
	}
	if observe == nil {
		return Snapshot{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if s.state.Snapshot.Pending != nil && !s.state.Snapshot.RecoveryRequired && !time.Now().Before(s.deadline) {
		if err := s.expire(); err != nil {
			return Snapshot{}, err
		}
	}
	out := s.snapshot()
	out.RecoveryRequired = out.RecoveryRequired || !s.consistent()
	return out, observe(clone(out))
}

// ExecuteManaged preserves request identity while requiring independent activation authority.
func (s *Service) ExecuteManaged(ctx context.Context, p Principal, surface Surface, request Request, guard ActivationGuard) (Snapshot, error) {
	if guard == nil {
		return Snapshot{}, ErrInvalid
	}
	return s.execute(ctx, p, surface, request, guard)
}
func (s *Service) execute(ctx context.Context, p Principal, surface Surface, request Request, guard ActivationGuard) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.halted {
		return Snapshot{}, ErrRecovery
	}
	if surface != Web && surface != CLI && surface != API {
		return Snapshot{}, ErrInvalid
	}
	switch request.Operation {
	case OpStatus, OpStage, OpValidate, OpCommit, OpConfirm, OpSave, OpRecover, OpRevoke, OpRollback:
	default:
		return s.reject(p, surface, "unknown", ErrInvalid)
	}
	if !s.authorized(p, request.Operation) {
		return s.reject(p, surface, request.Operation, ErrDenied)
	}
	if guard != nil && request.Operation == OpStatus && (request.Key != "" || request.ExpectedGeneration != 0 || request.Config != nil || request.ConfirmFor != 0 || request.Target != "") {
		return s.reject(p, surface, request.Operation, ErrInvalid)
	}
	if guard != nil && (request.Operation == OpCommit || request.Operation == OpRollback) && request.ConfirmFor != 0 && (request.ConfirmFor < 30*time.Second || request.ConfirmFor > 120*time.Second) {
		return s.reject(p, surface, request.Operation, ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if s.state.Snapshot.Pending != nil && !s.state.Snapshot.RecoveryRequired && !time.Now().Before(s.deadline) {
		if err := s.expire(); err != nil {
			return Snapshot{}, err
		}
		if request.Operation == OpConfirm {
			return Snapshot{}, ErrExpired
		}
	}
	if request.Operation == OpStatus {
		out := s.snapshot()
		out.RecoveryRequired = out.RecoveryRequired || !s.consistent()
		return out, nil
	}
	if !identifier.MatchString(request.Key) {
		return s.reject(p, surface, request.Operation, ErrInvalid)
	}
	data, _ := json.Marshal(request)
	sum := sha256.Sum256(data)
	fingerprint := hex.EncodeToString(sum[:])
	key := p.ID + ":" + request.Key
	if previous, ok := s.state.Receipts[key]; ok {
		if previous.Fingerprint != fingerprint {
			return s.reject(p, surface, request.Operation, ErrReplay)
		}
		// Replays return the current view, never an obsolete "applied" snapshot.
		out := s.snapshot()
		out.RecoveryRequired = out.RecoveryRequired || !s.consistent()
		out.ReplayedGeneration = previous.Generation
		return out, nil
	}
	if request.ExpectedGeneration != s.state.Snapshot.Generation {
		return s.reject(p, surface, request.Operation, ErrConflict)
	}
	if !s.requestCapacity(request) {
		return Snapshot{}, ErrStorage
	}
	if s.state.Snapshot.RecoveryRequired && request.Operation != OpRecover {
		return s.reject(p, surface, request.Operation, ErrRecovery)
	}
	if s.state.Snapshot.Pending != nil && request.Operation != OpConfirm && request.Operation != OpRevoke && !(request.Operation == OpRecover && s.state.Snapshot.RecoveryRequired) {
		return s.reject(p, surface, request.Operation, ErrPending)
	}
	if guard != nil {
		if err := s.managedRequest(p, request); err != nil {
			return s.reject(p, surface, request.Operation, err)
		}
		if admission, ok := guard.(AdmissionGuard); ok {
			var target *Revision
			if request.Operation == OpRollback {
				known, _ := s.historical(request.Target)
				target = &known
			}
			if err := admission.Check(clone(request), s.snapshot(), target); err != nil {
				return s.reject(p, surface, request.Operation, err)
			}
		}
	}
	if request.Operation != OpRecover && !s.consistent() {
		s.state.Snapshot.RecoveryRequired = true
		return s.reject(p, surface, request.Operation, ErrRecovery)
	}
	old := clone(s.state)
	var err error
	switch request.Operation {
	case OpStage:
		if request.Config == nil || request.ConfirmFor != 0 || request.Target != "" {
			err = ErrInvalid
			break
		}
		var revision Revision
		revision, err = Canonical(*request.Config)
		if err != nil {
			break
		}
		if s.state.Snapshot.Candidate != nil && s.state.Snapshot.Candidate.Owner != p.ID {
			err = ErrConflict
			break
		}
		s.state.Snapshot.Candidate = &Candidate{Owner: p.ID, Base: s.state.Snapshot.Running.Hash, Revision: revision}
	case OpValidate, OpCommit:
		candidate := s.state.Snapshot.Candidate
		if candidate == nil || candidate.Owner != p.ID {
			err = ErrDenied
			break
		}
		if candidate.Base != s.state.Snapshot.Running.Hash {
			err = ErrConflict
			break
		}
		if request.Config != nil || request.Target != "" {
			err = ErrInvalid
			break
		}
		if request.ConfirmFor != 0 && (request.Operation != OpCommit || request.ConfirmFor < 20*time.Millisecond || request.ConfirmFor > 5*time.Minute) {
			err = ErrInvalid
			break
		}
		if request.Operation == OpCommit && request.ConfirmFor == 0 && localServicesChanged(s.state.Snapshot.Running.Config, candidate.Revision.Config) {
			err = ErrInvalid
			break
		}
		for _, engine := range s.engines {
			if engine.Validate(clone(candidate.Revision.Config)) != nil {
				err = ErrInvalid
				break
			}
		}
		if err != nil || request.Operation == OpValidate {
			break
		}
		var pending *Pending
		if request.ConfirmFor > 0 {
			s.deadline = time.Now().Add(request.ConfirmFor)
			pending = &Pending{Owner: p.ID, Previous: s.state.Snapshot.Running, Deadline: s.deadline.UTC()}
			if guard != nil {
				pending.Lease = request.Key
			}
		}
		err = s.transitionGuarded(ctx, candidate.Revision, p.ID, surface, OpCommit, pending, false, key, fingerprint, guard, request.Key)
		if err != nil {
			return Snapshot{}, err
		}
		if pending != nil && !time.Now().Before(s.deadline) {
			if err = s.expire(); err != nil {
				return Snapshot{}, err
			}
			return Snapshot{}, ErrExpired
		}
		s.armTimer()
		return s.snapshot(), nil
	case OpConfirm:
		pending := s.state.Snapshot.Pending
		if pending == nil {
			err = ErrInvalid
			break
		}
		if pending.Owner != p.ID {
			err = ErrDenied
			break
		}
		if request.Target != s.state.Snapshot.Running.Hash || request.Config != nil || request.ConfirmFor != 0 {
			err = ErrInvalid
			break
		}
		if guard != nil {
			if pending.Lease == "" {
				return Snapshot{}, ErrRecovery
			}
			if err = guard.Confirm(ctx, pending.Lease, request.Target); err != nil {
				return s.snapshot(), err
			}
			if !time.Now().Before(s.deadline) {
				if err = s.expire(); err != nil {
					return Snapshot{}, err
				}
				return s.snapshot(), ErrExpired
			}
		}
		s.state.Snapshot.Pending = nil
		s.state.Snapshot.LastGood = s.state.Snapshot.Running
	case OpSave:
		if request.Config != nil || request.Target != "" || request.ConfirmFor != 0 {
			err = ErrInvalid
			break
		}
		s.state.Snapshot.Startup = s.state.Snapshot.Running
	case OpRollback:
		if request.Config != nil || !validHash(request.Target) {
			err = ErrInvalid
			break
		}
		target, found := s.historical(request.Target)
		if !found || !validRollbackWindow(s.state.Snapshot.Running.Config, target.Config, request.ConfirmFor) {
			err = ErrInvalid
			break
		}
		if (s.state.Snapshot.Running.Config.SchemaVersion == 3 || target.Config.SchemaVersion == 3) && s.state.Snapshot.Candidate != nil && s.state.Snapshot.Candidate.Owner != p.ID {
			err = ErrConflict
			break
		}
		var pending *Pending
		if request.ConfirmFor > 0 {
			s.deadline = time.Now().Add(request.ConfirmFor)
			pending = &Pending{Owner: p.ID, Previous: s.state.Snapshot.Running, Deadline: s.deadline.UTC()}
			if guard != nil {
				pending.Lease = request.Key
			}
		}
		err = s.transitionGuarded(ctx, target, p.ID, surface, OpRollback, pending, false, key, fingerprint, guard, request.Key)
		if err != nil {
			return Snapshot{}, err
		}
		if pending != nil && !time.Now().Before(s.deadline) {
			if err = s.expire(); err != nil {
				return Snapshot{}, err
			}
			return Snapshot{}, ErrExpired
		}
		s.armTimer()
		return s.snapshot(), nil
	case OpRecover:
		if request.Config != nil || request.Target != "" || request.ConfirmFor != 0 {
			err = ErrInvalid
			break
		}
		// Only a required recovery may spend the protected final transition.
		// Repeated healthy Recover requests remain ordinary bounded operations.
		err = s.transition(ctx, s.state.Snapshot.LastGood, p.ID, surface, OpRecover, nil, s.state.Snapshot.RecoveryRequired, key, fingerprint)
		if err != nil {
			return Snapshot{}, err
		}
		s.armTimer()
		return s.snapshot(), nil
	case OpRevoke:
		if !identifier.MatchString(request.Target) || request.Target == "system" || request.Target == p.ID || request.Config != nil || request.ConfirmFor != 0 || len(s.state.Snapshot.Revoked) >= 128 {
			err = ErrInvalid
			break
		}
		for _, id := range s.state.Snapshot.Revoked {
			if id == request.Target {
				err = ErrInvalid
			}
		}
		if err != nil {
			break
		}
		s.state.Snapshot.Revoked = append(s.state.Snapshot.Revoked, request.Target)
	}
	if err != nil {
		s.state = old
		return s.reject(p, surface, request.Operation, err)
	}
	if request.Operation != OpValidate && request.Operation != OpCommit && request.Operation != OpRecover {
		s.state.Snapshot.Generation++
	}
	s.state.Receipts[key] = receipt{Fingerprint: fingerprint, Generation: s.state.Snapshot.Generation}
	if err = s.persist(p.ID, surface, request.Operation, "ok", false); err != nil {
		if old.Snapshot.Pending != nil {
			s.emergencyRollback(old.Snapshot.Pending.Previous)
		}
		return Snapshot{}, err
	}
	s.armTimer()
	return s.snapshot(), nil
}

// Rollback across the local-service schema boundary is an administrative
// transition, including removal of all managed services by selecting a legacy
// revision. Legacy-only rollback retains its immediate, zero-window semantics.
func validRollbackWindow(previous, target Config, ttl time.Duration) bool {
	if previous.SchemaVersion == 3 || target.SchemaVersion == 3 {
		return ttl >= 20*time.Millisecond && ttl <= 5*time.Minute
	}
	return ttl == 0
}

func (s *Service) consistent() bool {
	for _, engine := range s.engines {
		if engine.Current() != s.state.Snapshot.Running.Hash {
			return false
		}
	}
	return true
}
func (s *Service) hookAt(point string) error {
	if s.hook == nil {
		return nil
	}
	if err := s.hook(point); err != nil {
		s.halted = true
		if s.timer != nil {
			s.timer.Stop()
		}
		return ErrInterrupted
	}
	return nil
}
func (s *Service) transition(ctx context.Context, target Revision, actor string, surface Surface, operation string, pending *Pending, critical bool, key, fingerprint string) error {
	return s.transitionGuarded(ctx, target, actor, surface, operation, pending, critical, key, fingerprint, nil, "")
}
func (s *Service) transitionGuarded(ctx context.Context, target Revision, actor string, surface Surface, operation string, pending *Pending, critical bool, key, fingerprint string, guard ActivationGuard, lease string) error {
	before := clone(s.state)
	previous := clone(s.state.Snapshot.Running)
	if s.state.Snapshot.RecoveryRequired {
		previous = clone(s.state.Snapshot.LastGood)
	}
	if s.state.Intent != nil {
		previous = clone(s.state.Intent.Previous)
	}
	if s.state.Snapshot.Pending != nil {
		previous = clone(s.state.Snapshot.Pending.Previous)
	}
	// Boot applies Startup as a forward transition. Its failure anchor must remain
	// the confirmed revision, even when the preceding controller was interrupted.
	rollback := operation == "timeout" || operation == "open-recovery" || operation == OpRecover
	if rollback {
		previous = clone(target)
	}
	// Never begin a critical intent that cannot also record its outcome. Older
	// exhausted stores remain blocked; their records and receipts are preserved.
	if critical && !s.store.capacity(recoveryRecords-1) {
		if rollback || operation == "boot" {
			s.emergencyRollback(previous)
		}
		return ErrStorage
	}
	if operation != "timeout" && operation != "open-recovery" {
		for _, engine := range s.engines {
			if engine.Validate(clone(target.Config)) != nil {
				if operation == "boot" && (before.Intent != nil || before.Snapshot.Pending != nil || before.Snapshot.RecoveryRequired) {
					s.emergencyRollback(previous)
				}
				return ErrInvalid
			}
		}
	}
	s.state.Intent = &Intent{Previous: previous, Target: clone(target)}
	if err := s.persist(actor, surface, operation, "intent", critical); err != nil {
		if rollback || operation == "boot" {
			s.emergencyRollback(previous)
		}
		return err
	}
	if err := s.hookAt("after_intent"); err != nil {
		return err
	}
	if guard != nil {
		ttl := 120 * time.Second
		if pending != nil {
			ttl = time.Until(s.deadline)
			// Preserve the remaining lifetime after durable intent. Extending it
			// would also extend effective access if this process then stopped.
		}
		if err := guard.Arm(ctx, lease, previous, target, ttl); err != nil {
			return s.compensate(previous, actor, surface, operation)
		}
	}
	for _, engine := range s.engines {
		if err := engine.Apply(ctx, clone(target)); err != nil || engine.Current() != target.Hash {
			return s.compensate(previous, actor, surface, operation)
		}
		if err := s.hookAt("after_apply:" + engine.Name()); err != nil {
			return err
		}
	}
	if guard != nil && pending == nil {
		if err := guard.Confirm(ctx, lease, target.Hash); err != nil {
			return s.compensate(previous, actor, surface, operation)
		}
	}
	if err := s.hookAt("before_receipt"); err != nil {
		return err
	}
	s.state.Snapshot.Running = clone(target)
	if operation != "resume" {
		s.state.Snapshot.Candidate = nil
	}
	s.state.Snapshot.Pending = clone(pending)
	if pending == nil {
		s.state.Snapshot.LastGood = clone(target)
	}
	s.state.Snapshot.RecoveryRequired = false
	s.state.Snapshot.Generation++
	s.state.Intent = nil
	if key != "" {
		s.state.Receipts[key] = receipt{Fingerprint: fingerprint, Generation: s.state.Snapshot.Generation}
	}
	if err := s.persist(actor, surface, operation, "applied", critical); err != nil {
		s.state = before
		s.emergencyRollback(previous)
		return err
	}
	return nil
}

// A storage failure cannot prevent an already-authorized safety rollback. Its outcome
// remains indeterminate until recovery; this best effort never reports a committed state.
func (s *Service) emergencyRollback(previous Revision) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, engine := range s.engines {
		_ = engine.Apply(ctx, clone(previous))
	}
	s.state.Snapshot.RecoveryRequired = true
	s.halted = true
	if s.timer != nil {
		s.timer.Stop()
	}
}
func (s *Service) compensate(previous Revision, actor string, surface Surface, operation string) error {
	failed := false
	// The engine returning an error may already have changed state. Reconcile all engines.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, engine := range s.engines {
		if engine.Apply(ctx, clone(previous)) != nil || engine.Current() != previous.Hash {
			failed = true
		}
	}
	s.state.Snapshot.Running = clone(previous)
	s.state.Snapshot.Candidate = nil
	s.state.Snapshot.RecoveryRequired = failed
	if !failed {
		s.state.Intent = nil
		s.state.Snapshot.Pending = nil
		s.state.Snapshot.LastGood = clone(previous)
	}
	s.state.Snapshot.Generation++
	result := "compensated"
	if failed {
		result = "compensation_failed"
	}
	if err := s.persist(actor, surface, operation, result, true); err != nil {
		return err
	}
	if failed {
		return ErrRecovery
	}
	return ErrEngine
}
func (s *Service) expire() error {
	if s.state.Snapshot.Pending == nil {
		return nil
	}
	previous := clone(s.state.Snapshot.Pending.Previous)
	return s.transition(context.Background(), previous, "system", API, "timeout", nil, true, "", "")
}
func (s *Service) armTimer() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if s.state.Snapshot.Pending == nil {
		return
	}
	delay := time.Until(s.deadline)
	s.timer = time.AfterFunc(delay, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed || s.halted || s.state.Snapshot.Pending == nil {
			return
		}
		_ = s.expire()
	})
}
