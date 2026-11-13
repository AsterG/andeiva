package configpoc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

type v2CoordinatorOptions struct {
	Integrity      RuntimeIntegrityV1
	SharedReader   *recoveryreserve.ReaderAccessV2
	Routed         RoutedAuthorityV1
	RoutedIdentity networkexecutor.OwnedNamespaceIdentity
	GuardDeadlines bool
	Reserves       *v2ReserveManager
	LocalPolicy    LocalPolicyV2
	BootID         *v2BootID
	Now            func() time.Time
	Hook           func(string) error
	// Tests may drive deadlines explicitly; appliance integration must not opt
	// out of the independent timeout worker. There is no runtime caller yet.
	ManualTimeout bool
}
type v2Coordinator struct {
	integrity    runtimeIntegrityStateV1
	bootBoundary *v2RoutedBootBoundary
	store        *v2Store
	firewall     []Engine
	local        []Engine
	options      v2CoordinatorOptions
	timer        *time.Timer
	timerLease   string
	timerOrigin  string
	closed       bool
}

func openCoordinatorV2(ctx context.Context, store *v2Store, firewall, local []Engine, options v2CoordinatorOptions) (*v2Coordinator, error) {
	if options.BootID != nil {
		boot := *options.BootID
		if !validBootIDV2(boot) {
			return nil, ErrInvalid
		}
		options.BootID = &boot
	}
	if store == nil || len(firewall) == 0 || len(local) == 0 || len(firewall) > 8 || len(local) > 8 {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, engine := range append(append([]Engine{}, firewall...), local...) {
		if engine == nil || !identifier.MatchString(engine.Name()) || seen[engine.Name()] {
			return nil, ErrInvalid
		}
		seen[engine.Name()] = true
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	c := &v2Coordinator{store: store, firewall: append([]Engine{}, firewall...), local: append([]Engine{}, local...), options: options}
	store.mu.Lock()
	defer store.mu.Unlock()
	if hasFeatureV2(store.state, v2RoutedOfflineSeedFeature) && (options.Routed == nil || options.BootID == nil || options.Reserves == nil || !options.GuardDeadlines) {
		return nil, ErrRecovery
	}
	if store.blocked {
		if store.state.RecoveryReserveVersion != 1 || options.Reserves == nil {
			return nil, errV2Unavailable
		}
		if err := recoverReservePendingV2(store, options.Reserves); err != nil {
			return nil, err
		}
	}
	if store.state.RecoveryReserveVersion == 1 {
		if options.Reserves == nil || options.Reserves.verifySelected(store) != nil {
			return nil, ErrRecovery
		}
		store.reserves = options.Reserves
	} else if options.Reserves != nil {
		return nil, ErrInvalid
	}
	if store.state.Configuration == nil {
		if err := c.initializeLocked(); err != nil {
			return nil, err
		}
	}
	if !validV2Configuration(store.state.Configuration) {
		return nil, errV2Unavailable
	}
	if err := c.guardDeadlineOpenV2(); err != nil {
		return nil, err
	}
	if err := c.validateReferencesLocked(); err != nil {
		return nil, fmt.Errorf("selected references: %w", err)
	}
	if handled, err := c.openRoutedBootBoundaryV2(ctx); handled {
		return c, err
	}
	if store.state.Configuration.Intent != nil {
		if err := c.reconcileLocked(ctx, "restart"); err != nil {
			return c, err
		}
	}
	if store.state.Configuration.Pending != nil {
		if err := c.revertLocked(ctx, "restart"); err != nil {
			return c, err
		}
	}
	if store.state.RoutedBootBoundary != nil && store.state.Configuration.Intent == nil && store.state.Configuration.Pending == nil {
		if err := c.finishRoutedBootBoundaryV2(); err != nil {
			return c, err
		}
	}
	if store.reserves != nil {
		if err := store.reserves.maintain(store); err != nil {
			return c, err
		}
	}
	if options.BootID != nil {
		if err := c.bootStartupLocked(ctx, *options.BootID); err != nil {
			return c, fmt.Errorf("startup reconciliation: %w", err)
		}
	}
	if err := c.resumeRoutedLockedV2(ctx); err != nil {
		return c, err
	}
	if !c.readback(*store.state.Configuration) {
		return c, ErrRecovery
	}
	c.armLocked()
	if err := c.publishLocalLocked(); err != nil {
		return c, err
	}
	return c, nil
}

func (c *v2Coordinator) now() time.Time { return c.options.Now().UTC() }
func (c *v2Coordinator) recoveryNow() time.Time {
	now := c.now()
	if now.Before(c.store.state.Clock) {
		return c.store.state.Clock
	}
	return now
}
func (c *v2Coordinator) point(name string) error {
	if c.options.Hook != nil {
		return c.options.Hook(name)
	}
	return nil
}

func (c *v2Coordinator) close() {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	c.closed = true
	c.invalidateLocalLocked()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.timerLease = ""
	c.timerOrigin = ""
}

func (c *v2Coordinator) armLocked() {
	state := c.store.state.Configuration
	if state != nil && state.Pending != nil && !c.closed && !c.options.ManualTimeout && c.timer != nil && c.timerLease == state.Pending.Lease && c.timerOrigin == state.Pending.OriginCommit {
		return
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if c.closed || c.options.ManualTimeout || c.store.state.Configuration == nil || c.store.state.Configuration.Pending == nil {
		c.timerLease = ""
		c.timerOrigin = ""
		return
	}
	pending := state.Pending
	lease, origin := pending.Lease, pending.OriginCommit
	c.timerLease = lease
	c.timerOrigin = origin
	delay := pending.Deadline.Sub(c.now())
	if delay < 0 {
		delay = 0
	}
	c.timer = time.AfterFunc(delay, func() {
		c.store.mu.Lock()
		defer c.store.mu.Unlock()
		if c.closed {
			return
		}
		current := c.store.state.Configuration.Pending
		if current == nil || current.Lease != lease || current.OriginCommit != origin {
			return
		}
		c.timer = nil
		c.timerLease = ""
		c.timerOrigin = ""
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// An elapsed monotonic timer cannot be extended by wall-clock rollback.
		if !c.store.blocked && c.store.state.Configuration.Intent == nil {
			_ = c.revertLocked(ctx, "timeout")
		}
	})
}

func (c *v2Coordinator) initializeLocked() error {
	s := c.store
	if err := c.pendingReferencesLocked(nil); err != nil {
		return err
	}
	if s.state.Migration == "" {
		return errV2Invalid
	}
	var imported v2Migration
	if s.readObject(s.state.Migration, &imported) != nil || s.validateMigration() != nil {
		return errV2Unavailable
	}
	from := func(image v2LegacyImage) v2DomainSnapshot {
		return v2DomainSnapshot{Generation: image.Projection, Running: clone(image.Snapshot.Running), Startup: clone(image.Snapshot.Startup), LastGood: clone(image.Snapshot.LastGood)}
	}
	state := v2Configuration{Firewall: from(imported.Firewall), LocalServices: from(imported.LocalServices)}
	if state.refresh() != nil || !validV2Configuration(&state) || !c.readback(state) {
		return ErrRecovery
	}
	if err := c.persistRevisions(state); err != nil {
		return err
	}
	issued, err := v2ID("initialize", s.selection.Sequence+1)
	if err != nil {
		return err
	}
	audit, err := c.appendAuditLocked(&state, issued, "", "", "system", "initialize", "verified", s.state.Generation, c.recoveryNow())
	if err != nil {
		return err
	}
	state.VerifiedIndex, err = c.verifiedInsert("", 0, v2VerifiedEntry{Revision: state.Running.Hash, Audit: audit, Operation: issued})
	if err != nil {
		return err
	}
	st := clone(s.state)
	st.Configuration = &state
	return s.publish(st)
}

func (c *v2Coordinator) persistRevisions(state v2Configuration) error {
	for _, domain := range []v2DomainSnapshot{state.Firewall, state.LocalServices} {
		revisions := []Revision{domain.Running, domain.Startup, domain.LastGood}
		if domain.Candidate != nil {
			revisions = append(revisions, domain.Candidate.Revision)
		}
		for _, revision := range revisions {
			hash, err := c.store.object(revision.Config)
			if err != nil || hash != revision.Hash {
				return errV2Unavailable
			}
		}
	}
	for _, revision := range []v2CompositeRevision{state.Running, state.Startup, state.LastGood} {
		hash, err := c.store.object(revision.Config)
		if err != nil || hash != revision.Hash {
			return errV2Unavailable
		}
	}
	if state.Candidate != nil {
		hash, err := c.store.object(state.Candidate.Config)
		if err != nil || hash != state.Candidate.Hash {
			return errV2Unavailable
		}
	}
	return nil
}

func (c *v2Coordinator) readback(state v2Configuration) bool {
	if state.Firewall.Running.Config.SchemaVersion == 6 || c.store.state.RoutedActive != nil || c.store.state.Configuration != nil && c.store.state.Configuration.Intent != nil && c.store.state.Configuration.Intent.RoutedWork != "" {
		if c.options.Routed == nil {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if in := c.store.state.Configuration.Intent; in != nil && in.Domain == "routed" && in.Recovery && in.Kind != v2BootKind && in.RoutedWork != "" {
			plan, err := c.selectedRoutedPlanV2()
			return err == nil && plan.previous.Composite.Hash == state.Running.Hash && c.options.Routed.Match(ctx, plan, "before") == nil
		}
		_, hash, err := c.options.Routed.Observe(ctx)
		if err != nil {
			return false
		}
		if hash == state.Running.Hash {
			return true
		}
		if hash != "" || state.Firewall.Running.Config.SchemaVersion != 4 {
			return false
		}
		var plan RoutedSelectedPlanV1
		if in := c.store.state.Configuration.Intent; in != nil && in.RoutedWork != "" {
			plan, err = c.selectedRoutedPlanV2()
		} else if active := c.store.state.RoutedActive; active != nil && active.Side == "before" {
			plan, err = loadRoutedWorkV2(active.Work, c.store.state.Lineage, c.store.readObject)
			if plan.Scope().Identity != c.options.RoutedIdentity {
				return false
			}
		} else {
			return false
		}
		return err == nil && plan.Cold() && plan.previous.Composite.Hash == state.Running.Hash && c.options.Routed.Match(ctx, plan, "before") == nil
	}
	for _, engine := range c.firewall {
		if engine.Current() != state.Firewall.Running.Hash {
			return false
		}
	}
	for _, engine := range c.local {
		if engine.Current() != state.LocalServices.Running.Hash {
			return false
		}
	}
	return true
}
func (c *v2Coordinator) localReadback(state v2Configuration) bool {
	for _, engine := range c.local {
		if engine.Current() != state.LocalServices.Running.Hash {
			return false
		}
	}
	return true
}

func (c *v2Coordinator) status(principal v2TrustedPrincipal) (v2Configuration, uint64, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked {
		return v2Configuration{}, 0, errV2Unavailable
	}
	if !c.store.principalV2Locked(principal) || (principal.Role != RoleAdmin && principal.Role != RoleViewer) {
		return v2Configuration{}, 0, ErrDenied
	}
	return clone(*c.store.state.Configuration), c.store.state.Generation, nil
}

func (c *v2Coordinator) execute(ctx context.Context, principal v2TrustedPrincipal, id string) (v2CoordinatorResult, error) {
	s := c.store
	s.mu.Lock()
	defer s.mu.Unlock()
	return c.executeLocked(ctx, principal, id)
}

func (c *v2Coordinator) executeLocked(ctx context.Context, principal v2TrustedPrincipal, id string) (v2CoordinatorResult, error) {
	return c.executeLocalLocked(ctx, principal, id, nil)
}
func (c *v2Coordinator) executeLocalLocked(ctx context.Context, principal v2TrustedPrincipal, id string, handle LocalHandleV2) (v2CoordinatorResult, error) {
	s := c.store
	result := func(op v2Operation) v2CoordinatorResult {
		return v2CoordinatorResult{Operation: clone(op), Current: clone(*s.state.Configuration), GlobalGeneration: s.state.Generation}
	}
	if c.closed || s.blocked {
		return v2CoordinatorResult{}, errV2Unavailable
	}
	if principal.Role != RoleAdmin || !s.principalV2Locked(principal) {
		return v2CoordinatorResult{}, ErrDenied
	}
	if c.options.Integrity != nil {
		op, err := s.lookupLocked(principal.Subject, id)
		if err != nil {
			return v2CoordinatorResult{}, err
		}
		if op.State != "accepted" {
			return result(op), nil
		}
		if !c.integrityAllowsV1(op.ClosingCredit != "") {
			return result(op), ErrRecovery
		}
	}
	if s.reserves != nil {
		if err := s.reserves.maintain(s); err != nil {
			return v2CoordinatorResult{}, err
		}
	}
	op, err := s.lookupLocked(principal.Subject, id)
	if err != nil {
		return v2CoordinatorResult{}, err
	}
	if op.State != "accepted" {
		return result(op), nil
	}
	if s.reserves != nil && op.ClosingCredit == "" {
		if err = s.reserveMaintenanceReadyV2(""); err != nil {
			return result(op), err
		}
	}
	if s.reserves != nil && s.reserves.verifyBundle(s, op.Reserve) != nil {
		return result(op), ErrRecovery
	}
	if ctx.Err() != nil {
		return result(op), ErrInterrupted
	}
	consume := false
	reservationFinished := false
	var localReservation LocalReservationV2
	if op.Domain == "local_services" {
		if handle == nil || c.options.LocalPolicy == nil {
			return result(op), ErrDenied
		}
		scope, e := c.localScopeLocked(op, principal)
		if e != nil {
			return result(op), e
		}
		reservation, e := c.options.LocalPolicy.Reserve(handle, scope)
		if e != nil {
			return result(op), e
		}
		if reservation == nil {
			return result(op), ErrDenied
		}
		localReservation = reservation
		defer func() {
			if !reservationFinished {
				reservation.Finish(consume)
			}
		}()
	} else {
		if err = c.tickLocked(ctx, c.now()); err != nil {
			return result(op), err
		}
	}
	now := c.now()
	state := clone(*s.state.Configuration)
	if state.Intent != nil || state.RecoveryRequired && op.Request.Kind != OpRecover {
		return result(op), ErrRecovery
	}
	ns := s.state.Namespaces[s.namespaceIndex(op.Subject, op.Namespace)]
	if ns.Closed {
		return result(op), errV2Closed
	}
	if !now.Before(op.ExecuteBefore) {
		return result(op), errV2Expired
	}
	if now.Before(s.state.Clock) {
		return result(op), errV2Unavailable
	}
	if op.Expected != s.state.Generation {
		return result(op), ErrConflict
	}
	if s.reserves != nil {
		if err = s.reserves.operationProfile(s, op, op.Reserve.Scope.Bundle); err != nil {
			st := clone(s.state)
			if e := s.withoutEffects(&st, op, "ANDEIVA_RESERVE_PROFILE_CHANGED", now); e != nil {
				return result(op), e
			}
			st.Clock = now
			if e := s.publish(st); e != nil {
				return result(op), e
			}
			if e := s.reserves.maintain(s); e != nil {
				return result(op), e
			}
			final, e := s.lookupRetained(op.Subject, op.ID)
			if e != nil {
				return result(op), e
			}
			return result(final), err
		}
	}
	if state.Pending != nil && op.Request.Kind != OpConfirm {
		return result(op), ErrPending
	}
	if op.Request.Kind == OpRecover {
		if !c.localReadback(state) {
			return result(op), ErrRecovery
		}
	} else if !c.readback(state) {
		return result(op), ErrRecovery
	}
	if op.Domain == "local_services" {
		if ctx.Err() != nil {
			return result(op), ErrInterrupted
		}
		deadline := time.Now().Add(10 * time.Second)
		if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
			deadline = requested
		}
		bounded, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
		defer cancel()
		ctx = bounded
	}
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = v2Budget{} }()
	closingRestore, err := s.closingOperationAllowanceLocked(op)
	if err != nil {
		return result(op), err
	}
	defer closingRestore()
	target, changed, err := c.targetLocked(op, state, now)
	if err != nil {
		return result(op), err
	}
	if op.Domain == "routed" && op.Request.Kind == OpValidate && c.options.Routed != nil {
		candidate, e := NewRoutedActivationBundleV1(target.Firewall.Candidate.Revision, target.LocalServices.Candidate.Revision)
		if e != nil {
			return result(op), e
		}
		var baseline *RoutedBaselineV1
		if c.store.state.RoutedActive != nil {
			_, baseline, e = c.routedBaselineV2()
			if e != nil {
				return result(op), e
			}
		}
		if _, e = c.options.Routed.Prepare(ctx, candidate, baseline); e != nil {
			return result(op), e
		}
	}
	if err = c.absoluteGuardPreflightV2(op, state, target); err != nil {
		return result(op), err
	}
	if err = c.persistRevisions(target); err != nil {
		s.blocked = true
		return result(op), err
	}
	previousHash, err := s.object(state)
	if err != nil {
		s.blocked = true
		return result(op), err
	}
	targetHash, err := s.object(target)
	if err != nil {
		s.blocked = true
		return result(op), err
	}
	generation := s.state.Generation
	if changed {
		if generation == ^uint64(0) {
			return result(op), errV2Limited
		}
		generation++
	}
	op.State = "pending"
	op.Pinned = true
	st := clone(s.state)
	if op.Domain == "local_services" || op.Domain == "routed" {
		addFeatureV2(&st, v2LocalFeature)
	}
	st.Clock = now
	st.Configuration.Intent = &v2CoordinatorIntent{Operation: op.ID, Subject: op.Subject, Domain: op.Domain, Kind: op.Request.Kind, Previous: previousHash, Target: targetHash, TargetGeneration: generation}
	if op.Request.Kind == OpReplaceCandidate || op.Request.Kind == OpDiscardCandidate {
		addFeatureV2(&st, v2OwnedCandidateFeature)
	}
	if err = c.publishRoutedWorkV2(ctx, op, state, target, st.Configuration.Intent); err != nil {
		return result(op), err
	}
	if c.options.GuardDeadlines && immediateGuardIntentV2(st.Configuration.Intent, state, target) {
		deadline := c.now().Add(10 * time.Second).UTC()
		st.Configuration.Intent.GuardDeadline = &deadline
		addFeatureV2(&st, v2GuardDeadlineFeature)
	}
	if s.reserves != nil {
		if err = s.reserves.selectedPlan(s, &op, &st, *st.Configuration.Intent, target); err != nil {
			return result(op), err
		}
	}
	if err = s.putOperation(&st, op); err != nil {
		s.blocked = true
		return result(op), err
	}
	consume = true
	if err = s.publish(st); err != nil {
		if s.reserves != nil {
			if e := s.reserves.emergencyCandidate(s, op.Reserve, "storage_uncertain"); e != nil {
				return result(op), ErrRecovery
			}
		}
		return result(op), err
	}
	if localReservation != nil {
		localReservation.Finish(true)
		reservationFinished = true
	}
	c.invalidateLocalLocked()
	if err = c.point("after_intent"); err != nil {
		return result(op), err
	}
	if err = c.prepareGuardsLocked(ctx, op, state, target); err != nil {
		return c.compensateLocked(ctx, op, state, err)
	}
	if err = c.applyGuardedLocked(ctx, state, target, op.Request.Kind == OpCommit || (op.Request.Kind == OpRollback && target.Pending != nil), op.Request.Kind == OpRecover, op.Domain); err != nil {
		if metadataOperationV2(op.Request.Kind) {
			return c.uncertainLocked(op, ErrRecovery)
		}
		if errors.Is(err, ErrInterrupted) {
			return result(op), err
		}
		return c.compensateLocked(ctx, op, state, err)
	}
	if !c.readback(target) {
		if metadataOperationV2(op.Request.Kind) {
			return c.uncertainLocked(op, ErrRecovery)
		}
		return c.compensateLocked(ctx, op, state, ErrEngine)
	}
	if err = c.point("after_readback"); err != nil {
		return result(op), err
	}
	if target.Pending != nil && !c.now().Before(target.Pending.Deadline) {
		return c.compensateLocked(ctx, op, state, ErrExpired)
	}
	if c.now().Before(s.state.Clock) {
		return c.compensateLocked(ctx, op, state, ErrInterrupted)
	}
	if err = c.confirmGuardsLocked(ctx, op, state, target); err != nil {
		if op.Request.Kind == OpConfirm {
			return c.compensateLocked(ctx, op, state, err)
		}
		return c.uncertainLocked(op, ErrRecovery)
	}
	code := "applied"
	pin := false
	if target.Pending != nil && target.Pending.OriginCommit == op.ID {
		code = "applied_pending_confirmation"
		pin = true
	}
	final, err := c.completeLocked(op, target, generation, code, "", pin, c.now())
	if err != nil {
		if s.reserves != nil {
			if e := s.reserves.emergencyCandidate(s, op.Reserve, "storage_uncertain"); e != nil {
				return result(op), ErrRecovery
			}
		}
		_ = c.reconcileStorageFailureLocked(ctx, state, op)
		return result(op), err
	}
	c.armLocked()
	return result(final), nil
}

func (c *v2Coordinator) targetLocked(op v2Operation, state v2Configuration, now time.Time) (v2Configuration, bool, error) {
	if op.Domain == "routed" {
		// Joint effects require the separately assembled group authority. Never
		// fall through to the independent legacy component guard loops.
		if c.options.Routed == nil && (op.Request.Kind == OpCommit || op.Request.Kind == OpRollback || op.Request.Kind == OpConfirm) {
			return state, false, ErrRecovery
		}
		lease := ""
		if op.Request.Kind == OpCommit || op.Request.Kind == OpRollback {
			var err error
			lease, err = v2ID("lease", op.Sequence)
			if err != nil {
				return state, false, err
			}
		}
		return routedTargetV2(c.store, op, state, now, lease)
	}
	if state.CandidateGroup != nil || state.Firewall.Running.Config.SchemaVersion == 6 || c.options.Routed != nil && hasFeatureV2(c.store.state, v2RoutedFeature) {
		return state, false, ErrConflict
	}
	target := clone(state)
	target.Intent = nil
	domain := domainSnapshotV2(&target, op.Domain)
	changed := true
	switch op.Request.Kind {
	case OpStage:
		if domain.Candidate != nil && domain.Candidate.Owner != op.Subject {
			return target, false, ErrConflict
		}
		canonical, err := Canonical(*op.Request.Config)
		if err != nil {
			return target, false, err
		}
		for _, engine := range c.enginesV2(op.Domain) {
			if engine.Validate(canonical.Config) != nil {
				return target, false, ErrInvalid
			}
		}
		domain.Candidate = &v2DomainCandidate{Owner: op.Subject, Base: domain.Running.Hash, Revision: canonical}
	case OpValidate:
		if domain.Candidate == nil || domain.Candidate.Owner != op.Subject {
			return target, false, ErrConflict
		}
		for _, engine := range c.enginesV2(op.Domain) {
			if engine.Validate(domain.Candidate.Revision.Config) != nil {
				return target, false, ErrInvalid
			}
		}
		changed = false
	case OpCommit:
		if domain.Candidate == nil || domain.Candidate.Owner != op.Subject || domain.Candidate.Base != domain.Running.Hash {
			return target, false, ErrConflict
		}
		for _, engine := range c.enginesV2(op.Domain) {
			if engine.Validate(domain.Candidate.Revision.Config) != nil {
				return target, false, ErrInvalid
			}
		}
		domain.Running = domain.Candidate.Revision
		domain.Candidate = nil
		if op.Request.ConfirmSeconds == nil {
			return target, false, ErrInvalid
		}
		seconds := *op.Request.ConfirmSeconds
		if seconds > 120 || (seconds != 0 && seconds < 30) || (op.Domain == "local_services" && seconds == 0) {
			return target, false, ErrInvalid
		}
		if seconds > 0 {
			previous, err := c.store.object(state)
			if err != nil {
				return target, false, err
			}
			lease, err := v2ID("lease", op.Sequence)
			if err != nil {
				return target, false, err
			}
			target.Pending = &v2Confirmation{OriginCommit: op.ID, Lease: lease, Owner: op.Subject, Domain: op.Domain, Previous: previous, Deadline: now.Add(time.Duration(seconds) * time.Second)}
		} else {
			domain.LastGood = domain.Running
		}
	case OpConfirm:
		pending := state.Pending
		if pending == nil || pending.Domain != op.Domain || pending.Owner != op.Subject || pending.OriginCommit != op.Request.Origin || pending.Target != op.Request.Target || !now.Before(pending.Deadline) {
			return target, false, ErrConflict
		}
		origin, err := c.store.lookupRetained(op.Subject, pending.OriginCommit)
		if err != nil || origin.State != "final" || !origin.Pinned || origin.Outcome == nil || origin.Outcome.Code != "applied_pending_confirmation" || origin.Outcome.ConfirmationLease != pending.Lease || origin.Outcome.RunningRevision != pending.Target || origin.Outcome.ConfirmationDeadline == nil || !origin.Outcome.ConfirmationDeadline.Equal(pending.Deadline) {
			return target, false, ErrConflict
		}
		domain.LastGood = domain.Running
		target.Pending = nil
	case OpSave:
		changed = domain.Startup.Hash != domain.Running.Hash
		domain.Startup = domain.Running
	case OpRollback:
		revision, err := c.loadDomainRevision(op.Request.Target, op.Domain)
		if err != nil {
			return target, false, err
		}
		for _, engine := range c.enginesV2(op.Domain) {
			if engine.Validate(revision.Config) != nil {
				return target, false, ErrInvalid
			}
		}
		domain.Running = revision
		domain.Candidate = nil
		if op.Domain == "local_services" {
			previous, err := c.store.object(state)
			if err != nil {
				return target, false, err
			}
			lease, err := v2ID("lease", op.Sequence)
			if err != nil {
				return target, false, err
			}
			target.Pending = &v2Confirmation{OriginCommit: op.ID, Lease: lease, Owner: op.Subject, Domain: op.Domain, Previous: previous, Deadline: now.Add(30 * time.Second)}
		} else {
			domain.LastGood = revision
		}
	case OpRecover:
		if op.Domain != "firewall" {
			return target, false, ErrDenied
		}
		domain.Running = domain.LastGood
		domain.Candidate = nil
		target.RecoveryRequired = false
		target.Pending = nil
	default:
		return target, false, ErrInvalid
	}
	if changed {
		if domain.Generation == ^uint64(0) {
			return target, false, errV2Limited
		}
		domain.Generation++
	}
	if err := target.refresh(); err != nil {
		return target, false, err
	}
	if target.Pending != nil {
		target.Pending.Target = target.Running.Hash
	}
	return target, changed, nil
}

func (c *v2Coordinator) loadFirewallRevision(hash string) (Revision, error) {
	return c.loadDomainRevision(hash, "firewall")
}
func (c *v2Coordinator) loadDomainRevision(hash, domain string) (Revision, error) {
	if !validHash(hash) {
		return Revision{}, ErrInvalid
	}
	proof, known, err := c.verifiedLookup(c.store.state.Configuration.VerifiedIndex, hash)
	if err != nil {
		return Revision{}, err
	}
	if !known {
		return Revision{}, ErrInvalid
	}
	if err = c.verifyWitness(proof); err != nil {
		return Revision{}, err
	}
	name, _ := v2ObjectName(hash)
	if _, err := c.store.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return Revision{}, ErrInvalid
	}
	var composite v2CompositeConfig
	data, readErr := c.store.readRecordV2(name, v2ObjectLimit)
	if readErr != nil || checkpointDigest(data) != hash {
		c.store.blocked = true
		return Revision{}, errV2Unavailable
	}
	if checkpointDecode(data, &composite) != nil {
		return Revision{}, ErrInvalid
	}
	canonical, err := CanonicalComposite(composite)
	if err != nil || canonical.Hash != hash {
		return Revision{}, ErrInvalid
	}
	current := c.store.state.Configuration
	if (domain == "firewall" && composite.Domains.LocalServices.Revision != current.LocalServices.Running.Hash) || (domain == "local_services" && composite.Domains.Firewall.Revision != current.Firewall.Running.Hash) {
		return Revision{}, ErrDenied
	}
	reference, schema := composite.Domains.Firewall.Revision, 4
	if domain == "local_services" {
		reference, schema = composite.Domains.LocalServices.Revision, 3
	}
	var config Config
	if c.store.readObject(reference, &config) != nil {
		return Revision{}, errV2Unavailable
	}
	revision, err := Canonical(config)
	if err != nil || config.SchemaVersion != schema || revision.Hash != reference {
		return Revision{}, ErrInvalid
	}
	return revision, nil
}

func (c *v2Coordinator) applyLocked(ctx context.Context, previous, target v2Configuration) error {
	return c.applyGuardedLocked(ctx, previous, target, false, false)
}
func (c *v2Coordinator) applyGuardedLocked(ctx context.Context, previous, target v2Configuration, forceGuard, recoverDrift bool, domains ...string) error {
	domain := effectDomainV2(previous, target)
	if len(domains) == 1 {
		domain = domains[0]
	}
	if domain == "routed" && (forceGuard || recoverDrift || previous.Running.Hash != target.Running.Hash) {
		plan, err := c.selectedRoutedPlanV2()
		if err != nil {
			return err
		}
		return c.options.Routed.Apply(ctx, plan)
	}
	if target.LocalServices.Running.Hash != previous.LocalServices.Running.Hash && target.Firewall.Running.Hash != previous.Firewall.Running.Hash {
		return ErrDenied
	}
	applied := domainSnapshotV2(&target, domain).Running
	prior := domainSnapshotV2(&previous, domain).Running
	if applied.Hash == prior.Hash && !recoverDrift {
		if !c.readback(target) {
			return ErrRecovery
		}
		if forceGuard {
			for _, engine := range c.enginesV2(domain) {
				if _, ok := engine.(ActivationGuard); ok {
					if err := engine.Apply(ctx, applied); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	for _, engine := range c.enginesV2(domain) {
		if err := engine.Apply(ctx, applied); err != nil {
			return err
		}
		if err := c.point("after_component_apply"); err != nil {
			return err
		}
	}
	return nil
}
