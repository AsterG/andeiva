package configpoc

import (
	"context"
	"time"
)

// A real prepared engine must pair its existing activation guard with narrowly
// scoped recovery. Plain Engine fixtures retain the original simulation path.
// Runtime assembly must not substitute an unguarded real engine for this wrapper.
type recoveringGuardV2 interface {
	ActivationGuard
	RecoverPrevious(context.Context, string, Revision, Revision) error
}

// Absolute guards must receive the original selected deadline, never a new
// wall-clock deadline reconstructed from a relative remaining interval.
type absoluteGuardV2 interface {
	ArmUntil(context.Context, string, Revision, Revision, time.Time) error
	RecoverPreviousUntil(context.Context, string, Revision, Revision, time.Time) error
}

func guardDeadlineV2(id, domain string, previous, target v2Configuration) (time.Time, error) {
	var deadline time.Time
	for _, pending := range []*v2Confirmation{target.Pending, previous.Pending} {
		if pending != nil && pending.Lease == id && pending.Domain == domain && !pending.Deadline.IsZero() {
			if !deadline.IsZero() && !deadline.Equal(pending.Deadline) {
				return time.Time{}, ErrRecovery
			}
			deadline = pending.Deadline
		}
	}
	if !deadline.IsZero() {
		return deadline, nil
	}
	// Immediate operations use the separately selected Intent.GuardDeadline.
	return time.Time{}, ErrRecovery
}

func (c *v2Coordinator) absoluteGuardPreflightV2(op v2Operation, previous, target v2Configuration) error {
	if !guardEffectV2(op, previous, target) {
		return nil
	}
	if op.Domain == "routed" {
		if c.options.Routed == nil {
			return ErrRecovery
		}
		return nil
	}
	id := op.ID
	if (op.Request.Kind == OpCommit || op.Request.Kind == OpRollback) && target.Pending != nil {
		id = target.Pending.Lease
	}
	if op.Request.Kind == OpConfirm && previous.Pending != nil {
		id = previous.Pending.Lease
	}
	for _, engine := range c.enginesV2(op.Domain) {
		if _, guarded := engine.(ActivationGuard); !guarded {
			continue
		}
		if _, absolute := engine.(absoluteGuardV2); absolute {
			if _, err := guardDeadlineV2(id, op.Domain, previous, target); err != nil {
				if !c.options.GuardDeadlines {
					return err
				}
			}
		} else if c.options.GuardDeadlines || hasFeatureV2(c.store.state, v2GuardDeadlineFeature) {
			return ErrRecovery
		}
	}
	return nil
}

func (c *v2Coordinator) hasPreparedGuard(domains ...string) bool {
	domain := "firewall"
	if len(domains) == 1 {
		domain = domains[0]
	}
	if domain == "routed" {
		return c.options.Routed != nil
	}
	for _, engine := range c.enginesV2(domain) {
		if _, ok := engine.(ActivationGuard); ok {
			return true
		}
	}
	return false
}
func (c *v2Coordinator) guardScopeLocked(op v2Operation, previous, target v2Configuration) (string, Revision, Revision, time.Duration, error) {
	id, prior, applied, ttl := op.ID, domainSnapshotV2(&previous, op.Domain).Running, domainSnapshotV2(&target, op.Domain).Running, 10*time.Second
	if (op.Request.Kind == OpCommit || op.Request.Kind == OpRollback) && target.Pending != nil {
		id = target.Pending.Lease
		ttl = target.Pending.Deadline.Sub(c.now())
	}
	if op.Request.Kind == OpConfirm {
		pending := previous.Pending
		if pending == nil {
			return "", Revision{}, Revision{}, 0, ErrRecovery
		}
		var original v2Configuration
		if c.store.readObject(pending.Previous, &original) != nil || !validV2Configuration(&original) {
			return "", Revision{}, Revision{}, 0, ErrRecovery
		}
		id, prior, applied, ttl = pending.Lease, domainSnapshotV2(&original, op.Domain).Running, domainSnapshotV2(&previous, op.Domain).Running, pending.Deadline.Sub(c.now())
	}
	return id, prior, applied, ttl, nil
}
func guardEffectV2(op v2Operation, previous, target v2Configuration) bool {
	return op.Request.Kind == OpRecover || op.Request.Kind == OpCommit || op.Request.Kind == OpConfirm || (op.Request.Kind == OpRollback && target.Pending != nil) || domainSnapshotV2(&previous, op.Domain).Running.Hash != domainSnapshotV2(&target, op.Domain).Running.Hash
}
func (c *v2Coordinator) prepareGuardsLocked(ctx context.Context, op v2Operation, previous, target v2Configuration) error {
	if op.Domain == "routed" && !metadataOperationV2(op.Request.Kind) {
		plan, err := c.selectedRoutedPlanV2()
		if err != nil {
			return err
		}
		if op.Request.Kind == OpConfirm {
			return nil
		}
		return c.options.Routed.Arm(ctx, plan)
	}
	domain := op.Domain
	if !c.hasPreparedGuard(op.Domain) || !guardEffectV2(op, previous, target) {
		return nil
	}
	id, prior, applied, ttl, err := c.guardScopeLocked(op, previous, target)
	if err != nil {
		return err
	}
	if ttl <= 0 || ttl > 120*time.Second || (op.Request.Kind != OpConfirm && ttl < 500*time.Millisecond) {
		return ErrExpired
	}
	for _, engine := range c.enginesV2(domain) {
		if _, ok := engine.(absoluteGuardV2); ok {
			if _, err := c.guardDeadlineLockedV2(id, domain, previous, target); err != nil {
				return err
			}
		}
	}
	for _, engine := range c.enginesV2(domain) {
		guard, ok := engine.(ActivationGuard)
		if !ok {
			continue
		}
		if _, ok := guard.(recoveringGuardV2); !ok {
			return ErrRecovery
		}
		var armErr error
		if absolute, ok := guard.(absoluteGuardV2); ok {
			deadline, _ := c.guardDeadlineLockedV2(id, domain, previous, target)
			armErr = absolute.ArmUntil(ctx, id, prior, applied, deadline)
		} else {
			armErr = guard.Arm(ctx, id, prior, applied, ttl)
		}
		if armErr != nil {
			return armErr
		}
	}
	return c.point("after_guard_arm")
}
func (c *v2Coordinator) confirmGuardsLocked(ctx context.Context, op v2Operation, previous, target v2Configuration) error {
	if op.Domain == "routed" && !metadataOperationV2(op.Request.Kind) {
		if target.Pending != nil {
			return nil
		}
		plan, err := c.selectedRoutedPlanV2()
		if err != nil {
			return err
		}
		return c.options.Routed.Confirm(ctx, plan)
	}
	domain := op.Domain
	if !c.hasPreparedGuard(op.Domain) || target.Pending != nil || !guardEffectV2(op, previous, target) {
		return nil
	}
	id, _, applied, _, err := c.guardScopeLocked(op, previous, target)
	if err != nil {
		return err
	}
	for _, engine := range c.enginesV2(domain) {
		guard, ok := engine.(ActivationGuard)
		if !ok {
			continue
		}
		if err := guard.Confirm(ctx, id, applied.Hash); err != nil {
			return err
		}
	}
	return c.point("after_guard_confirm")
}
func (c *v2Coordinator) restoreGuardsLocked(ctx context.Context, id string, previous, target v2Configuration, domains ...string) error {
	domain := effectDomainV2(previous, target)
	if len(domains) == 1 {
		domain = domains[0]
	}
	if domain == "routed" {
		plan, err := c.selectedRoutedPlanV2()
		if err != nil || plan.Lease() != id {
			return ErrRecovery
		}
		return c.options.Routed.Recover(ctx, plan)
	}
	for _, engine := range c.enginesV2(domain) {
		if guard, ok := engine.(ActivationGuard); ok {
			recovery, ok := guard.(recoveringGuardV2)
			if !ok {
				return ErrRecovery
			}
			var recoveryErr error
			if absolute, ok := guard.(absoluteGuardV2); ok {
				deadline, err := c.guardDeadlineLockedV2(id, domain, previous, target)
				if err != nil {
					return err
				}
				recoveryErr = absolute.RecoverPreviousUntil(ctx, id, domainSnapshotV2(&previous, domain).Running, domainSnapshotV2(&target, domain).Running, deadline)
			} else {
				recoveryErr = recovery.RecoverPrevious(ctx, id, domainSnapshotV2(&previous, domain).Running, domainSnapshotV2(&target, domain).Running)
			}
			if recoveryErr != nil {
				return recoveryErr
			}
		} else if err := engine.Apply(ctx, domainSnapshotV2(&previous, domain).Running); err != nil {
			return err
		}
	}
	return nil
}
func (c *v2Coordinator) compensationGuardsLocked(ctx context.Context, op v2Operation, previous v2Configuration) error {
	intent := c.store.state.Configuration.Intent
	if intent == nil {
		return ErrRecovery
	}
	var target v2Configuration
	if c.store.readObject(intent.Target, &target) != nil || !validV2Configuration(&target) {
		return ErrRecovery
	}
	id, _, _, _, err := c.guardScopeLocked(op, previous, target)
	if err != nil {
		return err
	}
	return c.restoreGuardsLocked(ctx, id, previous, target, op.Domain)
}
