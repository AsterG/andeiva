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

func (c *v2Coordinator) hasPreparedGuard() bool {
	for _, engine := range c.firewall {
		if _, ok := engine.(ActivationGuard); ok {
			return true
		}
	}
	return false
}
func (c *v2Coordinator) guardScopeLocked(op v2Operation, previous, target v2Configuration) (string, Revision, Revision, time.Duration, error) {
	id, prior, applied, ttl := op.ID, previous.Firewall.Running, target.Firewall.Running, 10*time.Second
	if op.Request.Kind == OpCommit && target.Pending != nil {
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
		id, prior, applied, ttl = pending.Lease, original.Firewall.Running, previous.Firewall.Running, pending.Deadline.Sub(c.now())
	}
	return id, prior, applied, ttl, nil
}
func guardEffectV2(op v2Operation, previous, target v2Configuration) bool {
	return op.Request.Kind == OpCommit || op.Request.Kind == OpConfirm || previous.Firewall.Running.Hash != target.Firewall.Running.Hash
}
func (c *v2Coordinator) prepareGuardsLocked(ctx context.Context, op v2Operation, previous, target v2Configuration) error {
	if !c.hasPreparedGuard() || !guardEffectV2(op, previous, target) {
		return nil
	}
	id, prior, applied, ttl, err := c.guardScopeLocked(op, previous, target)
	if err != nil {
		return err
	}
	if ttl < 500*time.Millisecond || ttl > 120*time.Second {
		return ErrExpired
	}
	for _, engine := range c.firewall {
		guard, ok := engine.(ActivationGuard)
		if !ok {
			continue
		}
		if _, ok := guard.(recoveringGuardV2); !ok {
			return ErrRecovery
		}
		if err := guard.Arm(ctx, id, prior, applied, ttl); err != nil {
			return err
		}
	}
	return c.point("after_guard_arm")
}
func (c *v2Coordinator) confirmGuardsLocked(ctx context.Context, op v2Operation, previous, target v2Configuration) error {
	if !c.hasPreparedGuard() || target.Pending != nil || !guardEffectV2(op, previous, target) {
		return nil
	}
	id, _, applied, _, err := c.guardScopeLocked(op, previous, target)
	if err != nil {
		return err
	}
	for _, engine := range c.firewall {
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
func (c *v2Coordinator) restoreGuardsLocked(ctx context.Context, id string, previous, target v2Configuration) error {
	for _, engine := range c.firewall {
		if guard, ok := engine.(ActivationGuard); ok {
			recovery, ok := guard.(recoveringGuardV2)
			if !ok {
				return ErrRecovery
			}
			if err := recovery.RecoverPrevious(ctx, id, previous.Firewall.Running, target.Firewall.Running); err != nil {
				return err
			}
		} else if err := engine.Apply(ctx, previous.Firewall.Running); err != nil {
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
	// An ambiguous confirmation must not replay the applied target or reverse a
	// helper safety rollback. Leave its linked intent/pins for authorized recovery.
	if op.Request.Kind == OpConfirm {
		return ErrRecovery
	}
	id, _, _, _, err := c.guardScopeLocked(op, previous, target)
	if err != nil {
		return err
	}
	return c.restoreGuardsLocked(ctx, id, previous, target)
}
