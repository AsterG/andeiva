//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ExerciseAbsoluteCoordinatorV2 is test-only assembly for the external adapter
// test package. Production exports and canonical store formats are unchanged.
func ExerciseAbsoluteCoordinatorV2(t *testing.T, build func(Engine, Revision) Engine, scenario string) {
	t.Helper()
	c, _, engines, p, now := coordinatorV2Fixture(t, false)
	initial := c.store.state.Configuration.Firewall.Running
	for i := range c.firewall {
		c.firewall[i] = build(engines[i], initial)
	}
	coordinatorV2Stage(t, c, p, "absolute-coordinator")
	if scenario == "immediate-gate" {
		coordinatorV2Run(t, c, p, v2Request{Kind: OpValidate})
		coordinatorV2Run(t, c, p, v2Request{Kind: OpSave})
		for _, e := range engines {
			e.reset()
		}
		zero := uint64(0)
		ns, err := c.store.namespace(p.Subject, "firewall", c.now(), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &zero}, c.now())
		if err != nil {
			t.Fatal(err)
		}
		before, _, err := v2Canonical(c.store.state)
		if err != nil {
			t.Fatal(err)
		}
		selector, used := c.store.selector, c.store.used
		_, err = c.execute(context.Background(), p, op.ID)
		if err == nil {
			t.Fatal("immediate absolute activation lacked durable deadline")
		}
		after, _, e := v2Canonical(c.store.state)
		if e != nil || string(before) != string(after) || selector != c.store.selector || used != c.store.used || c.store.blocked {
			t.Fatal("capability refusal changed admitted state", err, e)
		}
		retained, e := c.store.lookup(p.Subject, op.ID)
		if e != nil || retained.State != "accepted" {
			t.Fatal("unsupported operation consumed", e)
		}
		for _, e := range engines {
			if e.applies.Load() != 0 {
				t.Fatal("unsupported immediate activation reached engine")
			}
		}
		coordinatorV2Run(t, c, p, v2Request{Kind: OpSave})
		return
	}
	seconds := uint64(30)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if committed.Current.Pending == nil {
		t.Fatal("missing durable deadline")
	}
	pending := *committed.Current.Pending
	if scenario == "confirm" {
		// The coordinator's remaining TTL is deliberately different from the
		// exact original deadline. Absolute dispatch must preserve the latter.
		*now = now.Add(time.Millisecond)
		confirmed := coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: pending.OriginCommit, Target: pending.Target})
		if confirmed.Current.Pending != nil || confirmed.Current.Firewall.Running.Hash == initial.Hash {
			t.Fatal("confirmation did not finish")
		}
		return
	}
	if scenario != "expiry-restart" {
		t.Fatal("invalid test scenario")
	}
	c.close()
	time.Sleep(31 * time.Second)
	*now = now.Add(31 * time.Second)
	firewall := make([]Engine, len(engines)-1)
	for i := range firewall {
		firewall[i] = build(engines[i], initial)
	}
	reopened, err := openCoordinatorV2(context.Background(), c.store, firewall, c.local, c.options)
	if err != nil {
		t.Fatal("expired controller restart", err)
	}
	t.Cleanup(reopened.close)
	state, _, err := reopened.status(p)
	if err != nil || state.Pending != nil || state.RecoveryRequired || state.Firewall.Running.Hash != initial.Hash {
		t.Fatal("expired lease not recovered", err)
	}
	for _, e := range engines[:2] {
		if e.Current() != initial.Hash {
			t.Fatal("recovery did not restore effective state")
		}
	}
	if _, _, err := c.status(p); !errors.Is(err, errV2Unavailable) {
		t.Fatal("old controller resumed", err)
	}
}

func ExerciseImmediateGuardDeadlineV2(t *testing.T, build func(Engine, Revision) Engine, scenario string) {
	t.Helper()
	ctx := context.Background()
	c, area, engines, p, now := coordinatorV2Fixture(t, false)
	c.options.GuardDeadlines = true
	c.store.guardDeadlines = true
	initial := c.store.state.Configuration.Firewall.Running
	for i := range c.firewall {
		c.firewall[i] = build(engines[i], initial)
	}
	coordinatorV2Stage(t, c, p, "immediate-absolute")
	ns, err := c.store.namespace(p.Subject, "firewall", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	zero := uint64(0)
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &zero}, c.now())
	if err != nil {
		t.Fatal(err)
	}
	accepted := op.Accepted
	time.Sleep(31 * time.Second)
	*now = now.Add(31 * time.Second)
	var original time.Time
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			in := c.store.state.Configuration.Intent
			if in == nil || in.GuardDeadline == nil || !hasFeatureV2(c.store.state, v2GuardDeadlineFeature) {
				t.Fatal("deadline and feature not selected together")
			}
			original = *in.GuardDeadline
			if !original.Equal(c.now().Add(10*time.Second)) || !original.After(accepted.Add(40*time.Second)) {
				t.Fatal("admission timestamp substituted for effect start", original, accepted)
			}
			if scenario == "before-arm" {
				return ErrInterrupted
			}
			if scenario == "expired-before-arm" {
				time.Sleep(11 * time.Second)
				*now = now.Add(11 * time.Second)
			}
		}
		if scenario == "after-apply" && point == "after_component_apply" {
			return ErrInterrupted
		}
		if scenario == "after-confirm" && point == "after_guard_confirm" {
			return ErrInterrupted
		}
		return nil
	}
	result, err := c.execute(ctx, p, op.ID)
	if scenario == "success" {
		if err != nil || result.Operation.State != "final" || result.Current.Intent != nil || result.Current.Firewall.Running.Hash == initial.Hash || !hasFeatureV2(c.store.state, v2GuardDeadlineFeature) {
			t.Fatal("immediate commit", err)
		}
		return
	}
	if err == nil || original.IsZero() {
		t.Fatal("interruption did not exercise selected deadline", err)
	}
	if scenario == "expired-before-arm" {
		if c.store.state.Configuration.Firewall.Running.Hash != initial.Hash || c.store.state.Configuration.Intent != nil {
			t.Fatal("expired activation published target")
		}
		return
	}
	in := c.store.state.Configuration.Intent
	if in == nil || in.GuardDeadline == nil || !in.GuardDeadline.Equal(original) {
		t.Fatal("deadline lost after interruption")
	}
	c.close()
	budget := c.store.budget
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	store, err := openV2(area, budget)
	if err != nil {
		t.Fatal("cold read of selected deadline", err)
	}
	t.Cleanup(func() { _ = store.close() })
	if store.state.Configuration.Intent == nil || store.state.Configuration.Intent.GuardDeadline == nil || !store.state.Configuration.Intent.GuardDeadline.Equal(original) {
		t.Fatal("cold store changed deadline")
	}
	c.options.Hook = nil
	firewall := make([]Engine, 2)
	for i := range firewall {
		firewall[i] = build(engines[i], initial)
	}
	reopened, err := openCoordinatorV2(ctx, store, firewall, c.local, c.options)
	if scenario == "after-confirm" {
		if err == nil || store.state.Configuration.Firewall.Running.Hash != initial.Hash || store.state.Configuration.Intent == nil || !store.state.Configuration.Intent.GuardDeadline.Equal(original) {
			t.Fatal("ambiguous confirmation falsely published", err)
		}
		if reopened != nil {
			reopened.close()
		}
		return
	}
	if err != nil {
		t.Fatal("immediate restart recovery", err)
	}
	t.Cleanup(reopened.close)
	current, _, err := reopened.status(p)
	if err != nil || current.Intent != nil || current.RecoveryRequired || current.Firewall.Running.Hash != initial.Hash {
		t.Fatal("restart failed to compensate exact intent", err)
	}
}
