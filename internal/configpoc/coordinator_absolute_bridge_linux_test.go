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
