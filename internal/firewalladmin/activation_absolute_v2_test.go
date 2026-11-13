package firewalladmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

type absoluteAuthorityFixture struct {
	*preparedGuardAuthority
	beforeApply, beforeConfirm      func()
	lostArm, lostApply, lostConfirm bool
	arms                            int
}

func (a *absoluteAuthorityFixture) ArmUntil(_ context.Context, id string, p, t configpoc.Revision, d time.Time) error {
	a.arms++
	e := a.g.ArmUntil(id, p, t, d)
	if e == nil && a.lostArm {
		return errors.New("lost reply")
	}
	return e
}
func guardianScope(s LeaseState) nftguardian.State {
	return nftguardian.State{ID: s.ID, Previous: s.Previous, Target: s.Target, Deadline: s.Deadline}
}
func (a *absoluteAuthorityFixture) ApplyLease(ctx context.Context, r configpoc.Revision, s LeaseState) error {
	if a.beforeApply != nil {
		a.beforeApply()
	}
	e := a.g.ApplyLease(ctx, r, guardianScope(s))
	if e == nil && a.lostApply {
		return errors.New("lost apply reply")
	}
	return e
}
func (a *absoluteAuthorityFixture) ConfirmLease(_ context.Context, s LeaseState) error {
	if a.beforeConfirm != nil {
		a.beforeConfirm()
	}
	e := a.g.ConfirmLease(guardianScope(s))
	if e == nil && a.lostConfirm {
		return errors.New("lost reply")
	}
	return e
}
func (a *absoluteAuthorityFixture) RecoverScoped(_ context.Context, s LeaseState) error {
	return a.g.RecoverLease(s.ID, s.Previous, s.Target, s.Deadline)
}
func absoluteFixture(t *testing.T) (*PreparedAbsoluteGuardedEngine, *absoluteAuthorityFixture, configpoc.Revision, configpoc.Revision) {
	_, base, p, next := preparedGuardFixture(t)
	a := &absoluteAuthorityFixture{preparedGuardAuthority: base}
	g, e := NewPreparedAbsoluteGuardedEngine(preparedGuardianEngine{base.engine, base.g}, a)
	if e != nil {
		t.Fatal(e)
	}
	return g, a, p, next
}
func TestAbsoluteAdapterExactRebindAndLostReplies(t *testing.T) {
	g, a, p, next := absoluteFixture(t)
	ctx := context.Background()
	deadline := time.Now().UTC().Add(800 * time.Millisecond)
	a.lostArm = true
	if e := g.ArmUntil(ctx, "exact", p, next, deadline); e != nil {
		t.Fatal(e)
	}
	time.Sleep(450 * time.Millisecond)
	restarted, e := NewPreparedAbsoluteGuardedEngine(g.engine, a)
	if e != nil {
		t.Fatal(e)
	}
	if e = restarted.ArmUntil(ctx, "exact", p, next, deadline); e != nil || a.arms != 1 {
		t.Fatal("rebind rearmed", e, a.arms)
	}
	if restarted.ArmUntil(ctx, "exact", p, next, deadline.Add(time.Nanosecond)) == nil {
		t.Fatal("changed deadline rebound")
	}
	a.lostApply = true
	if e = restarted.Apply(ctx, next); e != nil {
		t.Fatal(e)
	}
	a.lostConfirm = true
	if e = restarted.Confirm(ctx, "exact", next.Hash); e != nil {
		t.Fatal(e)
	}
	if e = restarted.Confirm(ctx, "exact", next.Hash); e != nil {
		t.Fatal("exact retry", e)
	}
	if _, ok := any(&PreparedGuardedEngine{}).(interface {
		ArmUntil(context.Context, string, configpoc.Revision, configpoc.Revision, time.Time) error
	}); ok {
		t.Fatal("relative adapter gained absolute capability")
	}
}
func TestAbsoluteAdapterReplacementCannotBeConsumed(t *testing.T) {
	for _, action := range []string{"apply", "confirm", "recover"} {
		t.Run(action, func(t *testing.T) {
			g, a, p, next := absoluteFixture(t)
			ctx := context.Background()
			d := time.Now().UTC().Add(3 * time.Second)
			if e := g.ArmUntil(ctx, "same", p, next, d); e != nil {
				t.Fatal(e)
			}
			if action == "confirm" {
				if e := g.Apply(ctx, next); e != nil {
					t.Fatal(e)
				}
			}
			replace := func() {
				s := a.g.Status()
				if e := a.g.RecoverLease(s.ID, s.Previous, s.Target, s.Deadline); e != nil {
					t.Fatal(e)
				}
				if e := a.g.ArmUntil("same", p, next, d.Add(time.Nanosecond)); e != nil {
					t.Fatal(e)
				}
			}
			var err error
			switch action {
			case "apply":
				a.beforeApply = replace
				err = g.Apply(ctx, next)
			case "confirm":
				a.beforeConfirm = replace
				err = g.Confirm(ctx, "same", next.Hash)
			case "recover":
				replace()
				err = g.RecoverPrevious(ctx, "same", p, next)
			}
			if err == nil || a.engine.Current() != p.Hash || a.g.Status().Phase != "armed" || !a.g.Status().Deadline.Equal(d.Add(time.Nanosecond)) {
				t.Fatal("replacement consumed", err, a.g.Status())
			}
		})
	}
}
