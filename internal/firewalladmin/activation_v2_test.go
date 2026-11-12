package firewalladmin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

type preparedGuardAuthority struct {
	g                                      *nftguardian.Guardian
	engine                                 *configpoc.SimEngine
	armErr, confirmErr                     bool
	denyArm, denyConfirm                   bool
	failState, failStateAfterDeniedConfirm bool
	wrongID                                bool
	afterConfirm                           func() error
}

func (a *preparedGuardAuthority) Arm(_ context.Context, id string, previous, target configpoc.Revision, ttl time.Duration) error {
	if a.denyArm {
		return errors.New("arm unavailable")
	}
	err := a.g.Arm(id, previous, target, ttl)
	if err == nil && a.armErr {
		return errors.New("lost arm reply")
	}
	return err
}
func (a *preparedGuardAuthority) Confirm(_ context.Context, id, hash string) error {
	if a.denyConfirm {
		if a.failStateAfterDeniedConfirm {
			a.failState = true
		}
		return errors.New("confirmation unavailable")
	}
	err := a.g.Confirm(id, hash)
	if err == nil && a.afterConfirm != nil {
		if err = a.afterConfirm(); err != nil {
			return err
		}
	}
	if err == nil && a.confirmErr {
		return errors.New("lost confirmation reply")
	}
	return err
}
func (a *preparedGuardAuthority) Current(context.Context) (string, error) {
	return a.engine.Current(), nil
}
func (a *preparedGuardAuthority) State(context.Context) (LeaseState, error) {
	if a.failState {
		return LeaseState{}, errors.New("state unavailable")
	}
	s := a.g.Status()
	if a.wrongID {
		s.ID = "unrelated-lease"
	}
	return LeaseState{Phase: s.Phase, ID: s.ID, Previous: s.Previous, Target: s.Target, Deadline: s.Deadline}, nil
}

type preparedGuardianEngine struct {
	base     *configpoc.SimEngine
	guardian *nftguardian.Guardian
}

func (e preparedGuardianEngine) Name() string                      { return e.base.Name() }
func (e preparedGuardianEngine) Validate(c configpoc.Config) error { return e.base.Validate(c) }
func (e preparedGuardianEngine) Current() string                   { return e.base.Current() }
func (e preparedGuardianEngine) Apply(ctx context.Context, r configpoc.Revision) error {
	return e.guardian.Apply(ctx, r)
}

func preparedGuardFixture(t *testing.T) (*PreparedGuardedEngine, *preparedGuardAuthority, configpoc.Revision, configpoc.Revision) {
	t.Helper()
	old, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	on := true
	next, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "guard-fixture", Action: "deny", Enabled: &on, Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "udp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}})
	if err != nil {
		t.Fatal(err)
	}
	engine := configpoc.NewSimEngine("guarded-simulated-firewall")
	g := nftguardian.NewRestricted(engine)
	if err := g.Bootstrap(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	a := &preparedGuardAuthority{g: g, engine: engine}
	guard, err := NewPreparedGuardedEngine(preparedGuardianEngine{engine, g}, a, func(_ context.Context, scope LeaseState) error {
		return g.RecoverLease(scope.ID, scope.Previous, scope.Target, scope.Deadline)
	})
	if err != nil {
		t.Fatal(err)
	}
	return guard, a, old, next
}
func TestPreparedGuardRequiresExactArmAndReconcilesReplies(t *testing.T) {
	guard, a, old, next := preparedGuardFixture(t)
	ctx := context.Background()
	if guard.Apply(ctx, next) == nil {
		t.Fatal("apply succeeded without arm")
	}
	a.armErr = true
	if err := guard.Arm(ctx, "durable-intent", old, next, 10*time.Second); err != nil {
		t.Fatal("exact arm receipt not reconciled", err)
	}
	if err := guard.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	if guard.Confirm(ctx, "another-intent", next.Hash) == nil {
		t.Fatal("wrong confirmation lease accepted")
	}
	a.wrongID = true
	if guard.Confirm(ctx, "durable-intent", next.Hash) == nil {
		t.Fatal("wrong observed receipt accepted")
	}
	a.wrongID = false
	a.confirmErr = true
	if err := guard.Confirm(ctx, "durable-intent", next.Hash); err != nil {
		t.Fatal("exact confirmation receipt not reconciled", err)
	}
	if a.g.Status().Phase != "idle" || guard.Current() != next.Hash {
		t.Fatal("unverified confirmation")
	}
	if guard.RecoverPrevious(ctx, "durable-intent", old, next) == nil {
		t.Fatal("confirmed target was silently undone")
	}
}
func TestPreparedGuardRecoveryCannotClearForeignLease(t *testing.T) {
	guard, a, old, next := preparedGuardFixture(t)
	ctx := context.Background()
	if err := guard.Arm(ctx, "owned-intent", old, next, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := guard.Apply(ctx, next); err != nil {
		t.Fatal(err)
	}
	if guard.RecoverPrevious(ctx, "foreign-intent", old, next) == nil {
		t.Fatal("foreign lease cleared")
	}
	if a.g.Status().Phase != "pending" || guard.Current() != next.Hash {
		t.Fatal("denial changed authority")
	}
	if err := guard.RecoverPrevious(ctx, "owned-intent", old, next); err != nil {
		t.Fatal(err)
	}
	if guard.Current() != old.Hash || a.g.Status().Phase != "idle" {
		t.Fatal("previous revision not verified")
	}
}
