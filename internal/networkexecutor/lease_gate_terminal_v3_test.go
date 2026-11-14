package networkexecutor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLeaseGateRenewalBetweenCurrentAndLiveProvesOnlyClosure(t *testing.T) {
	ctx := context.Background()
	g, k, a, _ := gateFixture(t)
	if err := g.Stage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(ctx); err != nil {
		t.Fatal(err)
	}
	old := a.grant
	a.grant.Fact.Sequence++
	a.grant.Fact.DeadlineBootNS += int64(time.Minute)
	a.verify = func() error {
		if a.grant.Fact != old.Fact {
			return ErrLeaseUnavailable
		}
		return nil
	}
	if err := g.Verify(ctx); err == nil {
		t.Fatal("superseded live grant accepted")
	}
	if k.enabled || k.token != nil || !g.fenced {
		t.Fatal("old forwarding authority survived")
	}
	if err := g.Close(ctx); err != nil {
		t.Fatal("physical closure", err)
	}
	g.opts.Authority = terminalGateNoAuthorityV3{t}
	before := k.applies
	if err := g.VerifyClosedSelectedV3(ctx); err != nil {
		t.Fatal("renewal prevents selected withdrawal despite physical closure", err)
	}
	if k.applies != before {
		t.Fatal("closure proof wrote kernel state")
	}
	if !g.fenced || g.seen != old.Fact.Sequence {
		t.Fatal("closure erased fence or consumed sequence")
	}
	if g.Stage(ctx) == nil || g.Open(ctx) == nil || g.Verify(ctx) == nil {
		t.Fatal("closed proof rehabilitated the old gate")
	}
}

type terminalGateNoAuthorityV3 struct{ t *testing.T }

func (a terminalGateNoAuthorityV3) Current(context.Context) (LeaseGateGrant, error) {
	a.t.Fatal("terminal proof consulted lease authority")
	return LeaseGateGrant{}, ErrScope
}
func (a terminalGateNoAuthorityV3) Verify(context.Context, LeaseGateGrant) error {
	a.t.Fatal("terminal proof consulted selected authority")
	return ErrScope
}

func terminalGateSnapshotV3(t *testing.T) LeaseSelectedSnapshotV3 {
	t.Helper()
	l, _, _, _ := leaseFixture(t)
	s, err := l.PrepareSelectedSnapshotV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLeaseGateTerminalDisposalAndRecoveredHighWater(t *testing.T) {
	ctx := context.Background()
	s := terminalGateSnapshotV3(t)
	g, k, a, now := gateFixture(t)
	if g.Stage(ctx) != nil || g.Open(ctx) != nil {
		t.Fatal("initial gate")
	}
	_ = g.fail(ErrLeaseUnavailable)
	released := 0
	g.release = func() error { released++; return nil }
	before := k.applies
	if err := g.DisposeWithdrawnSelectedV3(ctx, s); err != nil {
		t.Fatal(err)
	}
	if released != 1 || !g.fenced || !g.disposed || g.seen != s.Sequence || k.applies != before {
		t.Fatal("terminal disposal changed gate authority")
	}
	if g.DisposeWithdrawnSelectedV3(ctx, s) == nil || g.Stage(ctx) == nil || g.Open(ctx) == nil || released != 1 {
		t.Fatal("old instance reused")
	}
	recovered := func() *LeaseGate {
		x, err := newLeaseGate(ctx, s.Identity, g.opts, k, func() (int64, error) { return *now, nil }, func() error { return nil })
		if err != nil || x.RecoverWithdrawnSelectedV3(ctx, s) != nil {
			t.Fatal("recover archived gate", err)
		}
		return x
	}
	if recovered().Stage(ctx) == nil || k.stages != 1 {
		t.Fatal("archived sequence reused")
	}
	next := recovered()
	a.grant.Fact.Sequence++
	a.grant.Fact.DeadlineBootNS += int64(time.Minute)
	if next.Stage(ctx) != nil || next.Open(ctx) != nil || k.stages != 2 {
		t.Fatal("fresh selected sequence could not open")
	}
}

func TestLeaseGateTerminalDisposalRejectsUnprovenClosure(t *testing.T) {
	for _, mode := range []string{"bad-hash", "identity", "owner", "desired", "wan", "below-seen", "forwarding", "open", "foreign-table", "extra-table", "staged", "cancelled", "cancel-during-read", "cancel-final-forwarding", "lifetime", "release"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := terminalGateSnapshotV3(t)
			g, k, _, _ := gateFixture(t)
			g.fenced, g.seen = true, s.Sequence
			switch mode {
			case "bad-hash":
				s.Hash = strings.Repeat("a", 64)
			case "identity":
				g.identity.Namespace++
			case "owner":
				g.opts.Owner.StartTicks++
			case "desired":
				g.opts.Desired.Hash = strings.Repeat("a", 64)
			case "wan":
				g.wan.Binding.Name = "foreign0"
			case "below-seen":
				g.seen++
			case "forwarding":
				g.closedForwarding = func() error { return ErrScope }
			case "open":
				k.enabled = true
			case "foreign-table":
				k.observe = func(b []byte) []byte { return []byte(strings.Replace(string(b), "drop", "accept", 1)) }
			case "extra-table":
				k.observe = func(b []byte) []byte {
					return []byte(strings.Replace(string(b), `"nftables":[`, `"nftables":[{"table":{"name":"extra","family":"inet"}},`, 1))
				}
			case "staged":
				g.staged.Fact.Sequence = s.Sequence
			case "cancelled":
				cancel()
			case "cancel-during-read":
				k.observe = func(b []byte) []byte { cancel(); return b }
			case "cancel-final-forwarding":
				checks := 0
				g.closedForwarding = func() error {
					checks++
					if checks == 2 {
						cancel()
					}
					return nil
				}
			case "lifetime":
				life, stop := context.WithCancel(context.Background())
				stop()
				g.lifetime = life
			}
			releases := 0
			g.release = func() error { releases++; return errors.New("release failed") }
			before := k.applies
			if g.DisposeWithdrawnSelectedV3(ctx, s) == nil || k.applies != before || !g.fenced {
				t.Fatal("invalid terminal disposal admitted or mutated")
			}
			if mode == "release" {
				if releases != 1 || !g.disposed || g.DisposeWithdrawnSelectedV3(ctx, s) == nil || releases != 1 {
					t.Fatal("partial release retried")
				}
			} else if releases != 0 || g.disposed {
				t.Fatal("unproven resources released")
			}
		})
	}
}
