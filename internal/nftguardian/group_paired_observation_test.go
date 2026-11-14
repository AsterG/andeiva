package nftguardian

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// Instrument the engine boundary, not an estimated native duration. Each
// existing Current/ObserveOwned performs a complete semantic readback.
type pairedObservationEngine struct {
	groupTestEngine
	reads  int
	match  func(context.Context, string) error
	paired func(context.Context)
	alias  string
	change func(*GroupObservationV1)
}

func (e *pairedObservationEngine) Current() string {
	e.reads++
	return e.groupTestEngine.Current()
}

func (e *pairedObservationEngine) ObserveOwned(ctx context.Context) (string, error) {
	e.reads++
	return e.groupTestEngine.ObserveOwned(ctx)
}

func (e *pairedObservationEngine) ObserveCurrentOwned(ctx context.Context) (GroupObservationV1, error) {
	e.reads++
	if e.paired != nil {
		e.paired(ctx)
	}
	if err := ctx.Err(); err != nil {
		return GroupObservationV1{}, err
	}
	o := GroupObservationV1{Plan: e.plan, Current: e.hash, Owned: e.owned, MatchingOwned: [2]string{e.owned, e.alias}}
	if e.change != nil {
		e.change(&o)
	}
	return o, nil
}

func (e *pairedObservationEngine) MatchOwned(ctx context.Context, want string) error {
	if e.match != nil {
		return e.match(ctx, want)
	}
	if e.owned != want {
		return ErrLease
	}
	return ctx.Err()
}

func TestGroupPairedObservationFourFreshPhases(t *testing.T) {
	target := groupBundle(t, false)
	owned := strings.Repeat("a", 64)
	e := &pairedObservationEngine{groupTestEngine: groupTestEngine{hash: target.Composite.Hash, owned: owned}}
	g, err := NewGroup(e)
	if err != nil {
		t.Fatal(err)
	}
	g.target, g.recoveredOwned = target, owned
	g.plan = groupPlan("four", strings.Repeat("b", 64), owned)
	e.plan = g.plan
	g.state = State{Phase: "idle"}
	for phase := range 4 { // Stage, Open, pre-forwarding, post-forwarding.
		state, current, err := g.SnapshotObserved()
		if err != nil || state.Phase != "idle" || current != target.Composite.Hash {
			t.Fatalf("phase %d: invalid observation: %v", phase, err)
		}
	}
	if e.reads != 4 {
		t.Fatalf("four independent phases performed %d full readbacks; want 4 fresh paired readbacks (legacy duplicates=8)", e.reads)
	}
}

func TestGroupPairedExactAliasesWithoutFallbackIO(t *testing.T) {
	for _, mutation := range []string{"none", "plan", "foreign-alias", "duplicate", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			target := groupBundle(t, false)
			before, after := strings.Repeat("a", 64), strings.Repeat("b", 64)
			e := &pairedObservationEngine{groupTestEngine: groupTestEngine{hash: target.Composite.Hash, owned: after}}
			g, _ := NewGroup(e)
			g.plan = groupPlan("paired", before, after)
			e.plan, e.alias = g.plan, before
			g.target, g.recoveredOwned, g.state = target, before, State{Phase: "idle"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			matched := 0
			e.match = func(_ context.Context, want string) error {
				matched++
				return ErrLease
			}
			e.change = func(o *GroupObservationV1) {
				switch mutation {
				case "plan":
					o.Plan.Operation = "changed"
				case "foreign-alias":
					o.MatchingOwned[1] = strings.Repeat("c", 64)
				case "duplicate":
					o.MatchingOwned[1] = after
				case "cancel":
					cancel()
				}
			}
			_, _, err := g.SnapshotObservedContext(ctx)
			if (err == nil) != (mutation == "none") || matched != 0 || e.reads != 1 {
				t.Fatal("mixed observation admitted", mutation, err, matched, e.reads)
			}
		})
	}
}

func TestGroupPairedRejectsABAContextualProof(t *testing.T) {
	target := groupBundle(t, false)
	before, after := strings.Repeat("a", 64), strings.Repeat("b", 64)
	e := &pairedObservationEngine{groupTestEngine: groupTestEngine{hash: target.Composite.Hash, owned: after}}
	g, _ := NewGroup(e)
	g.plan = groupPlan("aba", before, after)
	e.plan = g.plan
	g.target, g.recoveredOwned, g.state = target, before, State{Phase: "idle"}
	e.match = func(_ context.Context, want string) error {
		e.owned = before // A different physical state exists only during this call.
		if want != before {
			return ErrLease
		}
		return nil
	}
	e.paired = func(context.Context) { e.owned = after } // A -> B -> A.
	if _, _, err := g.SnapshotObservedContext(context.Background()); err == nil {
		t.Fatal("ABA mixed Target current with transient Before proof")
	}
	if e.reads != 1 {
		t.Fatal("ABA triggered a second observation", e.reads)
	}
}

func TestGroupPairedContextCancellationAndCompatibility(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := &pairedObservationEngine{}
		g, _ := NewGroup(e)
		g.mu.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { _, _, err := g.SnapshotObservedContext(ctx); done <- err }()
		time.Sleep(time.Second)
		synctest.Wait()
		if err := <-done; err == nil || e.reads != 0 {
			t.Fatal("locked cancellation observed engine", err)
		}
		g.mu.Unlock()
		if _, _, err := g.SnapshotObservedContext(ctx); err == nil || !g.mu.TryLock() {
			t.Fatal("cancelled admission leaked lock")
		}
		g.mu.Unlock()
	})
	legacy, _ := NewGroup(&groupTestEngine{})
	if _, _, err := legacy.SnapshotObservedContext(context.Background()); err == nil {
		t.Fatal("uncancellable legacy engine admitted")
	}
	target := groupBundle(t, false)
	e := &pairedObservationEngine{groupTestEngine: groupTestEngine{hash: target.Composite.Hash, owned: strings.Repeat("a", 64)}}
	g, _ := NewGroup(e)
	g.target, g.recoveredOwned, g.state = target, e.owned, State{Phase: "idle"}
	g.plan = groupPlan("cancel", strings.Repeat("b", 64), e.owned)
	e.plan = g.plan
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.paired = func(got context.Context) {
		if got != ctx {
			t.Fatal("RPC context replaced")
		}
		cancel()
	}
	if _, _, err := g.SnapshotObservedContext(ctx); err == nil {
		t.Fatal("late cancellation admitted")
	}
}

func TestGroupPairedRejectsUnknownAndMalformedObservations(t *testing.T) {
	for _, fault := range []string{"owned", "hash", "unknown-current", "unknown-reference", "expired-pending"} {
		t.Run(fault, func(t *testing.T) {
			target := groupBundle(t, false)
			e := &pairedObservationEngine{groupTestEngine: groupTestEngine{hash: target.Composite.Hash, owned: strings.Repeat("a", 64)}}
			g, _ := NewGroup(e)
			g.target, g.plan, g.state = target, groupPlan("pair", strings.Repeat("b", 64), e.owned), State{Phase: "idle"}
			e.plan = g.plan
			switch fault {
			case "owned":
				e.owned = "bad"
			case "hash":
				e.hash = "bad"
			case "unknown-current":
				e.hash = strings.Repeat("f", 64)
			case "unknown-reference":
				g.recoveredOwned = strings.Repeat("e", 64)
			case "expired-pending":
				g.state.Phase = "pending"
				g.deadline = time.Now().Add(-time.Second)
			}
			if _, _, err := g.SnapshotObservedContext(context.Background()); err == nil {
				t.Fatal("unknown observation admitted")
			}
		})
	}
}
