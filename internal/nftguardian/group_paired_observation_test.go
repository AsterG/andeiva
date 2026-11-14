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
}

func (e *pairedObservationEngine) Current() string {
	e.reads++
	return e.groupTestEngine.Current()
}

func (e *pairedObservationEngine) ObserveOwned(ctx context.Context) (string, error) {
	e.reads++
	return e.groupTestEngine.ObserveOwned(ctx)
}

func (e *pairedObservationEngine) ObserveCurrentOwned(ctx context.Context) (string, string, error) {
	e.reads++
	if e.paired != nil {
		e.paired(ctx)
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	return e.hash, e.owned, nil
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

func TestGroupPairedFallbackRejectsMutation(t *testing.T) {
	for _, mutation := range []string{"none", "current", "owned", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			target := groupBundle(t, false)
			before, after := strings.Repeat("a", 64), strings.Repeat("b", 64)
			e := &pairedObservationEngine{groupTestEngine: groupTestEngine{hash: target.Composite.Hash, owned: after}}
			g, _ := NewGroup(e)
			g.plan = groupPlan("paired", before, after)
			g.target, g.recoveredOwned, g.state = target, before, State{Phase: "idle"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			matched := 0
			e.match = func(_ context.Context, want string) error {
				matched++
				if want != before {
					t.Fatal("foreign contextual reference")
				}
				switch mutation {
				case "current":
					e.hash = strings.Repeat("c", 64)
				case "owned":
					e.owned = strings.Repeat("d", 64)
				case "cancel":
					cancel()
				}
				return nil
			}
			_, _, err := g.SnapshotObservedContext(ctx)
			if (err == nil) != (mutation == "none") || matched != 1 || e.reads != 2 {
				t.Fatal("mixed observation admitted", mutation, err, matched, e.reads)
			}
		})
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
