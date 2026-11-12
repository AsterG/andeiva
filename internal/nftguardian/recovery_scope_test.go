package nftguardian

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestPreparedGuardGuardianRecoveryCAS(t *testing.T) {
	for _, phase := range []string{"armed", "pending", "expired"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				previous, target := revisions()
				engine := configpoc.NewSimEngine("scoped-recovery")
				if err := engine.Apply(context.Background(), previous); err != nil {
					t.Fatal(err)
				}
				g := New(engine)
				defer g.Close()
				if err := g.Arm("owned", previous, target, time.Second); err != nil {
					t.Fatal(err)
				}
				if phase != "armed" {
					if err := g.Apply(context.Background(), target); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "expired" {
					time.Sleep(2 * time.Second)
					synctest.Wait()
				}
				observed := g.Status()
				if observed.Phase != phase {
					t.Fatal(observed)
				}
				for _, mutation := range []string{"id", "previous", "target", "deadline", "zero"} {
					stale := observed
					switch mutation {
					case "id":
						stale.ID = "foreign"
					case "previous":
						stale.Previous = target.Hash
					case "target":
						stale.Target = previous.Hash
					case "deadline":
						stale.Deadline = stale.Deadline.Add(time.Nanosecond)
					case "zero":
						stale.Deadline = time.Time{}
					}
					before := engine.Current()
					if !errors.Is(g.RecoverLease(stale.ID, stale.Previous, stale.Target, stale.Deadline), ErrLease) || g.Status() != observed || engine.Current() != before {
						t.Fatal("stale CAS changed lease", mutation)
					}
				}
				if err := g.RecoverLease(observed.ID, observed.Previous, observed.Target, observed.Deadline); err != nil || engine.Current() != previous.Hash || g.Status().Phase != "idle" {
					t.Fatal("exact CAS failed", err)
				}
				if g.RecoverLease(observed.ID, observed.Previous, observed.Target, observed.Deadline) == nil {
					t.Fatal("idle CAS accepted")
				}
			})
		})
	}
}

func TestPreparedGuardGuardianRecoveryCASConcurrent(t *testing.T) {
	previous, target := revisions()
	engine := configpoc.NewSimEngine("scoped-concurrent")
	if err := engine.Apply(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	g := New(engine)
	defer g.Close()
	if err := g.Arm("owned", previous, target, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	scope := g.Status()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			<-start
			if g.RecoverLease(scope.ID, scope.Previous, scope.Target, scope.Deadline.Add(time.Nanosecond)) == nil {
				t.Error("stale concurrent CAS accepted")
			}
		})
	}
	wg.Go(func() {
		<-start
		if err := g.RecoverLease(scope.ID, scope.Previous, scope.Target, scope.Deadline); err != nil {
			t.Error(err)
		}
	})
	close(start)
	wg.Wait()
	if engine.Current() != previous.Hash || g.Status().Phase != "idle" {
		t.Fatal("exact recovery lost")
	}
}

func TestPreparedGuardGuardianRecoveryCASRejectsInvalidPhase(t *testing.T) {
	for _, phase := range []string{"bootstrap", "idle", "blocked"} {
		t.Run(phase, func(t *testing.T) {
			previous, target := revisions()
			engine := configpoc.NewSimEngine("invalid-phase")
			g := New(engine)
			defer g.Close()
			g.state = State{Phase: phase, ID: "scope", Previous: previous.Hash, Target: target.Hash, Deadline: time.Now().Add(time.Minute)}
			g.previous, g.target, g.deadline = previous, target, g.state.Deadline
			before := g.state
			current := engine.Current()
			if !errors.Is(g.RecoverLease("scope", previous.Hash, target.Hash, g.deadline), ErrLease) || g.state != before || engine.Current() != current {
				t.Fatal("invalid phase mutated")
			}
		})
	}
}
