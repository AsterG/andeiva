package routedactivation

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

func TestPairedObservationRealEnginePendingColdAndRecovered(t *testing.T) {
	for _, target := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovered-before", true: "recovered-target"}[target], func(t *testing.T) {
			f, e, g := recoveredIdleFixture(t, target)
			ctx := context.Background()
			if err := g.RecoverIdle(ctx, f.plan); err != nil {
				t.Fatal(err)
			}
			current, owned, err := e.ObserveCurrentOwned(ctx)
			wantCurrent, wantOwned := "", f.plan.BeforeOwned
			if target {
				wantCurrent, wantOwned = f.target.Composite.Hash, f.plan.TargetOwned
			}
			if err != nil || current != wantCurrent || owned != wantOwned {
				t.Fatal("wrong pair", current, owned, err)
			}
			state, hash, err := g.SnapshotObservedContext(ctx)
			if err != nil || state.Phase != "idle" || hash != wantCurrent {
				t.Fatal("recovered receipt", state, hash, err)
			}
		})
	}
	f := assembleFixture(t)
	defer f.group.Close()
	ctx := context.Background()
	if err := f.group.BootstrapStartup(ctx, f.plan, f.target, f.started); err != nil {
		t.Fatal(err)
	}
	state, hash, err := f.group.SnapshotObservedContext(ctx)
	if err != nil || state.Phase != "pending" || hash != f.target.Composite.Hash {
		t.Fatal("pending", err)
	}
	if err := f.group.RecoverLease(f.plan, state); err != nil {
		t.Fatal(err)
	}
	current, owned, err := f.engine.ObserveCurrentOwned(ctx)
	if err != nil || current != "" || owned != f.plan.BeforeOwned {
		t.Fatal("cold restore", err)
	}
}

type cancellingPairedListeners struct {
	localengine.Listeners
	cancel context.CancelFunc
}

func (l cancellingPairedListeners) Observe(ctx context.Context) ([]localpolicy.Listener, error) {
	actual, err := l.Listeners.Observe(ctx)
	l.cancel() // Simulate a successful I/O return racing caller cancellation.
	return actual, err
}

func TestPairedObservationFreshPhysicalStateAndLateCancellation(t *testing.T) {
	for _, fault := range []string{"table", "network", "listener", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f := assembleFixture(t)
			defer f.group.Close()
			if err := f.group.BootstrapStartup(context.Background(), f.plan, f.target, f.started); err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.engine.ObserveCurrentOwned(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "table":
				delete(f.kernel.objects, LocalTable)
			case "network":
				f.network.active = false
			case "listener":
				f.listeners.actual = nil
			case "cancel":
				f.engine.listeners = cancellingPairedListeners{f.listeners, cancel}
			}
			writes := len(f.kernel.batches)
			current, owned, err := f.engine.ObserveCurrentOwned(ctx)
			if err == nil || current != "" || owned != "" || len(f.kernel.batches) != writes {
				t.Fatal("cached authority or observation effects", fault, current, owned, err)
			}
			if fault != "cancel" && !f.engine.fenced {
				t.Fatal("drift did not preserve fence")
			}
		})
	}
}

func TestPairedObservationEngineLockCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := &Engine{}
		e.mu.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done := make(chan error, 2)
		go func() { _, _, err := e.ObserveCurrentOwned(ctx); done <- err }()
		go func() { done <- e.MatchOwned(ctx, "unknown") }()
		time.Sleep(time.Second)
		synctest.Wait()
		for range 2 {
			if <-done == nil {
				t.Fatal("lockwait admitted")
			}
		}
		e.mu.Unlock()
		if _, _, err := e.ObserveCurrentOwned(ctx); err == nil || !e.mu.TryLock() {
			t.Fatal("admission leaked lock")
		}
		e.mu.Unlock()
	})
}
