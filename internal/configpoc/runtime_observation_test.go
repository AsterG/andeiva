package configpoc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRuntimeObservationPinsSnapshotAndCopiesCallbackInput(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	base := status(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	observed := make(chan error, 1)
	go func() {
		out, err := s.ObserveRuntime(context.Background(), func(snap Snapshot) error {
			snap.Running.Config.DefaultAction = "corrupted"
			close(entered)
			<-release
			return nil
		})
		if err == nil && (out.Running.Hash != base.Running.Hash || out.Running.Config.DefaultAction != "deny") {
			err = errors.New("snapshot alias")
		}
		observed <- err
	}()
	<-entered
	staged := make(chan error, 1)
	c := sample("after-observation")
	go func() {
		_, err := s.Execute(context.Background(), admin, API, Request{Operation: OpStage, Key: "runtime-barrier", ExpectedGeneration: base.Generation, Config: &c})
		staged <- err
	}()
	select {
	case <-staged:
		close(release)
		t.Fatal("mutation crossed readback barrier")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	if err := <-staged; err != nil {
		t.Fatal(err)
	}
	if status(t, s).Running.Config.DefaultAction != "deny" {
		t.Fatal("callback modified durable state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, err := s.ObserveRuntime(ctx, func(Snapshot) error { called = true; return nil }); !errors.Is(err, context.Canceled) || called {
		t.Fatal("cancelled read reached callback")
	}
	if _, err := s.ObserveRuntime(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil callback")
	}
}

func TestRuntimeObservationPinsExpiryTimer(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	previous := status(t, s).Running.Hash
	c := sample("pending-runtime")
	invoke(t, s, OpStage, &c, 0)
	invoke(t, s, OpValidate, nil, 0)
	pending := invoke(t, s, OpCommit, nil, time.Minute)
	out, err := s.ObserveRuntime(context.Background(), func(snap Snapshot) error {
		if snap.Running.Hash != pending.Running.Hash {
			return errors.New("wrong pinned revision")
		}
		// Install an already-due timer under the held coordinator lock so this
		// regression does not depend on scheduler speed before the callback.
		s.deadline = time.Now()
		s.armTimer()
		time.Sleep(80 * time.Millisecond)
		if s.state.Snapshot.Running.Hash != snap.Running.Hash {
			return errors.New("expiry crossed barrier")
		}
		return nil
	})
	if err != nil || out.Running.Hash != pending.Running.Hash {
		t.Fatal(err)
	}
	if restored := status(t, s); restored.Pending != nil || restored.Running.Hash != previous {
		t.Fatal("expiry did not resume")
	}
}
