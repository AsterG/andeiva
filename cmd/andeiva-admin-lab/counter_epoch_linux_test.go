package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type epochTestEngine struct {
	hash    string
	fail    bool
	applied chan struct{}
}

func (e *epochTestEngine) Current() string { return e.hash }
func (e *epochTestEngine) Apply(_ context.Context, r configpoc.Revision) error {
	if e.applied != nil {
		close(e.applied)
		e.applied = nil
	}
	if e.fail {
		return errors.New("failed apply")
	}
	e.hash = r.Hash
	return nil
}
func TestCounterEpochChangesOnEveryAttempt(t *testing.T) {
	backend := &epochTestEngine{hash: "same"}
	engine := &counterEngine{run: strings.Repeat("a", 32), engine: backend, read: func(context.Context) (string, []firewallipc.Counter, error) {
		return backend.hash, []firewallipc.Counter{{ID: "a", Packets: 100, Bytes: 6000}}, nil
	}}
	_, _, first, err := engine.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(context.Background(), configpoc.Revision{Hash: "same"}); err != nil {
		t.Fatal(err)
	}
	_, _, second, err := engine.Observe(context.Background())
	if err != nil || first == second {
		t.Fatal("same-hash apply kept epoch")
	}
	backend.fail = true
	if engine.Apply(context.Background(), configpoc.Revision{Hash: "other"}) == nil {
		t.Fatal("test failure not injected")
	}
	hash, _, third, err := engine.Observe(context.Background())
	if err != nil || hash != "same" || third == second {
		t.Fatal("failed apply kept continuity")
	}
	engine.generation = ^uint64(0)
	if engine.Apply(context.Background(), configpoc.Revision{Hash: "same"}) == nil {
		t.Fatal("epoch wrapped")
	}
	if _, _, _, err = engine.Observe(context.Background()); err == nil {
		t.Fatal("exhausted epoch observed")
	}
}
func TestCounterReadAndEpochCannotStraddleApply(t *testing.T) {
	entered, release, attempted := make(chan struct{}), make(chan struct{}), make(chan struct{})
	applied := make(chan struct{})
	backend := &epochTestEngine{hash: "old", applied: applied}
	engine := &counterEngine{run: strings.Repeat("a", 32), engine: backend, read: func(context.Context) (string, []firewallipc.Counter, error) {
		close(entered)
		<-release
		return backend.hash, []firewallipc.Counter{{ID: "a", Packets: 99}}, nil
	}}
	type result struct {
		hash, epoch string
		err         error
	}
	observed := make(chan result, 1)
	go func() {
		hash, _, epoch, err := engine.Observe(context.Background())
		observed <- result{hash, epoch, err}
	}()
	<-entered
	applyDone := make(chan error, 1)
	go func() {
		close(attempted)
		applyDone <- engine.Apply(context.Background(), configpoc.Revision{Hash: "new"})
	}()
	<-attempted
	select {
	case <-applied:
		t.Fatal("apply entered during raw read")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	r := <-observed
	if r.err != nil || r.hash != "old" || r.epoch != engine.run+".0" {
		t.Fatal("mixed read epoch", r)
	}
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	engine.read = func(context.Context) (string, []firewallipc.Counter, error) { return backend.hash, nil, nil }
	hash, _, epoch, err := engine.Observe(context.Background())
	if err != nil || hash != "new" || epoch != engine.run+".1" {
		t.Fatal("new epoch missing")
	}
}
func TestGuardianCompensationChangesCounterEpoch(t *testing.T) {
	s, initial, target := helperFixture(t)
	bootHelper(t, s, initial)
	before := sendHelper(t, s, 1, firewallipc.Message{Verb: "observe"})
	if before.CounterEpoch == "" {
		t.Fatal("missing epoch")
	}
	_ = sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "expires", Previous: initial, Revision: target, TTL: 500 * time.Millisecond})
	_ = sendHelper(t, s, 1, firewallipc.Message{Verb: "apply", Revision: target})
	active := sendHelper(t, s, 1, firewallipc.Message{Verb: "observe"})
	deadline := time.Now().Add(2 * time.Second)
	for s.guardian.Status().Phase != "expired" {
		if time.Now().After(deadline) {
			t.Fatal("expiration failed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	restored := sendHelper(t, s, 1, firewallipc.Message{Verb: "observe"})
	if restored.Hash != initial.Hash || restored.CounterEpoch == active.CounterEpoch || restored.CounterEpoch == before.CounterEpoch {
		t.Fatal("compensation epoch reused")
	}
}
