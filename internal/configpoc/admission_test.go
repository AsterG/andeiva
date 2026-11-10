package configpoc

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

type admissionEngine struct {
	*SimEngine
	reads   atomic.Int64
	applies atomic.Int64
}

func (e *admissionEngine) Current() string { e.reads.Add(1); return e.SimEngine.Current() }
func (e *admissionEngine) Apply(ctx context.Context, r Revision) error {
	e.applies.Add(1)
	return e.SimEngine.Apply(ctx, r)
}

type admissionGuard struct {
	testGuard
	checks int
	check  func(Request, Snapshot, *Revision) error
}

func (g *admissionGuard) Check(r Request, s Snapshot, target *Revision) error {
	g.checks++
	return g.check(r, s, target)
}

func TestAdmissionCopiesPreflightAndDurableReplay(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("durable journal requires Linux")
	}
	dir := filepath.Join(t.TempDir(), "state")
	e := &admissionEngine{SimEngine: NewSimEngine("admission")}
	s, err := Open(dir, []Engine{e}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	c := sample("candidate")
	initial := status(t, s)
	r := Request{Operation: OpStage, Key: "admit-stage", ExpectedGeneration: initial.Generation, Config: &c}
	g := &admissionGuard{check: func(r Request, snap Snapshot, target *Revision) error {
		if target != nil {
			t.Fatal("non-rollback target")
		}
		r.Config.Rules[0].ID = "mutated-request"
		snap.Running.Config.DefaultAction = "allow"
		return ErrDenied
	}}
	reads, applies := e.reads.Load(), e.applies.Load()
	_, err = s.ExecuteManaged(context.Background(), admin, API, r, g)
	if !errors.Is(err, ErrDenied) || reads != e.reads.Load() || applies != e.applies.Load() {
		t.Fatalf("admission touched engine: %v", err)
	}
	if c.Rules[0].ID != "candidate" || status(t, s).Running.Config.DefaultAction != "deny" {
		t.Fatal("admission aliases core/caller data")
	}
	for _, bad := range []Request{{Operation: OpStage, Key: "stale", ExpectedGeneration: 0, Config: &c}, {Operation: OpStage, Key: "invalid", ExpectedGeneration: initial.Generation}} {
		checks := g.checks
		_, err = s.ExecuteManaged(context.Background(), admin, API, bad, g)
		if err == nil || g.checks != checks {
			t.Fatal("invalid request reached admission")
		}
	}
	checks := g.checks
	_, err = s.ExecuteManaged(context.Background(), Principal{ID: "viewer", Role: RoleViewer}, API, r, g)
	if !errors.Is(err, ErrDenied) || g.checks != checks {
		t.Fatal("unauthorized admission")
	}
	g.check = func(Request, Snapshot, *Revision) error { return nil }
	out, err := s.ExecuteManaged(context.Background(), admin, API, r, g)
	if err != nil {
		t.Fatal(err)
	}
	checks = g.checks
	g.check = func(Request, Snapshot, *Revision) error { return ErrDenied }
	if replay, err := s.ExecuteManaged(context.Background(), admin, API, r, g); err != nil || replay.ReplayedGeneration != out.Generation || g.checks != checks {
		t.Fatalf("replay re-admitted: %v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, []Engine{e}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := s.ExecuteManaged(context.Background(), admin, API, r, g); err != nil || replay.ReplayedGeneration != out.Generation || g.checks != checks {
		t.Fatalf("durable replay re-admitted: %v", err)
	}
}

func TestAdmissionHistoricalTargetIsResolvedAndDetached(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	previous := status(t, s).Running
	c := sample("changed")
	invoke(t, s, OpStage, &c, 0)
	snap := invoke(t, s, OpCommit, nil, 0)
	g := &admissionGuard{check: func(r Request, snap Snapshot, target *Revision) error {
		if target == nil || target.Hash != previous.Hash || r.Target != previous.Hash {
			t.Fatal("historical target unavailable")
		}
		target.Config.DefaultAction = "allow"
		snap.Running.Config.Rules[0].ID = "corrupt"
		return ErrDenied
	}}
	_, err := s.ExecuteManaged(context.Background(), admin, API, Request{Operation: OpRollback, Key: "rollback-admission", ExpectedGeneration: snap.Generation, Target: previous.Hash}, g)
	if !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	stored, ok := s.historical(previous.Hash)
	if !ok || stored.Config.DefaultAction != "deny" || status(t, s).Running.Config.Rules[0].ID != "changed" {
		t.Fatal("historical or snapshot alias")
	}
}
