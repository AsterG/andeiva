package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

type authorityEngine struct {
	g *nftguardian.Guardian
	e *configpoc.SimEngine
}

func (a authorityEngine) Name() string { return "authority" }
func (a authorityEngine) Validate(c configpoc.Config) error {
	_, err := configpoc.Canonical(c)
	return err
}
func (a authorityEngine) Current() string { return a.e.Current() }
func (a authorityEngine) Apply(ctx context.Context, r configpoc.Revision) error {
	return a.g.Apply(ctx, r)
}

func TestDurableConfirmLostHelperAckCannotReviveExpiredTarget(t *testing.T) {
	ctx := context.Background()
	actor := configpoc.Principal{ID: "test", Role: configpoc.RoleAdmin}
	empty, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 1, DefaultAction: "deny"})
	target, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "fixture", Action: "allow"}}})
	e := configpoc.NewSimEngine("kernel")
	_ = e.Apply(ctx, empty)
	g := nftguardian.New(e)
	defer g.Close()
	dir := filepath.Join(t.TempDir(), "state")
	adapter := authorityEngine{g, e}
	s, err := configpoc.Open(dir, []configpoc.Engine{adapter}, configpoc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Execute(ctx, actor, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Execute(ctx, actor, configpoc.API, configpoc.Request{Operation: configpoc.OpStage, Key: "stage", ExpectedGeneration: r.Generation, Config: &target.Config})
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Arm("lease", empty, target, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	r, err = s.Execute(ctx, actor, configpoc.API, configpoc.Request{Operation: configpoc.OpCommit, Key: "commit", ExpectedGeneration: r.Generation, ConfirmFor: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Execute(ctx, actor, configpoc.API, configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: r.Generation, Target: target.Hash})
	if err != nil {
		t.Fatal(err)
	}
	// The durable confirm exists, but its authority acknowledgment never arrives.
	_ = s.Close()
	deadline := time.Now().Add(2 * time.Second)
	for e.Current() != empty.Hash && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if g.Confirm("lease", target.Hash) == nil {
		t.Fatal("late confirm succeeded")
	}
	reopened, err := configpoc.Open(dir, []configpoc.Engine{adapter}, configpoc.Options{})
	if err == nil {
		_ = reopened.Close()
		t.Fatal("ambiguous confirmed store reopened")
	}
	if e.Current() != empty.Hash {
		t.Fatal("expired target revived")
	}
}
