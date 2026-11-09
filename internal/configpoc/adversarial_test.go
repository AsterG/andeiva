package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestMalformedStateRejectedWithoutPanic(t *testing.T) {
	s, _, dir := fixture(t, Options{})
	_ = s.Close()
	path := filepath.Join(dir, "00000001.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record journalRecord
	if err = json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	record.State.Receipts = nil
	record.Hash = recordHash(record)
	data, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir, []Engine{NewSimEngine("one")}, Options{}); !errors.Is(err, ErrStorage) {
		t.Fatal("malformed store accepted")
	}
}

func TestFinalReceiptStorageAmbiguity(t *testing.T) {
	for _, point := range []string{"before_persist", "after_rename"} {
		t.Run(point, func(t *testing.T) {
			armed := false
			calls := 0
			s, engines, dir := fixture(t, Options{Hook: func(stage string) error {
				if armed && stage == point {
					calls++
					if calls == 2 {
						return errors.New("injected storage fault")
					}
				}
				return nil
			}})
			previous := status(t, s).Running.Hash
			c := sample("indeterminate")
			invoke(t, s, OpStage, &c, 0)
			before := status(t, s)
			request := Request{Operation: OpCommit, Key: "uncertain", ExpectedGeneration: before.Generation}
			armed = true
			if _, err := s.Execute(context.Background(), admin, API, request); !errors.Is(err, ErrStorage) {
				t.Fatal(err)
			}
			for _, engine := range engines {
				if engine.Current() != previous {
					t.Fatal("storage uncertainty left applied target")
				}
			}
			if _, err := s.Execute(context.Background(), admin, API, Request{Operation: OpStatus}); !errors.Is(err, ErrRecovery) {
				t.Fatal("uncertain coordinator remained usable")
			}
			_ = s.Close()
			s, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if point == "before_persist" {
				if status(t, s).Running.Hash != previous {
					t.Fatal("unpublished receipt committed")
				}
			} else {
				wanted, _ := Canonical(c)
				if status(t, s).Running.Hash != wanted.Hash {
					t.Fatal("published receipt not reconciled")
				}
				replayed, err := s.Execute(context.Background(), admin, API, request)
				if err != nil || replayed.ReplayedGeneration == 0 {
					t.Fatalf("indeterminate receipt missing: %v", err)
				}
			}
		})
	}
}

func TestCanceledApplyCompensatesIndependently(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	armed := false
	s, engines, _ := fixture(t, Options{Hook: func(point string) error {
		if armed && point == "after_apply:first" {
			cancel()
		}
		return nil
	}})
	previous := status(t, s).Running.Hash
	c := sample("canceled")
	invoke(t, s, OpStage, &c, 0)
	before := status(t, s)
	armed = true
	if _, err := s.Execute(ctx, admin, API, Request{Operation: OpCommit, Key: "canceled", ExpectedGeneration: before.Generation}); !errors.Is(err, ErrEngine) {
		t.Fatal(err)
	}
	for _, engine := range engines {
		if engine.Current() != previous {
			t.Fatal("canceled context prevented compensation")
		}
	}
}

type delayedEngine struct {
	*SimEngine
	enabled bool
}

func (engine *delayedEngine) Apply(ctx context.Context, r Revision) error {
	if engine.enabled {
		time.Sleep(40 * time.Millisecond)
	}
	return engine.SimEngine.Apply(ctx, r)
}
func TestApplyBeyondConfirmationDeadline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	engine := &delayedEngine{SimEngine: NewSimEngine("slow")}
	s, err := Open(filepath.Join(t.TempDir(), "state"), []Engine{engine}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	previous := status(t, s).Running.Hash
	c := sample("slow")
	invoke(t, s, OpStage, &c, 0)
	before := status(t, s)
	engine.enabled = true
	if _, err = s.Execute(context.Background(), admin, API, Request{Operation: OpCommit, Key: "slow", ExpectedGeneration: before.Generation, ConfirmFor: 20 * time.Millisecond}); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	if got := status(t, s); got.Pending != nil || got.Running.Hash != previous || engine.Current() != previous {
		t.Fatal("expired application remained active")
	}
}

func TestCandidateOwnershipAndActorBoundReplay(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	c := sample("private")
	stage := invoke(t, s, OpStage, &c, 0)
	other := Principal{ID: "bob", Role: RoleOperator}
	for _, operation := range []string{OpValidate, OpCommit} {
		if _, err := s.Execute(context.Background(), other, Web, Request{Operation: operation, Key: "alice-key", ExpectedGeneration: stage.Generation}); !errors.Is(err, ErrDenied) {
			t.Fatalf("foreign candidate: %v", err)
		}
	}
	req := Request{Operation: OpCommit, Key: "alice-key", ExpectedGeneration: stage.Generation}
	if _, err := s.Execute(context.Background(), admin, API, req); err != nil {
		t.Fatal(err)
	}
	if result, err := s.Execute(context.Background(), other, CLI, req); !errors.Is(err, ErrConflict) || result.ReplayedGeneration != 0 {
		t.Fatal("actor obtained another actor's receipt")
	}
}
