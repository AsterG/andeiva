package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/nftpoc"
)

type testHelper struct {
	g         *nftguardian.Guardian
	e         *configpoc.SimEngine
	confirm   func(message) (reply, error)
	authority func() (reply, error)
}

func (h *testHelper) call(m message) (reply, error) {
	var err error
	switch m.Verb {
	case "arm":
		err = h.g.Arm(m.Lease, m.Previous, m.Revision, m.TTL)
	case "confirm":
		if h.confirm != nil {
			return h.confirm(m)
		}
		err = h.g.Confirm(m.Lease, m.Revision.Hash)
	case "authority":
		if h.authority != nil {
			return h.authority()
		}
	case "current":
		return reply{Hash: h.e.Current()}, nil
	default:
		return reply{}, errProtocol
	}
	return reply{State: h.g.Status()}, err
}

var testActor = configpoc.Principal{ID: "test", Role: configpoc.RoleAdmin}

func pendingControl(t *testing.T) (*coordination, *testHelper, configpoc.Snapshot, string) {
	t.Helper()
	e := configpoc.NewSimEngine("kernel")
	g := nftguardian.New(e)
	t.Cleanup(func() { _ = g.Close() })
	engine := authorityEngine{g, e}
	dir := filepath.Join(t.TempDir(), "state")
	svc, err := configpoc.Open(dir, []configpoc.Engine{engine}, configpoc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	h := &testHelper{g: g, e: e}
	c := &coordination{svc: svc, helper: h, engine: engine}
	snap, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if err != nil {
		t.Fatal(err)
	}
	cfg := nftpoc.FixtureConfig(true, false, false, false)
	snap, err = c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpStage, Key: "stage", ExpectedGeneration: snap.Generation, Config: &cfg})
	if err != nil {
		t.Fatal(err)
	}
	snap, err = c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpCommit, Key: "lease", ExpectedGeneration: snap.Generation, ConfirmFor: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c, h, snap, dir
}

func TestUncertainConfirmBlocksEveryMutationAndPreservesStartup(t *testing.T) {
	for _, mode := range []string{"pending", "unreachable", "wrong-receipt", "wrong-current", "false-success"} {
		t.Run(mode, func(t *testing.T) {
			c, h, pending, _ := pendingControl(t)
			h.confirm = func(m message) (reply, error) {
				if mode == "false-success" {
					return reply{}, nil
				}
				return reply{}, errProtocol
			}
			if mode == "unreachable" {
				h.authority = func() (reply, error) { return reply{}, errProtocol }
			}
			if mode == "wrong-receipt" || mode == "wrong-current" {
				h.authority = func() (reply, error) {
					state := nftguardian.State{Phase: "idle", ID: "other", Target: pending.Running.Hash}
					if mode == "wrong-current" {
						state.ID = "lease"
						_ = h.e.Apply(context.Background(), pending.Startup)
					}
					return reply{State: state}, nil
				}
			}
			snap, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash})
			if err == nil || !snap.RecoveryRequired {
				t.Fatal("uncertain confirm was published")
			}
			var wg sync.WaitGroup
			for i, op := range []string{configpoc.OpSave, configpoc.OpSave, configpoc.OpCommit, configpoc.OpStage, configpoc.OpConfirm, configpoc.OpRecover, configpoc.OpRevoke, configpoc.OpValidate} {
				wg.Add(1)
				go func(i int, op string) {
					defer wg.Done()
					result, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: op, Key: fmt.Sprintf("blocked-%d", i), ExpectedGeneration: snap.Generation})
					if !errors.Is(err, configpoc.ErrRecovery) || !result.RecoveryRequired {
						t.Errorf("%s bypassed uncertainty: %v", op, err)
					}
				}(i, op)
			}
			wg.Wait()
			status, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
			if err != nil || !status.RecoveryRequired || status.Startup.Hash != pending.Startup.Hash {
				t.Fatal("startup or blocker changed")
			}
			history, err := c.svc.History(testActor)
			if err != nil {
				t.Fatal(err)
			}
			confirmedJournal := false
			for _, entry := range history {
				if entry.Operation == configpoc.OpSave && entry.Result == "ok" {
					t.Fatal("blocked save published a receipt")
				}
				confirmedJournal = confirmedJournal || entry.Operation == configpoc.OpConfirm && entry.Result == "ok"
			}
			if !confirmedJournal {
				t.Fatal("test did not reach durable confirm boundary")
			}
		})
	}
}

func TestLostConfirmAckReconcilesOnlyExactEffectiveReceipt(t *testing.T) {
	c, h, pending, _ := pendingControl(t)
	h.confirm = func(m message) (reply, error) {
		if err := h.g.Confirm(m.Lease, m.Revision.Hash); err != nil {
			return reply{}, err
		}
		return reply{}, errProtocol
	}
	request := configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash}
	confirmed, err := c.execute(context.Background(), testActor, configpoc.API, request)
	if err != nil || confirmed.RecoveryRequired {
		t.Fatalf("exact receipt did not reconcile: %v", err)
	}
	if _, err = c.execute(context.Background(), testActor, configpoc.API, request); err != nil {
		t.Fatalf("confirmed retry failed: %v", err)
	}
	saved, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpSave, Key: "save", ExpectedGeneration: confirmed.Generation})
	if err != nil || saved.Startup.Hash != pending.Running.Hash {
		t.Fatalf("confirmed save failed: %v", err)
	}
}

func TestConcurrentSaveWaitsForConfirmationOutcome(t *testing.T) {
	c, h, pending, _ := pendingControl(t)
	entered, release := make(chan struct{}), make(chan struct{})
	h.confirm = func(message) (reply, error) { close(entered); <-release; return reply{}, errProtocol }
	confirmation := make(chan error, 1)
	go func() {
		_, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash})
		confirmation <- err
	}()
	<-entered
	save := make(chan error, 1)
	go func() {
		_, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpSave, Key: "save", ExpectedGeneration: pending.Generation + 1})
		save <- err
	}()
	close(release)
	if <-confirmation == nil || !errors.Is(<-save, configpoc.ErrRecovery) {
		t.Fatal("concurrent save crossed confirmation boundary")
	}
}
