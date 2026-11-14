package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/nftpoc"
)

type authorityEngine struct {
	g *nftguardian.Guardian
	e *configpoc.SimEngine
}

// The helper stays in the parent while a new, unprivileged coordinator process
// opens the real journal through inherited pipes. No network calls are made.
func TestUncertainConfirmCoordinatorProcessRestart(t *testing.T) {
	if dir := os.Getenv("ANDEIVA_TEST_RESTART_DIR"); dir != "" {
		writer, reader := os.NewFile(3, "request"), os.NewFile(4, "response")
		defer writer.Close()
		defer reader.Close()
		ch := &channel{run: "restart", expectedNamespace: 42, out: writer, input: reader, in: scanner(reader)}
		svc, err := configpoc.Open(dir, []configpoc.Engine{&remoteEngine{ch}}, configpoc.Options{})
		if err == nil {
			_ = svc.Close()
			t.Fatal("uncertain durable confirm reopened")
		}
		return
	}
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-expiry", true: "after-expiry"}[expired], func(t *testing.T) {
			c, h, pending, dir := pendingControl(t)
			h.confirm = func(message) (reply, error) { return reply{}, errProtocol }
			if _, err := c.execute(context.Background(), testActor, configpoc.API, configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash}); err == nil {
				t.Fatal("confirm did not fail")
			}
			if err := c.svc.Close(); err != nil {
				t.Fatal(err)
			}
			if expired {
				deadline := time.Now().Add(7 * time.Second)
				for h.g.Status().Phase != "expired" && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if h.g.Status().Phase != "expired" {
					t.Fatal("lease did not expire")
				}
			}
			requestR, requestW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer requestR.Close()
			defer requestW.Close()
			responseR, responseW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer responseR.Close()
			defer responseW.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				s := scanner(requestR)
				for s.Scan() {
					var m message
					if decode(s.Bytes(), &m) != nil {
						return
					}
					r := reply{Run: m.Run, Sequence: m.Sequence, Namespace: 42}
					if a, err := nftpoc.Compile(m.Revision.Config); err == nil {
						r.Artifact = a.Digest
					}
					var err error
					switch m.Verb {
					case "apply":
						err = h.g.Apply(context.Background(), m.Revision)
					case "current":
						r.Hash = h.e.Current()
					case "validate":
						err = nil
					default:
						err = errProtocol
					}
					if err != nil {
						r.Error = err.Error()
					}
					r.State = h.g.Status()
					if json.NewEncoder(responseW).Encode(r) != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUncertainConfirmCoordinatorProcessRestart$")
			cmd.Env = append(os.Environ(), "ANDEIVA_TEST_RESTART_DIR="+dir)
			cmd.ExtraFiles = []*os.File{requestW, responseR}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = requestW.Close()
			_ = responseR.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatalf("restart process failed: %v", err)
			}
			<-done
			if expired && h.e.Current() != pending.Startup.Hash {
				t.Fatal("restart revived expired target")
			}
			if !expired && h.g.Status().Phase == "idle" {
				t.Fatal("restart cleared authority barrier")
			}
		})
	}
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
	if err = g.Arm("lease", empty, target, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	r, err = s.Execute(ctx, actor, configpoc.API, configpoc.Request{Operation: configpoc.OpCommit, Key: "commit", ExpectedGeneration: r.Generation, ConfirmFor: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Execute(ctx, actor, configpoc.API, configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: r.Generation, Target: target.Hash})
	if err != nil {
		t.Fatal(err)
	}
	// The durable confirm exists, but its authority acknowledgment never arrives.
	_ = s.Close()
	deadline := time.Now().Add(12 * time.Second)
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
