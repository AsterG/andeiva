package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func helperFixture(t *testing.T) (*helperSession, configpoc.Revision, configpoc.Revision) {
	t.Helper()
	initial, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	target, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "web", Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}})
	if err != nil {
		t.Fatal(err)
	}
	engine := configpoc.NewSimEngine("helper-test")
	guardian := nftguardian.NewRestricted(engine)
	t.Cleanup(func() { _ = guardian.Close() })
	return &helperSession{run: strings.Repeat("a", 32), namespace: 42, engine: engine, guardian: guardian, observe: func(context.Context) (string, []firewallipc.Counter, error) {
		return engine.Current(), []firewallipc.Counter{{ID: "web", Packets: 7, Bytes: 512}}, nil
	}}, initial, target
}
func sendHelper(t *testing.T, s *helperSession, epoch uint64, m firewallipc.Message) firewallipc.Reply {
	t.Helper()
	m.Run = s.run
	if epoch != s.epoch {
		m.Sequence = epoch<<32 | 1
	} else {
		m.Sequence = s.last + 1
	}
	r, err := s.handle(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func bootHelper(t *testing.T, s *helperSession, initial configpoc.Revision) {
	t.Helper()
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "bootstrap", Revision: initial}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "recovered"}); r.Error != "" {
		t.Fatal(r.Error)
	}
}
func TestHelperBootstrapLeaseAndReadback(t *testing.T) {
	s, initial, target := helperFixture(t)
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "recovered"}); r.Error == "" {
		t.Fatal("recovery before bootstrap accepted")
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "bootstrap", Revision: initial}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "commit-1", Previous: initial, Revision: target, TTL: 30 * time.Second}); r.Error == "" {
		t.Fatal("lease before recovery accepted")
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "recovered"}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "apply", Revision: target}); r.Error == "" {
		t.Fatal("unarmed apply accepted")
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "bootstrap", Revision: target}); r.Error == "" {
		t.Fatal("second bootstrap accepted")
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "commit-1", Previous: initial, Revision: target, TTL: 120 * time.Second}); r.Error != "" || r.Artifact == "" {
		t.Fatal("arm failed", r)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "apply", Revision: target}); r.Error != "" || r.State.Phase != "pending" {
		t.Fatal("apply failed", r)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "confirm", Lease: "wrong", Hash: target.Hash}); r.Error == "" {
		t.Fatal("wrong lease accepted")
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "confirm", Lease: "commit-1", Hash: target.Hash}); r.Error != "" || r.State.Phase != "idle" {
		t.Fatal("confirm failed", r)
	}
	r := sendHelper(t, s, 1, firewallipc.Message{Verb: "observe"})
	if r.Hash != target.Hash || len(r.Counters) != 1 || r.Counters[0].Packets != 7 {
		t.Fatal("readback lost", r)
	}
}
func TestHelperRestartCannotConfirmOrReapplyPendingTarget(t *testing.T) {
	s, initial, target := helperFixture(t)
	bootHelper(t, s, initial)
	_ = sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "commit-1", Previous: initial, Revision: target, TTL: 30 * time.Second})
	_ = sendHelper(t, s, 1, firewallipc.Message{Verb: "apply", Revision: target})
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "confirm", Lease: "commit-1", Hash: target.Hash}); r.Error == "" {
		t.Fatal("restart crossed confirmation barrier")
	}
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "apply", Revision: target}); r.Error == "" {
		t.Fatal("pending target replay accepted")
	}
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "recovered"}); r.Error == "" {
		t.Fatal("recovery without previous policy accepted")
	}
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "apply", Revision: initial}); r.Error != "" || r.State.Phase != "expired" {
		t.Fatal("restore failed", r)
	}
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "recovered"}); r.Error != "" || r.State.Phase != "idle" {
		t.Fatal("recovery failed", r)
	}
	if s.engine.Current() != initial.Hash {
		t.Fatal("previous revision not effective")
	}
}
func TestHelperProtocolRejectsUntrustedFields(t *testing.T) {
	for _, kind := range []string{"wrong-run", "replay", "gap", "old-epoch", "epoch-gap", "ttl", "extra", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			s, initial, target := helperFixture(t)
			bootHelper(t, s, initial)
			m := firewallipc.Message{Run: s.run, Sequence: s.last + 1, Verb: "state"}
			switch kind {
			case "wrong-run":
				m.Run = strings.Repeat("b", 32)
			case "replay":
				m.Sequence = s.last
			case "gap":
				m.Sequence = s.last + 2
			case "old-epoch":
				m.Sequence = 1
			case "epoch-gap":
				m.Sequence = 2<<32 | 2
			case "ttl":
				m.Verb = "arm"
				m.Previous = initial
				m.Revision = target
				m.Lease = "lease"
				m.TTL = 121 * time.Second
			case "extra":
				m.Hash = initial.Hash
			case "unknown":
				m.Verb = "shell"
			}
			if _, err := s.handle(context.Background(), m); err == nil {
				t.Fatal("invalid frame accepted")
			}
			if s.engine.Current() != initial.Hash {
				t.Fatal("invalid frame changed policy")
			}
		})
	}
}
func TestHelperStreamBoundsAndErrors(t *testing.T) {
	for _, input := range []string{`{"run":"a","run":"b"}`, strings.Repeat("x", firewallipc.MaxFrame+1), `{"role":"admin"}`} {
		s, _, _ := helperFixture(t)
		var out bytes.Buffer
		if err := s.serve(strings.NewReader(input), &out); !errors.Is(err, errHelper) || out.Len() != 0 {
			t.Fatal("malformed input accepted")
		}
	}
	s, _, _ := helperFixture(t)
	var input, out bytes.Buffer
	if err := json.NewEncoder(&input).Encode(firewallipc.Message{Run: s.run, Sequence: 1<<32 | 1, Verb: "state"}); err != nil {
		t.Fatal(err)
	}
	if err := s.serve(&input, &out); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	var reply firewallipc.Reply
	if json.Unmarshal(out.Bytes(), &reply) != nil || reply.Namespace != 42 || reply.State.Phase != "bootstrap" {
		t.Fatal("invalid state reply")
	}
	s.observe = func(context.Context) (string, []firewallipc.Counter, error) {
		return "private", nil, errors.New("private engine path")
	}
	r := sendHelper(t, s, 1, firewallipc.Message{Verb: "observe"})
	if r.Error != errHelper.Error() || r.Hash != "" {
		t.Fatal("internal error exposed")
	}
}
func TestHelperPrivilegeAndOutputBounds(t *testing.T) {
	for _, network := range []bool{false, true} {
		mask := "0000000000000000"
		if network {
			mask = "0000000000001000"
		}
		status := "NoNewPrivs:\t1\n"
		for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			status += key + ":\t" + mask + "\n"
		}
		if err := privilegeFields(status, network); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"", status + "CapEff:\t" + mask + "\n", strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(status, "CapEff:\t"+mask, "CapEff:\t0000000000003000", 1)} {
			if privilegeFields(bad, network) == nil {
				t.Fatal("unexpected privilege accepted")
			}
		}
	}
	var output helperOutput
	if _, err := output.Write(make([]byte, 512<<10)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("x")); err == nil {
		t.Fatal("output limit missing")
	}
	if bindParent("0") == nil || bindParent("not-a-pid") == nil {
		t.Fatal("invalid parent accepted")
	}
	if _, err := (helperTransport{}).execute(context.Background(), nil, "apply"); err == nil {
		t.Fatal("unbound namespace accepted")
	}
}

func TestHelperExpiredLeaseOnlyRearmsKnownPrevious(t *testing.T) {
	s, initial, target := helperFixture(t)
	bootHelper(t, s, initial)
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "expires", Previous: initial, Revision: target, TTL: 500 * time.Millisecond}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "apply", Revision: target}); r.Error != "" {
		t.Fatal(r.Error)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.guardian.Status().Phase != "expired" {
		if time.Now().After(deadline) {
			t.Fatal("lease failed to expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "wrong-previous", Previous: target, Revision: initial, TTL: 30 * time.Second}); r.Error == "" {
		t.Fatal("unverified previous accepted")
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "rearmed", Previous: initial, Revision: target, TTL: 30 * time.Second}); r.Error != "" || r.State.Phase != "armed" {
		t.Fatal("known previous could not rearm", r)
	}
}

func TestHelperCoreThirtySecondCommitIntegration(t *testing.T) {
	s, initial, target := helperFixture(t)
	client := connectHelperForTest(t, s, 1)
	core, err := configpoc.Open(filepath.Join(t.TempDir(), "state"), []configpoc.Engine{client}, configpoc.Options{Initial: &initial.Config})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Recovered(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := firewalladmin.New(core, firewallipc.Authority{Client: client})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	p := configpoc.Principal{ID: "alice", Role: configpoc.RoleAdmin}
	state, err := service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
	if err != nil {
		t.Fatal(err)
	}
	state, err = service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpStage, Key: "stage", ExpectedGeneration: state.Generation, Config: &target.Config})
	if err != nil {
		t.Fatal(err)
	}
	state, err = service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpCommit, Key: "commit", ExpectedGeneration: state.Generation, ConfirmFor: 30 * time.Second})
	if err != nil {
		t.Fatal("exact 30-second commit rejected", err)
	}
	if state.Pending == nil || s.guardian.Status().Phase != "pending" {
		t.Fatal("confirmation window missing")
	}
	state, err = service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: state.Generation, Target: target.Hash})
	if err != nil {
		t.Fatal(err)
	}
	if state.Pending != nil || s.guardian.Status().Phase != "idle" {
		t.Fatal("confirmed policy not published")
	}
}

func connectHelperForTest(t *testing.T, s *helperSession, epoch uint64) *firewallipc.Client {
	t.Helper()
	requestR, requestW := io.Pipe()
	responseR, responseW := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.serve(requestR, responseW)
		_ = responseW.Close()
		_ = requestR.Close()
	}()
	client, err := firewallipc.New(responseR, requestW, s.run, epoch<<32, s.namespace, artifactDigest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("helper channel leaked")
		}
	})
	return client
}

func TestHelperRestartReconcilesNoopPendingLease(t *testing.T) {
	s, initial, target := helperFixture(t)
	bootHelper(t, s, initial)
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "arm", Lease: "noop", Previous: initial, Revision: initial, TTL: 30 * time.Second}); r.Error != "" {
		t.Fatal(r.Error)
	}
	if r := sendHelper(t, s, 1, firewallipc.Message{Verb: "apply", Revision: initial}); r.Error != "" || r.State.Phase != "pending" {
		t.Fatal("no-op pending setup failed", r)
	}
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "apply", Revision: initial}); r.Error != "" {
		t.Fatal("no-op restart recovery failed", r)
	}
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "recovered"}); r.Error != "" || r.State.Phase != "idle" {
		t.Fatal("no-op lease not cleared", r)
	}
	if r := sendHelper(t, s, 2, firewallipc.Message{Verb: "arm", Lease: "next", Previous: initial, Revision: target, TTL: 30 * time.Second}); r.Error != "" {
		t.Fatal("no-op recovery left authority blocked", r)
	}
}

func TestHelperConfirmedJournalFailureAndRestart(t *testing.T) {
	for _, operation := range []string{"commit", "confirm"} {
		for _, point := range []string{"before_persist", "after_rename"} {
			t.Run(operation+"/"+point, func(t *testing.T) {
				s, initial, target := helperFixture(t)
				client := connectHelperForTest(t, s, 1)
				dir := filepath.Join(t.TempDir(), "state")
				fired := false
				hook := func(at string) error {
					state := s.guardian.Status()
					if !fired && at == point && state.Phase == "idle" && state.ID == "commit" && state.Target == target.Hash && s.engine.Current() == target.Hash {
						fired = true
						return configpoc.ErrStorage
					}
					return nil
				}
				core, err := configpoc.Open(dir, []configpoc.Engine{client}, configpoc.Options{Initial: &initial.Config, Hook: hook})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = core.Close() })
				if err = client.Recovered(context.Background()); err != nil {
					t.Fatal(err)
				}
				service, err := firewalladmin.New(core, firewallipc.Authority{Client: client})
				if err != nil {
					t.Fatal(err)
				}
				p := configpoc.Principal{ID: "alice", Role: configpoc.RoleAdmin}
				state, err := service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
				if err != nil {
					t.Fatal(err)
				}
				state, err = service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpStage, Key: "stage", ExpectedGeneration: state.Generation, Config: &target.Config})
				if err != nil {
					t.Fatal(err)
				}
				request := configpoc.Request{Operation: configpoc.OpCommit, Key: "commit", ExpectedGeneration: state.Generation}
				if operation == "confirm" {
					request.ConfirmFor = 30 * time.Second
				}
				state, err = service.Execute(context.Background(), p, configpoc.API, request)
				if operation == "confirm" {
					if err != nil {
						t.Fatal(err)
					}
					_, err = service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpConfirm, Key: "confirm", ExpectedGeneration: state.Generation, Target: target.Hash})
				}
				if !fired || !errors.Is(err, configpoc.ErrStorage) {
					t.Fatal("missed post-helper-confirm storage failure", fired, err)
				}
				if s.engine.Current() != initial.Hash {
					t.Fatal("failed durable publication left target effective")
				}
				if _, err = service.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpSave, Key: "must-not-save", ExpectedGeneration: state.Generation}); !errors.Is(err, configpoc.ErrRecovery) {
					t.Fatal("halted coordinator accepted write", err)
				}
				if err = service.Close(); err != nil {
					t.Fatal(err)
				}
				if err = client.Close(); err != nil {
					t.Fatal(err)
				}
				restarted := connectHelperForTest(t, s, 2)
				reopened, err := configpoc.Open(dir, []configpoc.Engine{restarted}, configpoc.Options{})
				if point == "after_rename" {
					// The confirmed record exists, but compensation restored previous.
					// Resuming must fail closed instead of silently reactivating target.
					if err == nil {
						_ = reopened.Close()
						t.Fatal("uncertain publication reactivated without a lease")
					}
					if s.engine.Current() != initial.Hash {
						t.Fatal("failed restart changed effective policy")
					}
					return
				}
				if err != nil {
					t.Fatal("durable previous revision did not recover", err)
				}
				t.Cleanup(func() { _ = reopened.Close() })
				if err = restarted.Recovered(context.Background()); err != nil {
					t.Fatal(err)
				}
				state, err = reopened.Execute(context.Background(), p, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
				if err != nil || state.Running.Hash != initial.Hash || state.Startup.Hash != initial.Hash || state.Pending != nil || state.RecoveryRequired {
					t.Fatal("unsafe recovered state", state, err)
				}
			})
		}
	}
}
