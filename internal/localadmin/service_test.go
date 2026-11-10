package localadmin

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

// memoryRuntime is only a unit-test double, not effective-kernel evidence.
type memoryRuntime struct {
	mu                                                 sync.Mutex
	revision                                           configpoc.Revision
	lease                                              firewalladmin.LeaseState
	reads, applies, arms, confirms                     int
	armError, confirmError, badReceipt, badObservation bool
	onApply                                            func()
}

func (m *memoryRuntime) Name() string { return "local-test" }
func (m *memoryRuntime) Validate(c configpoc.Config) error {
	_, err := configpoc.Canonical(c)
	return err
}
func (m *memoryRuntime) Apply(_ context.Context, r configpoc.Revision) error {
	m.mu.Lock()
	m.revision = copyValue(r)
	m.applies++
	hook := m.onApply
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil
}
func (m *memoryRuntime) Current() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	return m.revision.Hash
}

type authority struct{ m *memoryRuntime }

func (a authority) Current(context.Context) (string, error) { return a.m.Current(), nil }
func (a authority) State(context.Context) (firewalladmin.LeaseState, error) {
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	a.m.reads++
	return a.m.lease, nil
}
func (a authority) Arm(_ context.Context, id string, p, r configpoc.Revision, ttl time.Duration) error {
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	a.m.arms++
	a.m.lease = firewalladmin.LeaseState{Phase: "armed", ID: id, Previous: p.Hash, Target: r.Hash, Deadline: time.Now().Add(ttl)}
	if a.m.badReceipt {
		a.m.lease.Deadline = time.Now().Add(time.Hour)
	}
	if a.m.armError {
		return errors.New("unknown outcome")
	}
	return nil
}
func (a authority) Confirm(_ context.Context, id, hash string) error {
	a.m.mu.Lock()
	defer a.m.mu.Unlock()
	a.m.confirms++
	a.m.lease.Phase = "idle"
	a.m.lease.ID = id
	a.m.lease.Target = hash
	if a.m.badReceipt {
		a.m.lease.Target = strings.Repeat("f", 64)
	}
	if a.m.confirmError {
		return errors.New("lost acknowledgement")
	}
	return nil
}
func (m *memoryRuntime) Observe(context.Context) (ObservedState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reads++
	if m.badObservation {
		return ObservedState{}, errors.New("collector unavailable")
	}
	o := ObservedState{Hash: m.revision.Hash}
	if m.revision.Config.LocalServices != nil {
		a, err := localpolicy.Compile(*m.revision.Config.LocalServices)
		if err != nil {
			return o, err
		}
		o.Local = localpolicy.Observation{Revision: a.Revision.Hash, Rules: a.Rules, Listeners: expectedListeners(m.revision.Config)}
	}
	return o, nil
}
func (m *memoryRuntime) counts() [4]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return [4]int{m.reads, m.applies, m.arms, m.confirms}
}
func inventory() []localpolicy.Interface {
	return []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1", "2001:db8::1"}}}
}
func policy(t *testing.T, enabled bool) configpoc.Config {
	t.Helper()
	i := inventory()[0]
	s, err := localpolicy.DefaultManagement("management", "https", i, i.Addresses[0], []string{"198.18.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	s.Endpoints = []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: 18443, LastPort: 18443}}
	s.Enabled = enabled
	return configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: inventory(), Services: []localpolicy.Service{s}}}
}
func actor() Context {
	return Context{Principal: configpoc.Principal{ID: "alice", Role: configpoc.RoleAdmin}, Surface: configpoc.API, SessionHash: strings.Repeat("a", 64), EndpointID: "recovery"}
}

type fixture struct {
	s   *Service
	m   *memoryRuntime
	dir string
	t   *testing.T
	key int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("durable coordinator requires Linux")
	}
	m := &memoryRuntime{lease: firewalladmin.LeaseState{Phase: "idle"}}
	dir := filepath.Join(t.TempDir(), "state")
	c := policy(t, false)
	core, err := configpoc.Open(dir, []configpoc.Engine{m}, configpoc.Options{Initial: &c})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(core, Options{RunID: strings.Repeat("a", 32), RecoveryEndpointID: "recovery", Inventory: inventory(), Authority: authority{m}, Observer: m})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{s: s, m: m, dir: dir, t: t}
	t.Cleanup(func() {
		if err := f.s.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}
func (f *fixture) snapshot() configpoc.Snapshot {
	f.t.Helper()
	s, err := f.s.Status(context.Background(), actor())
	if err != nil {
		f.t.Fatal(err)
	}
	return s.Snapshot
}
func (f *fixture) request(op string) Request {
	f.key++
	return Request{Transaction: configpoc.Request{Operation: op, Key: fmt.Sprintf("request-%d", f.key), ExpectedGeneration: f.snapshot().Generation}}
}
func (f *fixture) execute(r Request) configpoc.Snapshot {
	f.t.Helper()
	s, err := f.s.Execute(context.Background(), actor(), r)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}
func (f *fixture) stage(enabled bool) configpoc.Snapshot {
	r := f.request(configpoc.OpStage)
	c := policy(f.t, enabled)
	r.Transaction.Config = &c
	return f.execute(r)
}
func (f *fixture) proof(c Context, r Request, target string, lease string) string {
	f.t.Helper()
	p, err := f.s.IssueProof(c, ProofRequest{Generation: r.Transaction.ExpectedGeneration, Target: target, Lease: lease})
	if err != nil {
		f.t.Fatal(err)
	}
	return p.Token
}
func (f *fixture) commit() (Request, configpoc.Snapshot) {
	f.stage(true)
	f.execute(f.request(configpoc.OpValidate))
	snap := f.snapshot()
	r := f.request(configpoc.OpCommit)
	r.Transaction.ConfirmFor = 30 * time.Second
	r.RecoveryProof = f.proof(actor(), r, snap.Candidate.Revision.Hash, r.Transaction.Key)
	return r, f.execute(r)
}
func (f *fixture) confirm(snap configpoc.Snapshot) Request {
	r := f.request(configpoc.OpConfirm)
	r.Transaction.Target = snap.Running.Hash
	r.RecoveryProof = f.proof(actor(), r, snap.Running.Hash, snap.Pending.Lease)
	for _, l := range expectedListeners(snap.Running.Config) {
		c := actor()
		c.EndpointID = BindingEndpointID(l)
		c.ActivationHash = snap.Running.Hash
		c.SessionHash = strings.Repeat("b", 64)
		r.EndpointProofs = append(r.EndpointProofs, f.proof(c, r, snap.Running.Hash, snap.Pending.Lease))
	}
	return r
}

func TestLifecycleProofsReplayAndReopen(t *testing.T) {
	f := newFixture(t)
	commit, pending := f.commit()
	if pending.Pending == nil {
		t.Fatal("missing lease")
	}
	confirm := f.confirm(pending)
	confirmed := f.execute(confirm)
	if confirmed.Pending != nil {
		t.Fatal("pending after confirm")
	}
	save := f.request(configpoc.OpSave)
	save.RecoveryProof = f.proof(actor(), save, confirmed.Running.Hash, save.Transaction.Key)
	saved := f.execute(save)
	if saved.Startup.Hash != confirmed.Running.Hash {
		t.Fatal("save mismatch")
	}
	before := f.m.counts()
	commit.RecoveryProof = ""
	confirm.RecoveryProof = ""
	confirm.EndpointProofs = nil
	for _, r := range []Request{commit, confirm, save} {
		if f.execute(r).ReplayedGeneration == 0 {
			t.Fatal("missing replay")
		}
	}
	after := f.m.counts()
	if before[1] != after[1] || before[2] != after[2] || before[3] != after[3] {
		t.Fatal("replayed mutation")
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	core, err := configpoc.Open(f.dir, []configpoc.Engine{f.m}, configpoc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = New(core, Options{RunID: strings.Repeat("b", 32), RecoveryEndpointID: "recovery", Inventory: inventory(), Authority: authority{f.m}, Observer: f.m})
	if err != nil {
		t.Fatal(err)
	}
	before = f.m.counts()
	if f.execute(commit).ReplayedGeneration == 0 {
		t.Fatal("durable replay lost")
	}
	after = f.m.counts()
	if before[1] != after[1] || before[2] != after[2] || before[3] != after[3] {
		t.Fatal("durable replay mutated")
	}
}

func TestProofDenialsPrecedeEveryEngineCallAndDoNotLatch(t *testing.T) {
	for _, name := range []string{"missing", "expired", "session", "actor", "target", "generation", "lease", "endpoint", "run"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			snap := f.stage(true)
			r := f.request(configpoc.OpCommit)
			r.Transaction.ConfirmFor = 30 * time.Second
			c := actor()
			pr := ProofRequest{Generation: r.Transaction.ExpectedGeneration, Target: snap.Candidate.Revision.Hash, Lease: r.Transaction.Key}
			switch name {
			case "session":
				c.SessionHash = strings.Repeat("b", 64)
			case "actor":
				c.Principal.ID = "bob"
			case "target":
				pr.Target = strings.Repeat("f", 64)
			case "generation":
				pr.Generation++
			case "lease":
				pr.Lease = "different"
			case "endpoint":
				c.EndpointID = BindingEndpointID(expectedListeners(snap.Candidate.Revision.Config)[0])
			}
			p, err := f.s.IssueProof(c, pr)
			if err != nil && name != "endpoint" {
				t.Fatal(err)
			}
			r.RecoveryProof = p.Token
			switch name {
			case "missing":
				r.RecoveryProof = ""
			case "expired":
				f.s.proofs.now = func() time.Time { return p.ExpiresAt }
			case "run":
				f.s.proofs.runID = strings.Repeat("b", 32)
			}
			before := f.m.counts()
			_, err = f.s.Execute(context.Background(), actor(), r)
			if !errors.Is(err, configpoc.ErrDenied) {
				t.Fatalf("denial %v", err)
			}
			if f.m.counts() != before {
				t.Fatal("denial touched engine/authority")
			}
			if f.s.blocked {
				t.Fatal("invalid proof latched")
			}
			f.s.proofs.now = time.Now
			f.s.proofs.runID = f.s.options.RunID
			r.RecoveryProof = f.proof(actor(), r, snap.Candidate.Revision.Hash, r.Transaction.Key)
			f.execute(r)
		})
	}
}

func TestConfirmNeedsAllAuthenticatedBindingsAndSaveCannotUndoPending(t *testing.T) {
	f := newFixture(t)
	stage := f.request(configpoc.OpStage)
	c := policy(t, true)
	c.LocalServices.Services[0].Bindings = append(c.LocalServices.Services[0].Bindings, localpolicy.Binding{Interface: "lan0", Zone: localpolicy.LAN, LocalAddress: "2001:db8::1", Sources: []string{"2001:db8::2/128"}})
	stage.Transaction.Config = &c
	staged := f.execute(stage)
	commit := f.request(configpoc.OpCommit)
	commit.Transaction.ConfirmFor = 30 * time.Second
	commit.RecoveryProof = f.proof(actor(), commit, staged.Candidate.Revision.Hash, commit.Transaction.Key)
	pending := f.execute(commit)
	r := f.confirm(pending)
	good := r.EndpointProofs
	r.EndpointProofs = good[:1]
	before := f.m.counts()
	_, err := f.s.Execute(context.Background(), actor(), r)
	if !errors.Is(err, configpoc.ErrDenied) || before != f.m.counts() {
		t.Fatalf("missing endpoint proof: %v", err)
	}
	r.EndpointProofs = []string{good[0], good[0]}
	before = f.m.counts()
	_, err = f.s.Execute(context.Background(), actor(), r)
	if !errors.Is(err, configpoc.ErrDenied) || before != f.m.counts() {
		t.Fatal("duplicate binding proof accepted")
	}
	save := f.request(configpoc.OpSave)
	before = f.m.counts()
	_, err = f.s.Execute(context.Background(), actor(), save)
	if !errors.Is(err, configpoc.ErrPending) || before != f.m.counts() {
		t.Fatalf("save during pending: %v", err)
	}
	r.EndpointProofs = good
	f.execute(r)
	f.stage(false)
	snap := f.snapshot()
	disable := f.request(configpoc.OpCommit)
	disable.Transaction.ConfirmFor = 30 * time.Second
	disable.RecoveryProof = f.proof(actor(), disable, snap.Candidate.Revision.Hash, disable.Transaction.Key)
	pending = f.execute(disable)
	confirmed := f.execute(f.confirm(pending))
	if confirmed.Pending != nil {
		t.Fatal("disable not confirmed")
	}
}

func TestProfilesRejectedBeforeEngineCalls(t *testing.T) {
	for _, name := range []string{"default_allow", "legacy_allow", "inventory", "owner", "id", "low_port", "forward"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			r := f.request(configpoc.OpStage)
			c := policy(t, true)
			switch name {
			case "default_allow":
				c.DefaultAction = "allow"
			case "legacy_allow":
				c = configpoc.Config{SchemaVersion: 2, DefaultAction: "allow"}
			case "inventory":
				c.LocalServices.Interfaces[0].Addresses = append(c.LocalServices.Interfaces[0].Addresses, "198.18.0.9")
			case "owner":
				c.LocalServices.Services[0].Owner = "other"
			case "id":
				c.LocalServices.Services[0].ID = "api"
			case "low_port":
				c.LocalServices.Services[0].Endpoints[0] = localpolicy.Endpoint{Protocol: localpolicy.TCP, FirstPort: 443, LastPort: 443}
			case "forward":
				c.SchemaVersion = 1
				c.LocalServices = nil
				c.Rules = []configpoc.Rule{{ID: "forward", Action: "allow"}}
			}
			r.Transaction.Config = &c
			before := f.m.counts()
			_, err := f.s.Execute(context.Background(), actor(), r)
			if !errors.Is(err, configpoc.ErrInvalid) || before != f.m.counts() {
				t.Fatalf("profile accepted or engine touched: %v", err)
			}
		})
	}
}

func TestReadbackUnavailableAndUncertainOutcomes(t *testing.T) {
	f := newFixture(t)
	_, pending := f.commit()
	r := f.confirm(pending)
	f.m.badObservation = true
	status, err := f.s.Status(context.Background(), actor())
	if err != nil || status.Snapshot.Running.Hash != pending.Running.Hash || !status.Snapshot.RecoveryRequired || status.Effective.Phase != "unavailable" || len(status.Effective.Rules) != 0 {
		t.Fatalf("unavailable status: %+v %v", status, err)
	}
	_, err = f.s.Execute(context.Background(), actor(), r)
	if !errors.Is(err, configpoc.ErrDenied) || f.s.blocked {
		t.Fatalf("invalidated proof was not rejected before activation: %v", err)
	}
	f.m.badObservation = false
	r = f.confirm(f.snapshot())
	// This failure occurs after fresh proofs were admitted, rather than after a
	// status read already invalidated them. It must latch uncertain confirmation.
	f.m.badObservation = true
	_, err = f.s.Execute(context.Background(), actor(), r)
	if !errors.Is(err, configpoc.ErrRecovery) || !f.s.blocked {
		t.Fatalf("unknown confirmation not blocked: %v", err)
	}
	if f.m.confirms != 0 {
		t.Fatal("confirmed before effective readback")
	}
	for _, kind := range []string{"arm", "arm_deadline", "bad_receipt", "lost_ack"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			if kind == "arm" || kind == "arm_deadline" {
				f.stage(true)
				snap := f.snapshot()
				r := f.request(configpoc.OpCommit)
				r.Transaction.ConfirmFor = 30 * time.Second
				r.RecoveryProof = f.proof(actor(), r, snap.Candidate.Revision.Hash, r.Transaction.Key)
				f.m.armError = kind == "arm"
				f.m.badReceipt = kind == "arm_deadline"
				_, err := f.s.Execute(context.Background(), actor(), r)
				if !errors.Is(err, configpoc.ErrRecovery) || !f.s.blocked {
					t.Fatal("unknown arm not blocked")
				}
				return
			}
			_, pending := f.commit()
			r := f.confirm(pending)
			f.m.badReceipt = kind == "bad_receipt"
			f.m.confirmError = kind == "lost_ack"
			_, err := f.s.Execute(context.Background(), actor(), r)
			if kind == "bad_receipt" {
				if err == nil || !f.s.blocked {
					t.Fatal("bad receipt accepted")
				}
			} else if err != nil || f.s.blocked {
				t.Fatalf("exact receipt failed reconciliation %v", err)
			}
		})
	}
}

func TestProofIssuanceDuringApplyAndBoundedLifetimes(t *testing.T) {
	f := newFixture(t)
	f.stage(true)
	snap := f.snapshot()
	r := f.request(configpoc.OpCommit)
	r.Transaction.ConfirmFor = 30 * time.Second
	r.RecoveryProof = f.proof(actor(), r, snap.Candidate.Revision.Hash, r.Transaction.Key)
	called := make(chan struct{}, 1)
	f.m.onApply = func() {
		_, err := f.s.IssueProof(actor(), ProofRequest{Generation: r.Transaction.ExpectedGeneration, Target: snap.Candidate.Revision.Hash, Lease: r.Transaction.Key})
		if err != nil {
			t.Error(err)
		}
		called <- struct{}{}
	}
	done := make(chan error, 1)
	go func() { _, err := f.s.Execute(context.Background(), actor(), r); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proof issuance deadlocked activation")
	}
	<-called
	f.m.onApply = nil
	now := time.Now()
	f.s.proofs.now = func() time.Time { return now }
	pr := ProofRequest{Generation: 1, Target: snap.Running.Hash, Lease: "bounded"}
	p, err := f.s.IssueProof(actor(), pr)
	if err != nil || p.ExpiresAt.Sub(now) != ProofTTL {
		t.Fatal("recovery ttl")
	}
	c := actor()
	c.EndpointID = BindingEndpointID(expectedListeners(snap.Candidate.Revision.Config)[0])
	current := f.snapshot()
	c.ActivationHash = current.Running.Hash
	ep := ProofRequest{Generation: current.Generation, Target: current.Running.Hash, Lease: current.Pending.Lease}
	p, err = f.s.IssueProof(c, ep)
	if err != nil || p.ExpiresAt.Sub(now) > EndpointProofTTL || p.ExpiresAt.After(current.Pending.Deadline) {
		t.Fatal("endpoint ttl")
	}
	for len(f.s.proofs.entries) < MaxProofs {
		if _, err = f.s.IssueProof(actor(), pr); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = f.s.IssueProof(actor(), pr); !errors.Is(err, configpoc.ErrStorage) {
		t.Fatal("unbounded proofs")
	}
	f.s.proofs.now = func() time.Time { return now.Add(EndpointProofTTL) }
	if _, err = f.s.IssueProof(actor(), pr); err != nil {
		t.Fatal("expired proof capacity retained")
	}
}

func TestRolesGenerationAndFilters(t *testing.T) {
	f := newFixture(t)
	snap := f.stage(true)
	r := f.request(configpoc.OpCommit)
	r.Transaction.ConfirmFor = 30 * time.Second
	viewer := actor()
	viewer.Principal.Role = configpoc.RoleViewer
	before := f.m.counts()
	if _, err := f.s.Execute(context.Background(), viewer, r); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := f.s.History(viewer, 0, 10); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := f.s.Audit(viewer); !errors.Is(err, configpoc.ErrDenied) {
		t.Fatal(err)
	}
	if f.m.counts() != before {
		t.Fatal("viewer mutation touched helper")
	}
	if _, err := f.s.Status(context.Background(), viewer); err != nil {
		t.Fatal(err)
	}
	r.Transaction.ExpectedGeneration--
	before = f.m.counts()
	if _, err := f.s.Execute(context.Background(), actor(), r); !errors.Is(err, configpoc.ErrConflict) || f.m.counts() != before {
		t.Fatalf("generation: %v", err)
	}
	r.Transaction.ExpectedGeneration = snap.Generation
	bob := actor()
	bob.Principal.ID = "bob"
	before = f.m.counts()
	if _, err := f.s.Execute(context.Background(), bob, r); !errors.Is(err, configpoc.ErrDenied) || f.m.counts() != before {
		t.Fatalf("owner: %v", err)
	}
	before = f.m.counts()
	if _, err := f.s.Effective(context.Background(), viewer, Filter{Interface: "host0"}); !errors.Is(err, configpoc.ErrInvalid) || f.m.counts() != before {
		t.Fatal("invalid filter reached observer")
	}
	a, err := localpolicy.Compile(*policy(t, true).LocalServices)
	if err != nil {
		t.Fatal(err)
	}
	e := Effective{Rules: a.Rules, Listeners: expectedListeners(policy(t, true))}
	out, err := FilterEffective(e, Filter{Service: "https", Protocol: "tcp", Port: 18443, Source: "198.18.0.2/32"}, inventory())
	if err != nil || len(out.Rules) != 1 || len(out.Listeners) != 0 {
		t.Fatalf("filter: %+v %v", out, err)
	}
}

func TestHistoricalRollbackAdmissionRejectsForeignProfileBeforeEngine(t *testing.T) {
	for _, kind := range []string{"inventory", "forward"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			// A journal may predate the local-only adapter. Record valid core revisions
			// which this narrower management domain must never reactivate.
			direct := func(op string, c *configpoc.Config, target string, ttl time.Duration) configpoc.Snapshot {
				t.Helper()
				f.key++
				snap, err := f.s.core.Execute(context.Background(), actor().Principal, configpoc.API, configpoc.Request{Operation: configpoc.OpStatus})
				if err != nil {
					t.Fatal(err)
				}
				out, err := f.s.core.Execute(context.Background(), actor().Principal, configpoc.API, configpoc.Request{Operation: op, Key: fmt.Sprintf("legacy-%d", f.key), ExpectedGeneration: snap.Generation, Config: c, Target: target, ConfirmFor: ttl})
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
			bad := policy(t, false)
			if kind == "inventory" {
				bad.LocalServices.Interfaces[0].Addresses = append(bad.LocalServices.Interfaces[0].Addresses, "198.18.0.9")
			} else {
				bad = configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "forward", Action: "allow"}}}
			}
			direct(configpoc.OpStage, &bad, "", 0)
			recorded := direct(configpoc.OpCommit, nil, "", 30*time.Second)
			direct(configpoc.OpConfirm, nil, recorded.Running.Hash, 0)
			good := policy(t, false)
			direct(configpoc.OpStage, &good, "", 0)
			current := direct(configpoc.OpCommit, nil, "", 30*time.Second)
			direct(configpoc.OpConfirm, nil, current.Running.Hash, 0)
			r := f.request(configpoc.OpRollback)
			r.Transaction.Target = recorded.Running.Hash
			r.Transaction.ConfirmFor = 30 * time.Second
			r.RecoveryProof = f.proof(actor(), r, recorded.Running.Hash, r.Transaction.Key)
			before := f.m.counts()
			_, err := f.s.Execute(context.Background(), actor(), r)
			if !errors.Is(err, configpoc.ErrInvalid) || before != f.m.counts() {
				t.Fatalf("historical profile reached engine: %v", err)
			}
		})
	}
}

func TestRollbackSameGuardianAndRestartRevertsUnconfirmedTarget(t *testing.T) {
	f := newFixture(t)
	original := f.snapshot().Running
	_, pending := f.commit()
	confirmed := f.execute(f.confirm(pending))
	r := f.request(configpoc.OpRollback)
	r.Transaction.Target = original.Hash
	r.Transaction.ConfirmFor = 30 * time.Second
	r.RecoveryProof = f.proof(actor(), r, original.Hash, r.Transaction.Key)
	rolled := f.execute(r)
	if rolled.Running.Hash != original.Hash || rolled.Pending == nil || rolled.Pending.Previous.Hash != confirmed.Running.Hash || rolled.Pending.Lease != r.Transaction.Key {
		t.Fatal("rollback did not use shared pending lease")
	}
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	core, err := configpoc.Open(f.dir, []configpoc.Engine{f.m}, configpoc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = New(core, Options{RunID: strings.Repeat("b", 32), RecoveryEndpointID: "recovery", Inventory: inventory(), Authority: authority{f.m}, Observer: f.m})
	if err != nil {
		t.Fatal(err)
	}
	snap := f.snapshot()
	if snap.Running.Hash != confirmed.Running.Hash || snap.Pending != nil {
		t.Fatal("restart retained unconfirmed rollback")
	}
}

func TestConcurrentAdministratorsShareOneGeneration(t *testing.T) {
	f := newFixture(t)
	r := f.request(configpoc.OpStage)
	c := policy(t, true)
	r.Transaction.Config = &c
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"alice", "bob"} {
		go func(name string) {
			ctx := actor()
			ctx.Principal.ID = name
			local := copyValue(r)
			local.Transaction.Key = name + "-stage"
			<-start
			_, err := f.s.Execute(context.Background(), ctx, local)
			results <- err
		}(name)
	}
	close(start)
	success, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if errors.Is(err, configpoc.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes %d %d", success, conflicts)
	}
}

func BenchmarkIssueAndConsumeRecoveryProof(b *testing.B) {
	s := &Service{options: Options{RecoveryEndpointID: "recovery"}, proofs: proofBook{entries: make(map[[32]byte]attestation), now: time.Now}}
	c := actor()
	r := ProofRequest{Generation: 1, Target: strings.Repeat("a", 64), Lease: "benchmark"}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		p, err := s.IssueProof(c, r)
		if err != nil {
			b.Fatal(err)
		}
		keys, err := s.proofs.reserve(c, r, []proofNeed{{token: p.Token, endpoint: "recovery", sameSession: true}})
		if err != nil {
			b.Fatal(err)
		}
		s.proofs.finish(keys, true)
	}
}
