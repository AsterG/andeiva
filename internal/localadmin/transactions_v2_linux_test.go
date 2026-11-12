//go:build linux

package localadmin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

type transactionAuthorityV2 struct {
	guardian *nftguardian.Guardian
	engine   *configpoc.SimEngine
}
type transactionEngineV2 struct {
	base        *configpoc.SimEngine
	guardian    *nftguardian.Guardian
	applies     atomic.Int64
	beforeApply func() error
	afterApply  func() error
}

func (e *transactionEngineV2) Name() string                      { return e.base.Name() }
func (e *transactionEngineV2) Validate(c configpoc.Config) error { return e.base.Validate(c) }
func (e *transactionEngineV2) Current() string                   { return e.base.Current() }
func (e *transactionEngineV2) Apply(ctx context.Context, r configpoc.Revision) error {
	e.applies.Add(1)
	if e.beforeApply != nil {
		if err := e.beforeApply(); err != nil {
			return err
		}
	}
	if err := e.guardian.Apply(ctx, r); err != nil {
		return err
	}
	if e.afterApply != nil {
		return e.afterApply()
	}
	return nil
}

func (a transactionAuthorityV2) Arm(_ context.Context, id string, p, t configpoc.Revision, ttl time.Duration) error {
	return a.guardian.Arm(id, p, t, ttl)
}
func (a transactionAuthorityV2) Confirm(_ context.Context, id, hash string) error {
	return a.guardian.Confirm(id, hash)
}
func (a transactionAuthorityV2) Current(context.Context) (string, error) {
	return a.engine.Current(), nil
}
func (a transactionAuthorityV2) State(context.Context) (firewalladmin.LeaseState, error) {
	s := a.guardian.Status()
	return firewalladmin.LeaseState{Phase: s.Phase, ID: s.ID, Previous: s.Previous, Target: s.Target, Deadline: s.Deadline}, nil
}

type transactionFixtureV2 struct {
	service  *configpoc.ServiceV2
	area     *os.Root
	book     *PreparedProofBookV2
	policy   *PreparedPolicyV2
	auth     *adminauth.Manager
	binding  adminauth.SessionBinding
	token    string
	recovery *PreparedBridgeV2
	fw       *configpoc.SimEngine
	local    *configpoc.SimEngine
	guard    *firewalladmin.PreparedGuardedEngine
	guardian *nftguardian.Guardian
	effects  *transactionEngineV2
}

func transactionFixture(t *testing.T) *transactionFixtureV2 {
	t.Helper()
	f := &transactionFixtureV2{}
	var secret [32]byte
	if _, e := rand.Read(secret[:]); e != nil {
		t.Fatal(e)
	}
	credential := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(credential))
	subject, e := configpoc.NewSubjectIDV2()
	if e != nil {
		t.Fatal(e)
	}
	revision := strings.Repeat("a", 64)
	f.auth, e = adminauth.New([]adminauth.Account{{Username: "alice", Role: "admin", SubjectID: subject, CredentialRevision: revision, CredentialSHA256: hex.EncodeToString(digest[:])}}, func(adminauth.Event) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	_, f.token, e = f.auth.Login("alice", credential)
	if e != nil {
		t.Fatal(e)
	}
	f.binding, e = f.auth.ResolveSession(f.token)
	if e != nil {
		t.Fatal(e)
	}
	root := func() *os.Root {
		path := t.TempDir()
		if e := os.Chmod(path, 0700); e != nil {
			t.Fatal(e)
		}
		r, e := os.OpenRoot(path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	firewallArea, localArea := root(), root()
	f.area = root()
	f.fw = configpoc.NewSimEngine("fw-real-store")
	f.local = configpoc.NewSimEngine("local-real-store")
	initialFW := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	initialLocal := policy(t, false)
	for i, item := range []struct {
		area   *os.Root
		engine *configpoc.SimEngine
		config configpoc.Config
	}{{firewallArea, f.fw, initialFW}, {localArea, f.local, initialLocal}} {
		core, e := configpoc.Open(item.area.Name(), []configpoc.Engine{item.engine}, configpoc.Options{Initial: &item.config})
		if e != nil {
			t.Fatal(i, e)
		}
		if e = core.Close(); e != nil {
			t.Fatal(e)
		}
	}
	fp, e := configpoc.InspectLegacyV2(firewallArea, "firewall")
	if e != nil {
		t.Fatal(e)
	}
	lp, e := configpoc.InspectLegacyV2(localArea, "local_services")
	if e != nil {
		t.Fatal(e)
	}
	if e = configpoc.PrepareMigrationV2(f.area, firewallArea, localArea, [2]configpoc.LegacyFingerprintV2{fp, lp}, []configpoc.SubjectV2{{ID: subject, Login: "alice", CredentialRevision: revision}}, nil, configpoc.BudgetV2{Bytes: 2 << 30, Inodes: 300000}, time.Now().UTC()); e != nil {
		t.Fatal(e)
	}
	recovery := ProofReceiverV2{Run: strings.Repeat("1", 32), Instance: strings.Repeat("2", 32), Endpoint: "recovery", Namespace: 100, Surface: configpoc.API}
	f.book, e = NewPreparedProofBookV2(f.auth, recovery, inventory())
	if e != nil {
		t.Fatal(e)
	}
	f.policy, e = NewPreparedPolicyV2(f.book, func(r configpoc.Revision) ([]ProofReceiverV2, error) {
		listeners := expectedListeners(r.Config)
		result := []ProofReceiverV2{}
		for _, listener := range listeners {
			result = append(result, ProofReceiverV2{Run: recovery.Run, Instance: strings.Repeat("3", 32), Endpoint: BindingEndpointID(listener), ActivationHash: r.Hash, Namespace: 100, Surface: configpoc.API})
		}
		return result, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	f.guardian = nftguardian.NewRestricted(f.local)
	initial, _ := configpoc.Canonical(initialLocal)
	if e = f.guardian.Bootstrap(context.Background(), initial); e != nil {
		t.Fatal(e)
	}
	f.effects = &transactionEngineV2{base: f.local, guardian: f.guardian}
	f.guard, e = firewalladmin.NewPreparedGuardedEngine(f.effects, transactionAuthorityV2{f.guardian, f.local}, func(_ context.Context, s firewalladmin.LeaseState) error {
		return f.guardian.RecoverLease(s.ID, s.Previous, s.Target, s.Deadline)
	})
	if e != nil {
		t.Fatal(e)
	}
	f.service, e = configpoc.OpenServiceV2WithLocalPolicy(context.Background(), f.area, configpoc.BudgetV2{Bytes: 2 << 30, Inodes: 300000}, f.auth, []configpoc.Engine{f.fw}, []configpoc.Engine{f.guard}, f.policy)
	if e != nil {
		t.Fatal(e)
	}
	f.recovery, e = NewPreparedBridgeV2(f.service, recovery)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.service.Close(); _ = f.guardian.Close(); f.book.Close() })
	return f
}
func (f *transactionFixtureV2) admit(t *testing.T, r configpoc.OperationRequestV2) configpoc.OperationV2 {
	t.Helper()
	s, e := f.service.Status(f.binding)
	if e != nil {
		t.Fatal(e)
	}
	ns, e := f.service.Namespace(f.binding, "local_services", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	op, e := f.service.AdmitLocalV2(f.binding, ns.ID, s.GlobalGeneration, r)
	if e != nil {
		t.Fatal(e)
	}
	return op
}
func (f *transactionFixtureV2) execute(t *testing.T, op configpoc.OperationV2, proofs bool) configpoc.ObservationV2 {
	t.Helper()
	evidence := ProofEvidenceV2{}
	if proofs {
		purpose := "execute"
		if op.Request.Kind == configpoc.OpConfirm {
			purpose = "confirm"
		}
		token, e := f.recovery.Issue(f.binding, op.ID, purpose)
		if e != nil {
			t.Fatal("recovery proof", e)
		}
		evidence.Recovery = token.Token
		if purpose == "confirm" {
			local, e := f.service.Projection(f.binding, "local_services")
			if e != nil {
				t.Fatal(e)
			}
			receivers, e := f.policy.receivers(local.Running)
			if e != nil {
				t.Fatal(e)
			}
			for _, receiver := range receivers {
				bridge, e := NewPreparedBridgeV2(f.service, receiver)
				if e != nil {
					t.Fatal(e)
				}
				token, e := bridge.Issue(f.binding, op.ID, purpose)
				if e != nil {
					t.Fatal("endpoint proof", e)
				}
				evidence.Endpoints = append(evidence.Endpoints, token.Token)
			}
		}
	}
	out, e := f.recovery.Execute(context.Background(), f.binding, op.ID, evidence)
	if e != nil {
		t.Fatal(op.Request.Kind, e, out.Operation.State, out.Operation.Outcome, f.guardian.Status())
	}
	return out
}
func TestLocalTransactionsV2FullLifecycle(t *testing.T) {
	f := transactionFixture(t)
	before, e := f.service.Projection(f.binding, "firewall")
	if e != nil {
		t.Fatal(e)
	}
	initial, e := f.service.Status(f.binding)
	if e != nil {
		t.Fatal(e)
	}
	config := policy(t, true)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config}), false)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpValidate}), false)
	seconds := uint64(30)
	pending := f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}), true)
	status, e := f.service.Status(f.binding)
	if e != nil || status.Confirmation == nil || status.Confirmation.Domain != "local_services" || f.local.Current() != pending.Current.Snapshot.Running.Hash {
		t.Fatal(status, e)
	}
	confirmed := f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: status.Confirmation.Origin, Target: status.Confirmation.Target}), true)
	if confirmed.Current.Snapshot.Pending != nil || confirmed.Operation.Outcome.DomainGeneration != confirmed.Current.Snapshot.Generation {
		t.Fatal("confirm projection")
	}
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpSave}), true)
	saved, e := f.service.Projection(f.binding, "local_services")
	if e != nil || saved.Startup.Hash != saved.Running.Hash {
		t.Fatal("save", e)
	}
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpRollback, Target: initial.RunningRevision}), true)
	status, e = f.service.Status(f.binding)
	if e != nil || status.Confirmation == nil {
		t.Fatal("rollback must require confirmation", e)
	}
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: status.Confirmation.Origin, Target: status.Confirmation.Target}), true)
	after, e := f.service.Projection(f.binding, "firewall")
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("local transaction changed firewall", e)
	}
	if e = f.service.Close(); e != nil {
		t.Fatal(e)
	}
	f.service, e = configpoc.OpenServiceV2WithLocalPolicy(context.Background(), f.area, configpoc.BudgetV2{Bytes: 2 << 30, Inodes: 300000}, f.auth, []configpoc.Engine{f.fw}, []configpoc.Engine{f.guard}, f.policy)
	if e != nil {
		t.Fatal("reopen", e)
	}
	view, e := f.service.Projection(f.binding, "local_services")
	if e != nil || view.Startup.Hash != saved.Startup.Hash || view.Running.Hash == view.Startup.Hash {
		t.Fatal("running/startup independence", e)
	}
}
func TestLocalTransactionsV2InvalidEvidenceHasNoEffects(t *testing.T) {
	f := transactionFixture(t)
	config := policy(t, true)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config}), false)
	seconds := uint64(30)
	op := f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	before, e := f.service.Status(f.binding)
	if e != nil {
		t.Fatal(e)
	}
	files, e := os.ReadDir(f.area.Name())
	if e != nil {
		t.Fatal(e)
	}
	hash := f.local.Current()
	applies := f.effects.applies.Load()
	if _, e = f.recovery.Execute(context.Background(), f.binding, op.ID, ProofEvidenceV2{Recovery: strings.Repeat("f", 64)}); !errors.Is(e, configpoc.ErrDenied) {
		t.Fatal("bad token", e)
	}
	after, e := f.service.Status(f.binding)
	if e != nil || !reflect.DeepEqual(before, after) || f.local.Current() != hash || f.effects.applies.Load() != applies {
		t.Fatal("bad evidence changed state", e)
	}
	next, e := os.ReadDir(f.area.Name())
	if e != nil || len(files) != len(next) {
		t.Fatal("bad evidence wrote journal", e)
	}
	q, e := f.service.Query(f.binding, op.ID)
	if e != nil || q.State != "accepted" {
		t.Fatal("accepted operation lost", e)
	}
	f.execute(t, op, true)
}

func TestLocalTransactionsV2PendingRestartAndTimeout(t *testing.T) {
	for _, kind := range []string{"restart", "timeout"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := transactionFixture(t)
				initial, e := f.service.Projection(f.binding, "local_services")
				if e != nil {
					t.Fatal(e)
				}
				config := policy(t, true)
				f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config}), false)
				seconds := uint64(30)
				committed := f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}), true)
				if kind == "restart" {
					if e = f.service.Close(); e != nil {
						t.Fatal(e)
					}
					f.service, e = configpoc.OpenServiceV2WithLocalPolicy(context.Background(), f.area, configpoc.BudgetV2{Bytes: 2 << 30, Inodes: 300000}, f.auth, []configpoc.Engine{f.fw}, []configpoc.Engine{f.guard}, f.policy)
					if e != nil {
						t.Fatal("recovery reopen", e)
					}
				} else {
					time.Sleep(31 * time.Second)
					synctest.Wait()
				}
				view, e := f.service.Projection(f.binding, "local_services")
				if e != nil || view.Pending != nil || view.Running.Hash != initial.Running.Hash || view.Startup.Hash != initial.Startup.Hash || view.Generation <= committed.Current.Snapshot.Generation || f.local.Current() != initial.Running.Hash {
					t.Fatal("failed recovery", view, e)
				}
				origin, e := f.service.Query(f.binding, committed.Operation.ID)
				if e != nil || origin.Pinned || !reflect.DeepEqual(origin.Outcome, committed.Operation.Outcome) {
					t.Fatal("origin receipt changed", e)
				}
			})
		})
	}
}

func TestLocalTransactionsV2AtomicEvidenceAndReplay(t *testing.T) {
	f := transactionFixture(t)
	config := policy(t, true)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config}), false)
	seconds := uint64(30)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}), true)
	status, _ := f.service.Status(f.binding)
	op := f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: status.Confirmation.Origin, Target: status.Confirmation.Target})
	recovery, e := f.recovery.Issue(f.binding, op.ID, "confirm")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.recovery.Execute(context.Background(), f.binding, op.ID, ProofEvidenceV2{Recovery: recovery.Token}); !errors.Is(e, configpoc.ErrDenied) {
		t.Fatal("partial evidence accepted", e)
	}
	view, _ := f.service.Projection(f.binding, "local_services")
	receivers, _ := f.policy.receivers(view.Running)
	evidence := ProofEvidenceV2{Recovery: recovery.Token}
	for _, receiver := range receivers {
		bridge, _ := NewPreparedBridgeV2(f.service, receiver)
		token, e := bridge.Issue(f.binding, op.ID, "confirm")
		if e != nil {
			t.Fatal(e)
		}
		evidence.Endpoints = append(evidence.Endpoints, token.Token)
	}
	out, e := f.recovery.Execute(context.Background(), f.binding, op.ID, evidence)
	if e != nil {
		t.Fatal("partial reservation consumed valid recovery proof", e)
	}
	before := f.effects.applies.Load()
	again, e := f.recovery.Execute(context.Background(), f.binding, op.ID, ProofEvidenceV2{})
	if e != nil || !reflect.DeepEqual(out.Operation.Outcome, again.Operation.Outcome) || f.effects.applies.Load() != before {
		t.Fatal("replay needed proof or caused effects", e)
	}
}

func TestLocalTransactionsV2ConcurrentExactOperation(t *testing.T) {
	f := transactionFixture(t)
	config := policy(t, true)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config}), false)
	seconds := uint64(30)
	op := f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	proof, e := f.recovery.Issue(f.binding, op.ID, "execute")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	out := make(chan configpoc.OperationV2, 2)
	fail := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, e := f.recovery.Execute(context.Background(), f.binding, op.ID, ProofEvidenceV2{Recovery: proof.Token})
			out <- result.Operation
			fail <- e
		}()
	}
	wg.Wait()
	close(out)
	close(fail)
	for e := range fail {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first *configpoc.OperationV2
	for item := range out {
		if first == nil {
			copy := item
			first = &copy
		} else if !reflect.DeepEqual(first.Outcome, item.Outcome) {
			t.Fatal("concurrent outcomes differ")
		}
	}
	if f.effects.applies.Load() != 1 {
		t.Fatal("concurrent operation applied twice", f.effects.applies.Load())
	}
}

func TestLocalTransactionsV2ExpiredProofAndLogout(t *testing.T) {
	for _, problem := range []string{"expiry", "logout"} {
		t.Run(problem, func(t *testing.T) {
			f := transactionFixture(t)
			config := policy(t, true)
			f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config}), false)
			seconds := uint64(30)
			op := f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
			proof, e := f.recovery.Issue(f.binding, op.ID, "execute")
			if e != nil {
				t.Fatal(e)
			}
			hash := f.local.Current()
			count := f.effects.applies.Load()
			if problem == "logout" {
				f.auth.Logout(f.token)
			} else {
				f.book.now = func() time.Time { return time.Now().Add(21 * time.Second) }
			}
			if _, e = f.recovery.Execute(context.Background(), f.binding, op.ID, ProofEvidenceV2{Recovery: proof.Token}); !errors.Is(e, configpoc.ErrDenied) {
				t.Fatal("invalid auth/evidence accepted", e)
			}
			if f.local.Current() != hash || f.effects.applies.Load() != count {
				t.Fatal("denied request touched engine")
			}
			if problem == "expiry" {
				q, e := f.service.Query(f.binding, op.ID)
				if e != nil || q.State != "accepted" {
					t.Fatal("expired proof lost operation", e)
				}
				fresh, e := f.recovery.Issue(f.binding, op.ID, "execute")
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.recovery.Execute(context.Background(), f.binding, op.ID, ProofEvidenceV2{Recovery: fresh.Token}); e != nil {
					t.Fatal("same accepted ID could not refresh proof", e)
				}
			}
		})
	}
}

func TestLocalTransactionsV2ListenerReplacementInvalidatesProof(t *testing.T) {
	f := transactionFixture(t)
	config := policy(t, true)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config}), false)
	seconds := uint64(30)
	f.execute(t, f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}), true)
	status, _ := f.service.Status(f.binding)
	op := f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: status.Confirmation.Origin, Target: status.Confirmation.Target})
	recovery, e := f.recovery.Issue(f.binding, op.ID, "confirm")
	if e != nil {
		t.Fatal(e)
	}
	local, _ := f.service.Projection(f.binding, "local_services")
	receivers, _ := f.policy.receivers(local.Running)
	evidence := ProofEvidenceV2{Recovery: recovery.Token}
	old := []*PreparedBridgeV2{}
	for _, receiver := range receivers {
		bridge, _ := NewPreparedBridgeV2(f.service, receiver)
		old = append(old, bridge)
		token, e := bridge.Issue(f.binding, op.ID, "confirm")
		if e != nil {
			t.Fatal(e)
		}
		evidence.Endpoints = append(evidence.Endpoints, token.Token)
	}
	previous := f.policy.receivers
	f.policy.receivers = func(r configpoc.Revision) ([]ProofReceiverV2, error) {
		items, e := previous(r)
		for i := range items {
			items[i].Instance = strings.Repeat("4", 32)
		}
		return items, e
	}
	if _, e = f.recovery.Issue(f.binding, op.ID, "confirm"); e != nil {
		t.Fatal(e)
	}
	for _, bridge := range old {
		if _, e = bridge.Issue(f.binding, op.ID, "confirm"); !errors.Is(e, configpoc.ErrDenied) {
			t.Fatal("retired instance issued proof", e)
		}
	}
	if _, e = f.recovery.Execute(context.Background(), f.binding, op.ID, evidence); !errors.Is(e, configpoc.ErrDenied) {
		t.Fatal("replacement reused proof", e)
	}
	evidence.Endpoints = nil
	receivers, _ = f.policy.receivers(local.Running)
	for _, receiver := range receivers {
		bridge, _ := NewPreparedBridgeV2(f.service, receiver)
		token, e := bridge.Issue(f.binding, op.ID, "confirm")
		if e != nil {
			t.Fatal(e)
		}
		evidence.Endpoints = append(evidence.Endpoints, token.Token)
	}
	if _, e = f.recovery.Execute(context.Background(), f.binding, op.ID, evidence); e != nil {
		t.Fatal("fresh instance proof rejected", e)
	}
}

func TestLocalTransactionsV2NoBypassOrPlainCommit(t *testing.T) {
	f := transactionFixture(t)
	status, _ := f.service.Status(f.binding)
	ns, e := f.service.Namespace(f.binding, "local_services", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	zero := uint64(0)
	if _, e = f.service.AdmitLocalV2(f.binding, ns.ID, status.GlobalGeneration, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &zero}); !errors.Is(e, configpoc.ErrInvalid) {
		t.Fatal("plain local commit accepted", e)
	}
	config := policy(t, true)
	op := f.admit(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &config})
	if _, e = f.service.Execute(context.Background(), f.binding, op.ID); !errors.Is(e, configpoc.ErrDenied) {
		t.Fatal("generic Execute bypassed local policy", e)
	}
	f.execute(t, op, false)
}
