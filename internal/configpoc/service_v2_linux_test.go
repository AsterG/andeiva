//go:build linux

package configpoc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

func serviceV2Auth(t *testing.T, subject, login, role, revision string) (*adminauth.Manager, adminauth.SessionBinding, string) {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(credential))
	m, err := adminauth.New([]adminauth.Account{{Username: login, Role: role, CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: subject, CredentialRevision: revision}}, func(adminauth.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := m.Login(login, credential)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.ResolveSession(token)
	if err != nil {
		t.Fatal(err)
	}
	return m, b, token
}

func TestServiceV2IncompleteStoreDeniesOperations(t *testing.T) {
	auth, binding, _ := serviceV2Auth(t, "subject", "alice", "admin", strings.Repeat("a", 64))
	s := &ServiceV2{auth: auth, coordinator: &v2Coordinator{}}
	checks := map[string]func() error{
		"namespace":       func() error { _, err := s.Namespace(binding, "firewall", time.Minute); return err },
		"admit":           func() error { _, err := s.Admit(binding, "namespace", 1, OperationRequestV2{Kind: OpSave}); return err },
		"execute":         func() error { _, err := s.Execute(context.Background(), binding, "operation"); return err },
		"query":           func() error { _, err := s.Query(binding, "operation"); return err },
		"list":            func() error { _, _, err := s.List(binding, "namespace", 0, 10); return err },
		"close-namespace": func() error { return s.CloseNamespace(binding, "namespace") },
		"status":          func() error { _, err := s.Status(binding); return err },
		"projection":      func() error { _, err := s.Projection(binding, "firewall"); return err },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, ErrDenied) {
				t.Fatalf("incomplete service did not deny operation: %v", err)
			}
		})
	}
}
func serviceV2Fixture(t *testing.T, role string) (*ServiceV2, adminauth.SessionBinding, string, []*countedCoordinatorV2Engine) {
	t.Helper()
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	m, b, token := serviceV2Auth(t, p.Subject, "alice", role, c.store.state.Subjects[0].CredentialRevision)
	s := &ServiceV2{coordinator: c, auth: m}
	return s, b, token, engines
}
func TestServiceV2CatalogueExecuteProjectionAndReopen(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	m, b, _ := serviceV2Auth(t, p.Subject, "alice", "admin", c.store.state.Subjects[0].CredentialRevision)
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	s, err := OpenServiceV2(context.Background(), area, BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}, m, []Engine{engines[0], engines[1]}, []Engine{engines[2]})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	status, err := s.Status(b)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := s.Namespace(b, "firewall", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	config := coordinatorV2Rule("wrapper-rule")
	op, err := s.Admit(b, ns.ID, status.GlobalGeneration, OperationRequestV2{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	config.Rules[0].ID = "caller-mutated"
	query, err := s.Query(b, op.ID)
	if err != nil || query.Request.Config.Rules[0].ID != "wrapper-rule" {
		t.Fatal("request alias", err)
	}
	query.Request.Config.Rules[0].ID = "result-mutated"
	result, err := s.Execute(context.Background(), b, op.ID)
	if err != nil || result.Operation.State != "final" || result.Operation.Outcome.Code != "applied" {
		t.Fatal("execute", err, result.Operation.State)
	}
	if engines[0].applies.Load() != 0 {
		t.Fatal("stage unexpectedly applied engine")
	}
	again, err := s.Execute(context.Background(), b, op.ID)
	if err != nil || !reflect.DeepEqual(again.Operation.Outcome, result.Operation.Outcome) {
		t.Fatal("replay changed outcome", err)
	}
	listed, _, err := s.List(b, ns.ID, 0, 10)
	if err != nil || len(listed) != 1 || listed[0].ID != op.ID {
		t.Fatal("list", err)
	}
	projection, err := s.Projection(b, "firewall")
	if err != nil || projection.Candidate == nil || projection.Candidate.Revision.Config.Rules[0].ID != "wrapper-rule" {
		t.Fatal("projection", err)
	}
	if projection.Generation == result.Current.GlobalGeneration {
		t.Fatal("projection counter confused with global")
	}
	if err := s.CloseNamespace(b, ns.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Admit(b, ns.ID, result.Current.GlobalGeneration, OperationRequestV2{Kind: OpValidate}); !errors.Is(err, errV2Closed) {
		t.Fatal("closed namespace admitted", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("non-idempotent close", err)
	}
	if _, err := s.Status(b); !errors.Is(err, errV2Unavailable) {
		t.Fatal("closed service accessed", err)
	}
	s, err = OpenServiceV2(context.Background(), area, BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}, m, []Engine{engines[0], engines[1]}, []Engine{engines[2]})
	if err != nil {
		t.Fatal(err)
	}
	query, err = s.Query(b, op.ID)
	if err != nil || !reflect.DeepEqual(query.Outcome, result.Operation.Outcome) {
		t.Fatal("cold query", err)
	}
}

func TestServiceV2DeniedBindingsRolesAndOwnership(t *testing.T) {
	s, b, token, engines := serviceV2Fixture(t, "admin")
	status, _ := s.Status(b)
	ns, err := s.Namespace(b, "firewall", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.Admit(b, ns.ID, status.GlobalGeneration, OperationRequestV2{Kind: OpValidate})
	if err != nil {
		t.Fatal(err)
	}
	other, foreign, _ := serviceV2Auth(t, s.coordinator.store.state.Subjects[0].ID, "alice", "admin", s.coordinator.store.state.Subjects[0].CredentialRevision)
	_ = other
	for _, bad := range []adminauth.SessionBinding{{}, foreign} {
		if _, err := s.Query(bad, op.ID); !errors.Is(err, ErrDenied) {
			t.Fatal("forged/foreign issuer", err)
		}
	}
	if err := s.auth.Logout(token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Execute(context.Background(), b, op.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("logout survived", err)
	}
	if engines[0].applies.Load() != 0 {
		t.Fatal("denied access had effects")
	}
	viewer, vb, _, _ := serviceV2Fixture(t, "viewer")
	if _, err := viewer.Status(vb); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Projection(vb, "firewall"); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Namespace(vb, "firewall", time.Hour); !errors.Is(err, ErrDenied) {
		t.Fatal("viewer catalogue", err)
	}
	if _, err := viewer.Execute(context.Background(), vb, op.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("viewer mutation", err)
	}
	if _, err := viewer.Query(vb, op.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("viewer query", err)
	}
}

func TestServiceV2CanonicalRegistryGuardAfterAuthentication(t *testing.T) {
	for _, change := range []string{"rotation", "rename", "retirement", "recreated"} {
		for _, method := range []string{"namespace", "admit", "query", "list", "close", "execute", "status", "projection"} {
			t.Run(change+"/"+method, func(t *testing.T) {
				s, b, _, engines := serviceV2Fixture(t, "admin")
				status, _ := s.Status(b)
				ns, err := s.Namespace(b, "firewall", time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				op, err := s.Admit(b, ns.ID, status.GlobalGeneration, OperationRequestV2{Kind: OpValidate})
				if err != nil {
					t.Fatal(err)
				}
				authenticated, release := make(chan struct{}), make(chan struct{})
				s.afterAuthentication = func() { close(authenticated); <-release }
				done := make(chan error, 1)
				go func() {
					var err error
					switch method {
					case "namespace":
						_, err = s.Namespace(b, "firewall", time.Hour)
					case "admit":
						_, err = s.Admit(b, ns.ID, status.GlobalGeneration, OperationRequestV2{Kind: OpValidate})
					case "query":
						_, err = s.Query(b, op.ID)
					case "list":
						_, _, err = s.List(b, ns.ID, 0, 10)
					case "close":
						err = s.CloseNamespace(b, ns.ID)
					case "execute":
						_, err = s.Execute(context.Background(), b, op.ID)
					case "status":
						_, err = s.Status(b)
					case "projection":
						_, err = s.Projection(b, "firewall")
					}
					done <- err
				}()
				<-authenticated
				store := s.coordinator.store
				original := store.state.Subjects[0]
				login, revision, retire := original.Login, original.CredentialRevision, false
				if change == "rotation" {
					revision = strings.Repeat("b", 64)
				}
				if change == "rename" {
					login = "renamed"
				}
				if change == "retirement" || change == "recreated" {
					retire = true
				}
				if _, err := store.changeSubject(original.ID, login, revision, retire, s.coordinator.now()); err != nil {
					t.Fatal(err)
				}
				if change == "recreated" {
					if _, err := store.changeSubject("", login, revision, false, s.coordinator.now()); err != nil {
						t.Fatal(err)
					}
				}
				close(release)
				if err := <-done; !errors.Is(err, ErrDenied) {
					t.Fatal("stale registry binding authorized", err)
				}
				if engines[0].applies.Load() != 0 {
					t.Fatal("stale binding effects")
				}
			})
		}
	}
}

func TestServiceV2ConcurrentCatalogueRevocation(t *testing.T) {
	s, b, _, _ := serviceV2Fixture(t, "admin")
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 10 {
				_, err := s.Status(b)
				if err != nil && !errors.Is(err, ErrDenied) {
					t.Errorf("status: %v", err)
				}
			}
		})
	}
	sub := s.coordinator.store.state.Subjects[0]
	if _, err := s.coordinator.store.changeSubject(sub.ID, sub.Login, sub.CredentialRevision, true, s.coordinator.now()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := s.Status(b); !errors.Is(err, ErrDenied) {
		t.Fatal("retirement ignored", err)
	}
}

func TestServiceV2TransactionsAndForeignOwnership(t *testing.T) {
	s, binding, _, engines := serviceV2Fixture(t, "admin")
	ns, err := s.Namespace(binding, "firewall", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	run := func(request OperationRequestV2) ResultV2 {
		t.Helper()
		status, err := s.Status(binding)
		if err != nil {
			t.Fatal(err)
		}
		op, err := s.Admit(binding, ns.ID, status.GlobalGeneration, request)
		if err != nil {
			t.Fatal(err)
		}
		result, err := s.Execute(context.Background(), binding, op.ID)
		if err != nil {
			t.Fatal(request.Kind, err)
		}
		return result
	}
	initial, _ := s.Projection(binding, "firewall")
	initialStatus, _ := s.Status(binding)
	config := coordinatorV2Rule("transaction-via-wrapper")
	run(OperationRequestV2{Kind: OpStage, Config: &config})
	run(OperationRequestV2{Kind: OpValidate})
	seconds := uint64(30)
	committed := run(OperationRequestV2{Kind: OpCommit, ConfirmSeconds: &seconds})
	if committed.Current.Confirmation == nil || engines[0].applies.Load() != 1 {
		t.Fatal("confirmed commit not applied")
	}
	active, _ := s.Projection(binding, "firewall")
	if active.Running.Hash == initial.Running.Hash || active.Startup.Hash != initial.Startup.Hash {
		t.Fatal("running/startup collapsed")
	}
	run(OperationRequestV2{Kind: OpConfirm, Target: committed.Current.RunningRevision, Origin: committed.Operation.ID})
	run(OperationRequestV2{Kind: OpSave})
	saved, _ := s.Projection(binding, "firewall")
	if saved.Startup.Hash != saved.Running.Hash || saved.Pending != nil {
		t.Fatal("save/confirmation missing")
	}
	run(OperationRequestV2{Kind: OpRollback, Target: initialStatus.RunningRevision})
	after, _ := s.Projection(binding, "firewall")
	if after.Running.Hash != initial.Running.Hash || after.Startup.Hash != saved.Startup.Hash {
		t.Fatal("rollback altered startup")
	}
	historical, err := s.Query(binding, committed.Operation.ID)
	if err != nil || !reflect.DeepEqual(historical.Outcome, committed.Operation.Outcome) {
		t.Fatal("historical outcome mutated", err)
	}

	store := s.coordinator.store
	foreign, err := store.changeSubject("", "bob", strings.Repeat("d", 64), false, s.coordinator.now())
	if err != nil {
		t.Fatal(err)
	}
	foreignNS, err := store.namespace(foreign.ID, "firewall", s.coordinator.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	foreignOp, err := store.admit(foreign.ID, foreignNS.ID, store.state.Generation, v2Request{Kind: OpValidate}, s.coordinator.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Query(binding, foreignOp.ID); !errors.Is(err, errV2NotFound) {
		t.Fatal("foreign operation disclosed", err)
	}
	if _, err := s.Execute(context.Background(), binding, foreignOp.ID); !errors.Is(err, errV2NotFound) {
		t.Fatal("foreign operation executed", err)
	}
	if err := s.CloseNamespace(binding, foreignNS.ID); !errors.Is(err, errV2NotFound) {
		t.Fatal("foreign namespace closed", err)
	}

	local, err := s.Namespace(binding, "local_services", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, _ := s.Status(binding)
	op, err := s.Admit(binding, local.ID, status.GlobalGeneration, OperationRequestV2{Kind: OpValidate})
	if err != nil {
		t.Fatal(err)
	}
	before := engines[2].validations.Load()
	if _, err := s.Execute(context.Background(), binding, op.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("unproved local mutation accepted", err)
	}
	if engines[2].validations.Load() != before || engines[2].applies.Load() != 0 {
		t.Fatal("unproved local request reached engine")
	}
}
