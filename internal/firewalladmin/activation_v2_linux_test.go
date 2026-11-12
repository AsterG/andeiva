//go:build linux

package firewalladmin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type guardedCoordinatorFixture struct {
	service   *configpoc.ServiceV2
	auth      *adminauth.Manager
	binding   adminauth.SessionBinding
	guard     *PreparedGuardedEngine
	authority *preparedGuardAuthority
	local     *configpoc.SimEngine
	area      *os.Root
	old, next configpoc.Revision
	namespace string
}

func guardedCoordinator(t *testing.T) *guardedCoordinatorFixture {
	t.Helper()
	g, a, old, next := preparedGuardFixture(t)
	f := &guardedCoordinatorFixture{guard: g, authority: a, old: old, next: next}
	roots := make([]*os.Root, 3)
	for i := range roots {
		path := t.TempDir()
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		roots[i] = root
		t.Cleanup(func() { _ = root.Close() })
	}
	f.area = roots[2]
	localConfig := configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"192.0.2.1"}}}, Services: []localpolicy.Service{}}}
	f.local = configpoc.NewSimEngine("local-sim")
	configs := []configpoc.Config{old.Config, localConfig}
	engines := []configpoc.Engine{a.engine, f.local}
	var expected [2]configpoc.LegacyFingerprintV2
	for i, domain := range []string{"firewall", "local_services"} {
		legacy, err := configpoc.Open(roots[i].Name(), []configpoc.Engine{engines[i]}, configpoc.Options{Initial: &configs[i]})
		if err != nil {
			t.Fatal(err)
		}
		if err = legacy.Close(); err != nil {
			t.Fatal(err)
		}
		expected[i], err = configpoc.InspectLegacyV2(roots[i], domain)
		if err != nil {
			t.Fatal(err)
		}
	}
	subject, err := configpoc.NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	revision := sha256.Sum256([]byte("explicit credential revision"))
	revisionID := hex.EncodeToString(revision[:])
	bindings := []configpoc.LegacyBindingV2{{Source: expected[0].Source, Actor: "alice", Subject: subject, ReceiptIndex: expected[0].ReceiptIndex}, {Source: expected[1].Source, Actor: "alice", Subject: subject, ReceiptIndex: expected[1].ReceiptIndex}}
	if err := configpoc.PrepareMigrationV2(roots[2], roots[0], roots[1], expected, []configpoc.SubjectV2{{ID: subject, Login: "alice", CredentialRevision: revisionID}}, bindings, configpoc.BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(credential))
	f.auth, err = adminauth.New([]adminauth.Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: subject, CredentialRevision: revisionID}}, func(adminauth.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := f.auth.Login("alice", credential)
	if err != nil {
		t.Fatal(err)
	}
	f.binding, err = f.auth.ResolveSession(token)
	if err != nil {
		t.Fatal(err)
	}
	f.reopen(t)
	ns, err := f.service.Namespace(f.binding, "firewall", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.namespace = ns.ID
	t.Cleanup(func() { _ = f.service.Close() })
	return f
}
func (f *guardedCoordinatorFixture) reopen(t *testing.T) {
	t.Helper()
	var err error
	f.service, err = configpoc.OpenServiceV2(context.Background(), f.area, configpoc.BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}, f.auth, []configpoc.Engine{f.guard}, []configpoc.Engine{f.local})
	if err != nil {
		t.Fatal(err)
	}
}
func (f *guardedCoordinatorFixture) run(t *testing.T, request configpoc.OperationRequestV2) (configpoc.ResultV2, error) {
	t.Helper()
	status, err := f.service.Status(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	op, err := f.service.Admit(f.binding, f.namespace, status.GlobalGeneration, request)
	if err != nil {
		t.Fatal(err)
	}
	return f.service.Execute(context.Background(), f.binding, op.ID)
}
func (f *guardedCoordinatorFixture) stage(t *testing.T) {
	t.Helper()
	if _, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &f.next.Config}); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedGuardCoordinatorImmediateAndConfirmed(t *testing.T) {
	f := guardedCoordinator(t)
	f.stage(t)
	seconds := uint64(30)
	commit, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal(err)
	}
	state := f.authority.g.Status()
	if state.Phase != "pending" || state.ID != commit.Operation.Outcome.ConfirmationLease || state.Target != f.next.Hash || f.guard.Current() != f.next.Hash {
		t.Fatal("commit was not helper leased")
	}
	if _, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Target: commit.Current.RunningRevision, Origin: commit.Operation.ID}); err != nil {
		t.Fatal(err)
	}
	if f.authority.g.Status().Phase != "idle" {
		t.Fatal("helper not confirmed")
	}
	if _, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpSave}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &f.old.Config}); err != nil {
		t.Fatal(err)
	}
	seconds = 0
	if _, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}); err != nil {
		t.Fatal(err)
	}
	if f.authority.g.Status().Phase != "idle" || f.guard.Current() != f.old.Hash {
		t.Fatal("immediate commit not helper confirmed")
	}
}
func TestPreparedGuardIndependentTimeoutAndRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := guardedCoordinator(t)
		f.stage(t)
		seconds := uint64(30)
		if _, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}); err != nil {
			t.Fatal(err)
		}
		if err := f.service.Close(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(31 * time.Second)
		if f.guard.Current() != f.old.Hash || f.authority.g.Status().Phase != "expired" {
			t.Fatal("helper did not rollback without coordinator")
		}
		f.reopen(t)
		status, err := f.service.Projection(f.binding, "firewall")
		if err != nil || status.Pending != nil || status.Running.Hash != f.old.Hash || status.RecoveryRequired {
			t.Fatal("restart did not reconcile helper rollback", err)
		}
	})
}
func TestPreparedGuardConfirmedRemoteUncertainPublicationFencesReopen(t *testing.T) {
	f := guardedCoordinator(t)
	f.stage(t)
	created := false
	f.authority.afterConfirm = func() error {
		file, err := f.area.OpenFile("selection.pending", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		created = true
		_, writeErr := file.Write([]byte("{}"))
		syncErr, closeErr := file.Sync(), file.Close()
		return errors.Join(writeErr, syncErr, closeErr)
	}
	seconds := uint64(0)
	if _, err := f.run(t, configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}); err == nil {
		t.Fatal("uncertain publication reported success")
	}
	if !created || f.guard.Current() != f.next.Hash || f.authority.g.Status().Phase != "idle" {
		t.Fatal("fault was not after real helper confirmation")
	}
	if err := f.service.Close(); err != nil {
		t.Fatal(err)
	}
	// Remove only the exact test-created staging file; real recovery must not
	// clear unknown staging. The independently confirmed helper remains intact.
	if err := f.area.Remove("selection.pending"); err != nil {
		t.Fatal(err)
	}
	f.authority.afterConfirm = nil
	service, err := configpoc.OpenServiceV2(context.Background(), f.area, configpoc.BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}, f.auth, []configpoc.Engine{f.guard}, []configpoc.Engine{f.local})
	if service != nil || !errors.Is(err, configpoc.ErrRecovery) {
		t.Fatal("uncertain confirmed target reopened writable", err)
	}
	if f.guard.Current() != f.next.Hash {
		t.Fatal("reopen invented helper rollback")
	}
}
