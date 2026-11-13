//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

func TestServiceV2AuditSelectedPaginationAndPermissions(t *testing.T) {
	s, binding, _, _ := serviceV2Fixture(t, "admin")
	page, err := s.AuditV2(context.Background(), binding, 0, 10)
	if err != nil || len(page.Events) != 1 || page.Truncated || page.Events[0].Operation != "initialize" || page.Events[0].ActorID != "system" {
		t.Fatal("initialization audit", page, err)
	}
	ns, err := s.Namespace(binding, "firewall", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		status, err := s.Status(binding)
		if err != nil {
			t.Fatal(err)
		}
		op, err := s.Admit(binding, ns.ID, status.GlobalGeneration, OperationRequestV2{Kind: OpSave})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Execute(context.Background(), binding, op.ID); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.AuditV2(context.Background(), binding, 0, 100)
	if err != nil || len(all.Events) != 4 {
		t.Fatal("selected audit", all, err)
	}
	var cursor uint64
	for i, want := range all.Events {
		p, err := s.AuditV2(context.Background(), binding, cursor, 1)
		if err != nil || len(p.Events) != 1 || p.Events[0] != want {
			t.Fatal("exclusive cursor", i, p, err)
		}
		if want.ActorID == "" || want.OperationID == "" || want.At.IsZero() || (i < 3 && (want.ActorName != "alice" || want.Operation != string(OpSave))) {
			t.Fatal("missing administrative facts", want)
		}
		cursor = p.NextBefore
		if i < len(all.Events)-1 && cursor == 0 {
			t.Fatal("missing next cursor")
		}
	}
	if cursor != 0 {
		t.Fatal("unexpected continuation")
	}
	if _, err := s.AuditV2(context.Background(), binding, ^uint64(0), 1); !errors.Is(err, ErrInvalid) {
		t.Fatal("future cursor", err)
	}
	for _, limit := range []int{0, -1, 101} {
		if _, err := s.AuditV2(context.Background(), binding, 0, limit); !errors.Is(err, ErrInvalid) {
			t.Fatal("unbounded limit", err)
		}
	}
	if _, err := s.AuditV2(context.Background(), adminauth.SessionBinding{}, 0, 1); !errors.Is(err, ErrDenied) {
		t.Fatal("unauthenticated audit", err)
	}
	viewer, vb, _, _ := serviceV2Fixture(t, "viewer")
	if _, err := viewer.AuditV2(context.Background(), vb, 0, 1); !errors.Is(err, ErrDenied) {
		t.Fatal("viewer audit", err)
	}
}

func TestServiceV2AuditCancellationDoesNotFenceWrites(t *testing.T) {
	s, binding, _, _ := serviceV2Fixture(t, "admin")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.AuditV2(ctx, binding, 0, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.coordinator.store.blocked {
		t.Fatal("cancelled reader fenced writes")
	}
	s.coordinator.store.mu.Lock()
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := s.AuditV2(ctx, binding, 0, 1)
	s.coordinator.store.mu.Unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lock wait ignored cancellation", err)
	}
}

func TestServiceV2AuditRejectsCorruptSelectedObject(t *testing.T) {
	s, binding, _, engines := serviceV2Fixture(t, "admin")
	store := s.coordinator.store
	name, err := v2ObjectName(store.state.Configuration.AuditTip)
	if err != nil {
		t.Fatal(err)
	}
	file, err := store.root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuditV2(context.Background(), binding, 0, 10); !errors.Is(err, errV2Unavailable) {
		t.Fatal("corrupt audit exposed", err)
	}
	if !store.blocked {
		t.Fatal("corruption did not fence new writes")
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("reader changed traffic engine")
		}
	}
}
