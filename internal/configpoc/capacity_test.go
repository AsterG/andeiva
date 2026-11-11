package configpoc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type countedCapacityEngine struct {
	Engine
	applies atomic.Int64
}

func (e *countedCapacityEngine) Apply(ctx context.Context, r Revision) error {
	e.applies.Add(1)
	return e.Engine.Apply(ctx, r)
}

func fillCapacityRecords(t *testing.T, s *Service, free int) {
	t.Helper()
	for len(s.store.records) < s.store.limit-free {
		if err := s.persist("system", API, "capacity-fixture", "ok", true); err != nil {
			t.Fatal(err)
		}
	}
}

func fillCapacityReceipts(t *testing.T, s *Service, count int) {
	t.Helper()
	for i := len(s.state.Receipts); i < count; i++ {
		s.state.Receipts[fmt.Sprintf("alice:fixture-%d", i)] = receipt{Fingerprint: strings.Repeat("a", 64), Generation: s.state.Snapshot.Generation}
	}
	if err := s.persist("system", API, "capacity-fixture", "ok", true); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityConfirmedAdmissionBeforeEffects(t *testing.T) {
	for _, boundary := range []string{"records", "bytes", "receipts"} {
		t.Run(boundary, func(t *testing.T) {
			s, engines, _ := fixture(t, Options{MaxRecords: 20})
			c := firewallSample()
			staged := invoke(t, s, OpStage, &c, 0)
			switch boundary {
			case "records":
				fillCapacityRecords(t, s, 5)
			case "bytes":
				// Exercise the byte admission boundary independently of record count;
				// this is quota accounting, not a physical ENOSPC simulation.
				s.store.bytes = maxJournalBytes - 5*maxRecordBytes
			case "receipts":
				fillCapacityReceipts(t, s, 1023)
			}
			before := clone(s.state)
			counted := &countedCapacityEngine{Engine: engines[0]}
			s.engines[0] = counted
			guard := &testGuard{}
			_, err := s.ExecuteManaged(context.Background(), admin, API, Request{Operation: OpCommit, Key: "near-quota", ExpectedGeneration: staged.Generation, ConfirmFor: 30 * time.Second}, guard)
			if !errors.Is(err, ErrStorage) {
				t.Fatalf("unsafe admission: got %v, want storage rejection", err)
			}
			if guard.arms != 0 || guard.confirms != 0 || counted.applies.Load() != 0 || !reflect.DeepEqual(before, s.state) {
				t.Fatal("capacity rejection changed state or called activation authority/engine")
			}
		})
	}
}

func TestCapacityPendingBudgetCannotBeStolen(t *testing.T) {
	s, engines, dir := fixture(t, Options{MaxRecords: 20})
	c := firewallSample()
	staged := invoke(t, s, OpStage, &c, 0)
	fillCapacityReceipts(t, s, 1021)
	fillCapacityRecords(t, s, 6)
	guard := &testGuard{}
	ctx := context.Background()
	commit := Request{Operation: OpCommit, Key: "reserved-commit", ExpectedGeneration: staged.Generation, ConfirmFor: 30 * time.Second}
	pending, err := s.ExecuteManaged(ctx, admin, API, commit, guard)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		for _, attempt := range []struct {
			actor Principal
			req   Request
		}{
			{Principal{ID: "viewer", Role: RoleViewer}, Request{Operation: OpSave}},
			{admin, Request{Operation: OpRevoke, Key: fmt.Sprintf("revoke-%d", i), ExpectedGeneration: pending.Generation, Target: "other"}},
			{admin, Request{Operation: OpConfirm, Key: fmt.Sprintf("bad-%d", i), ExpectedGeneration: pending.Generation, Target: "wrong"}},
			{Principal{ID: "bob", Role: RoleAdmin}, Request{Operation: OpConfirm, Key: fmt.Sprintf("owner-%d", i), ExpectedGeneration: pending.Generation, Target: pending.Running.Hash}},
			{admin, Request{Operation: OpConfirm, Key: fmt.Sprintf("stale-%d", i), ExpectedGeneration: pending.Generation - 1, Target: pending.Running.Hash}},
		} {
			if _, err := s.Execute(ctx, attempt.actor, API, attempt.req); err == nil {
				t.Fatal("pending budget was consumed by another operation")
			}
		}
	}
	confirm := Request{Operation: OpConfirm, Key: "reserved-confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash}
	confirmed, err := s.ExecuteManaged(ctx, admin, CLI, confirm, guard)
	if err != nil || confirmed.Pending != nil || confirmed.Running.Hash != pending.Running.Hash || guard.confirms != 1 {
		t.Fatalf("reserved confirmation failed: %v", err)
	}
	records, receipts := len(s.store.records), len(s.state.Receipts)
	for _, req := range []Request{commit, confirm} {
		out, err := s.ExecuteManaged(ctx, admin, API, req, guard)
		if err != nil || out.ReplayedGeneration == 0 || out.Generation != confirmed.Generation {
			t.Fatalf("quota replay unavailable: %v", err)
		}
	}
	_ = status(t, s)
	if _, err := s.History(admin); err != nil || len(s.store.records) != records || len(s.state.Receipts) != receipts || guard.confirms != 1 || guard.arms != 1 {
		t.Fatal("reads/replays consumed capacity or repeated effects")
	}
	for range 8 {
		_, _ = s.Execute(ctx, Principal{ID: "viewer", Role: RoleViewer}, API, Request{Operation: OpSave})
	}
	if s.store.limit-len(s.store.records) != recoveryRecords {
		t.Fatal("post-confirmation rejections spent recovery reserve")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{MaxRecords: 20})
	if err != nil {
		t.Fatalf("reserved reopen failed: %v", err)
	}
	defer reopened.Close()
	if got := status(t, reopened); got.Running.Hash != confirmed.Running.Hash || got.Pending != nil {
		t.Fatal("reopen changed confirmed revision")
	}
	if out, err := reopened.ExecuteManaged(ctx, admin, API, confirm, guard); err != nil || out.ReplayedGeneration != confirmed.Generation {
		t.Fatalf("durable quota replay failed: %v", err)
	}
	logCapacity(t, reopened)
}

func logCapacity(t *testing.T, s *Service) {
	t.Helper()
	largest := 0
	for _, record := range s.store.records {
		largest = max(largest, int(record.info.Size()))
	}
	t.Logf("records=%d receipts=%d accounted_bytes=%d largest_record_bytes=%d", len(s.store.records), len(s.state.Receipts), s.store.bytes, largest)
}

func TestCapacityByteReservationIncludesGrowingState(t *testing.T) {
	s, _, _ := fixture(t, Options{MaxRecords: 1000})
	c := firewallSample()
	staged := invoke(t, s, OpStage, &c, 0)
	fillCapacityReceipts(t, s, 1021)
	s.store.bytes = maxJournalBytes - 6*maxRecordBytes
	guard := &testGuard{}
	pending, err := s.ExecuteManaged(context.Background(), admin, API, Request{Operation: OpCommit, Key: "byte-commit", ExpectedGeneration: staged.Generation, ConfirmFor: 30 * time.Second}, guard)
	if err != nil {
		t.Fatal(err)
	}
	// Actual serialized records (including the new receipt and pending revision)
	// spend the simulated byte remainder. Record-count capacity stays ample.
	for range 100 {
		if _, err := s.Execute(context.Background(), Principal{ID: "viewer", Role: RoleViewer}, API, Request{Operation: OpSave}); errors.Is(err, ErrStorage) {
			break
		}
	}
	if s.store.capacity(pendingRecords) || len(s.store.records) >= 100 {
		t.Fatal("did not reach the byte-only audit boundary")
	}
	confirmed, err := s.ExecuteManaged(context.Background(), admin, API, Request{Operation: OpConfirm, Key: "byte-confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash}, guard)
	if err != nil || confirmed.Pending != nil || !s.store.capacity(recoveryRecords-1) {
		t.Fatalf("byte reservation failed to cover confirmation and recovery: %v", err)
	}
	logCapacity(t, s)
}

func TestCapacityExpiryAndRequiredRecovery(t *testing.T) {
	for _, failRollback := range []bool{false, true} {
		t.Run(fmt.Sprint(failRollback), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, engines, dir := fixture(t, Options{MaxRecords: 20})
				c := firewallSample()
				initial := status(t, s)
				invoke(t, s, OpStage, &c, 0)
				fillCapacityReceipts(t, s, 1021)
				fillCapacityRecords(t, s, 6)
				invoke(t, s, OpCommit, nil, time.Second)
				if failRollback {
					engines[0].SetFailure(initial.Running.Hash, "before")
				}
				time.Sleep(time.Second)
				synctest.Wait()
				after := status(t, s)
				if s.store.limit-len(s.store.records) != recoveryRecords {
					t.Fatal("expiry did not preserve one final recovery")
				}
				if failRollback {
					if !after.RecoveryRequired {
						t.Fatal("failed rollback was published as verified")
					}
					engines[0].ClearFailure()
					for _, p := range []Principal{{ID: "viewer", Role: RoleViewer}, admin} {
						if _, err := s.Execute(context.Background(), p, API, Request{Operation: OpRecover, Key: "invalid-recover", ExpectedGeneration: after.Generation, Target: "unexpected"}); err == nil {
							t.Fatal("invalid recovery consumed protected budget")
						}
					}
					req := Request{Operation: OpRecover, Key: "last-recovery", ExpectedGeneration: after.Generation}
					recovered, err := s.Execute(context.Background(), admin, API, req)
					if err != nil || recovered.RecoveryRequired || recovered.Pending != nil || recovered.Running.Hash != initial.Running.Hash {
						t.Fatalf("reserved recovery failed: %v", err)
					}
					if _, err := s.Execute(context.Background(), admin, API, req); err != nil {
						t.Fatalf("full journal replay failed: %v", err)
					}
					req.Key, req.ExpectedGeneration = "unbounded-recover", recovered.Generation
					if _, err := s.Execute(context.Background(), admin, API, req); !errors.Is(err, ErrStorage) {
						t.Fatal("healthy recovery bypassed lifetime quota")
					}
					logCapacity(t, s)
					return
				}
				if after.RecoveryRequired || after.Pending != nil || after.Running.Hash != initial.Running.Hash {
					t.Fatal("expiry did not restore previous Running")
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{MaxRecords: 20})
				if err != nil {
					t.Fatalf("reserved reopen after expiry: %v", err)
				}
				defer reopened.Close()
				if status(t, reopened).Running.Hash != initial.Running.Hash {
					t.Fatal("reopen lost rollback result")
				}
				logCapacity(t, reopened)
			})
		})
	}
}

func TestCapacityLastReceiptIsOnlyForRequiredRecovery(t *testing.T) {
	s, _, _ := fixture(t, Options{MaxRecords: 20})
	fillCapacityReceipts(t, s, 1023)
	before := status(t, s)
	req := Request{Operation: OpRecover, Key: "last-receipt", ExpectedGeneration: before.Generation}
	if _, err := s.Execute(context.Background(), admin, API, req); !errors.Is(err, ErrStorage) {
		t.Fatal("healthy recovery consumed reserved receipt")
	}
	// Model a durably recorded failed compensation, independently of record
	// capacity. The ordinary engine-failure tests exercise that producer.
	s.state.Snapshot.RecoveryRequired = true
	if err := s.persist("system", API, "recovery-fixture", "failed", true); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.Execute(context.Background(), admin, API, req)
	if err != nil || recovered.RecoveryRequired || len(s.state.Receipts) != 1024 {
		t.Fatalf("last recovery receipt unavailable: %v", err)
	}
	records := len(s.store.records)
	replayed, err := s.Execute(context.Background(), admin, API, req)
	if err != nil || replayed.ReplayedGeneration != recovered.Generation || len(s.store.records) != records {
		t.Fatalf("full receipt replay failed: %v", err)
	}
	req.Key, req.ExpectedGeneration = "another-recover", recovered.Generation
	if _, err := s.Execute(context.Background(), admin, API, req); !errors.Is(err, ErrStorage) || len(s.state.Receipts) != 1024 {
		t.Fatal("recovery exceeded receipt bound")
	}
	_ = status(t, s)
	if _, err := s.History(admin); err != nil {
		t.Fatal(err)
	}
	logCapacity(t, s)
}

func TestCapacityExhaustedLegacyOpenPreservesFiles(t *testing.T) {
	s, engines, dir := fixture(t, Options{MaxRecords: 12})
	fillCapacityRecords(t, s, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	files := func() map[string]string {
		out := map[string]string{}
		if err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			out[path] = string(data)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := files()
	counted := &countedCapacityEngine{Engine: engines[0]}
	opened, err := Open(dir, []Engine{counted, engines[1]}, Options{MaxRecords: 12})
	if opened != nil {
		_ = opened.Close()
	}
	if !errors.Is(err, ErrStorage) || opened != nil || counted.applies.Load() != 0 || !reflect.DeepEqual(before, files()) {
		t.Fatal("exhausted reopen applied or appended an incomplete intent")
	}
}

func TestCapacityHistoricalRollbackUsesSameReservation(t *testing.T) {
	for _, free := range []int{5, 6} {
		t.Run(fmt.Sprint(free), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, engines, _ := fixture(t, Options{MaxRecords: 24})
				first := commitLocal(t, s, localSample(t, 18443))
				current := commitLocal(t, s, localSample(t, 18444))
				fillCapacityRecords(t, s, free)
				guard := &testGuard{}
				counted := &countedCapacityEngine{Engine: engines[0]}
				s.engines[0] = counted
				r := Request{Operation: OpRollback, Key: "historical-reserve", Target: first.Running.Hash, ExpectedGeneration: current.Generation, ConfirmFor: 30 * time.Second}
				pending, err := s.ExecuteManaged(context.Background(), admin, CLI, r, guard)
				if free == 5 {
					if !errors.Is(err, ErrStorage) || counted.applies.Load() != 0 || guard.arms != 0 || status(t, s).Running.Hash != current.Running.Hash {
						t.Fatal("unsafe historical rollback was admitted")
					}
					return
				}
				if err != nil || pending.Pending == nil || pending.Running.Hash != first.Running.Hash {
					t.Fatalf("historical rollback failed: %v", err)
				}
				r = Request{Operation: OpConfirm, Key: "historical-confirm", Target: pending.Running.Hash, ExpectedGeneration: pending.Generation}
				if confirmed, err := s.ExecuteManaged(context.Background(), admin, CLI, r, guard); err != nil || confirmed.Pending != nil {
					t.Fatalf("historical confirmation failed: %v", err)
				}
			})
		})
	}
}

func TestCapacityRevokedPendingOwnerStillExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, engines, dir := fixture(t, Options{MaxRecords: 20})
		initial := status(t, s)
		c := firewallSample()
		staged := invoke(t, s, OpStage, &c, 0)
		fillCapacityReceipts(t, s, 1020)
		fillCapacityRecords(t, s, 7)
		guard := &testGuard{}
		ctx := context.Background()
		checkBudget := func(free, receipts int) {
			t.Helper()
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.store.limit-len(s.store.records) != free || len(s.state.Receipts) != receipts {
				t.Fatal("transaction did not preserve the expected budget")
			}
		}
		pending, err := s.ExecuteManaged(ctx, admin, API, Request{Operation: OpCommit, Key: "revoke-pending", ExpectedGeneration: staged.Generation, ConfirmFor: 30 * time.Second}, guard)
		if err != nil {
			t.Fatal(err)
		}
		other := Principal{ID: "bob", Role: RoleAdmin}
		revoked, err := s.Execute(ctx, other, CLI, Request{Operation: OpRevoke, Key: "revoke-owner", ExpectedGeneration: pending.Generation, Target: admin.ID})
		if err != nil || revoked.Pending == nil || revoked.Pending.Owner != admin.ID || revoked.Generation != pending.Generation+1 || !reflect.DeepEqual(revoked.Revoked, []string{admin.ID}) {
			t.Fatalf("owner revocation before reserve floor failed: %v", err)
		}
		checkBudget(pendingRecords, 1022)
		for range 8 {
			if _, err := s.ExecuteManaged(ctx, admin, API, Request{Operation: OpConfirm, Key: "revoked-confirm", ExpectedGeneration: revoked.Generation, Target: revoked.Running.Hash}, guard); err == nil {
				t.Fatal("revoked owner confirmed")
			}
		}
		if guard.confirms != 0 {
			t.Fatal("denied confirmation consumed authority")
		}
		checkBudget(pendingRecords, 1022)
		time.Sleep(30 * time.Second)
		synctest.Wait()
		after, err := s.Execute(ctx, other, API, Request{Operation: OpStatus})
		if err != nil || after.Pending != nil || after.RecoveryRequired || after.Running.Hash != initial.Running.Hash {
			t.Fatalf("revoked owner's transaction did not expire safely: %v", err)
		}
		checkBudget(recoveryRecords, 1022)
		for _, engine := range engines {
			if engine.Current() != initial.Running.Hash {
				t.Fatal("expiry did not restore an engine")
			}
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{MaxRecords: 20})
		if err != nil {
			t.Fatalf("reserved recovery after owner revocation failed: %v", err)
		}
		defer reopened.Close()
		out, err := reopened.Execute(ctx, other, API, Request{Operation: OpStatus})
		if err != nil || out.Pending != nil || out.Running.Hash != initial.Running.Hash || !reflect.DeepEqual(out.Revoked, []string{admin.ID}) {
			t.Fatalf("reopen lost rollback or revocation: %v", err)
		}
	})
}

func BenchmarkCapacityAdmission(b *testing.B) {
	s := &Service{store: &fileStore{limit: 2048}, state: durableState{Receipts: make(map[string]receipt)}}
	for i := range 1021 {
		s.state.Receipts[fmt.Sprint(i)] = receipt{}
	}
	r := Request{Operation: OpCommit, ConfirmFor: 30 * time.Second}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !s.requestCapacity(r) {
			b.Fatal("unexpected rejection")
		}
	}
}
