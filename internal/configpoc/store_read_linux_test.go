//go:build linux

package configpoc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func journalFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(path)] = data
	}
	return out
}

func TestStoreReadV1GoldenUnchanged(t *testing.T) {
	dir, count, _ := readFixture(t, "small")
	before := journalFiles(t, dir)
	digest := sha256.New()
	for i := 1; i <= count; i++ {
		_, _ = digest.Write(before[fmt.Sprintf("%08d.json", i)])
	}
	// Captured from the unchanged v1 writer at 3d0ddb1 with this fixed fixture.
	if hex.EncodeToString(digest.Sum(nil)) != "9e28e78cd3f2bd733b45871f56bc64bd1291b84bcd1ecbd713eaea80c763e9d1" {
		t.Fatal("legacy v1 journal encoding changed")
	}
	store, err := openStore(dir, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer store.lock.Close()
	for sequence := 1; sequence <= count; sequence++ {
		record, err := store.read(uint64(sequence))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(record)
		if err != nil || !bytes.Equal(encoded, before[fmt.Sprintf("%08d.json", sequence)]) {
			t.Fatalf("v1 bytes changed at sequence %d: %v", sequence, err)
		}
	}
	if !reflect.DeepEqual(before, journalFiles(t, dir)) {
		t.Fatal("read-only store open/read changed journal")
	}
	if _, err := store.read(0); !errors.Is(err, ErrInvalid) || store.readFailed {
		t.Fatal("invalid internal sequence changed integrity state")
	}
	if _, err := store.read(^uint64(0)); !errors.Is(err, ErrInvalid) || store.readFailed {
		t.Fatal("out-of-bounds sequence was accepted")
	}
}

func TestStoreHistoricalReadRejectsChangedFiles(t *testing.T) {
	for _, mutation := range []string{"replacement", "symlink", "fifo", "mode", "hardlink", "truncated", "oversized", "rehash"} {
		t.Run(mutation, func(t *testing.T) {
			dir, _, _ := readFixture(t, "small")
			store, err := openStore(dir, 2048)
			if err != nil {
				t.Fatal(err)
			}
			defer store.lock.Close()
			path := filepath.Join(dir, "00000001.json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "canary")
			if err := os.WriteFile(outside, original, 0600); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "replacement":
				err = os.Rename(outside, path)
			case "symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink(outside, path)
				}
			case "mode":
				err = os.Chmod(path, 0640)
			case "fifo":
				if err = os.Remove(path); err == nil {
					err = syscall.Mkfifo(path, 0600)
				}
			case "hardlink":
				err = os.Link(path, filepath.Join(t.TempDir(), "link"))
			case "truncated":
				err = os.Truncate(path, 1)
			case "oversized":
				err = os.Truncate(path, maxRecordBytes+1)
			case "rehash":
				var record journalRecord
				if err = json.Unmarshal(original, &record); err != nil {
					t.Fatal(err)
				}
				record.Audit.Result = "no" // same length as "ok", valid structure and recomputed hash
				record.Hash = recordHash(record)
				data, marshalErr := json.Marshal(record)
				if marshalErr != nil || len(data) != len(original) {
					t.Fatal("invalid equal-size tampering fixture")
				}
				err = os.WriteFile(path, data, 0600)
				if err == nil {
					stamp := store.records[0].info.ModTime()
					err = os.Chtimes(path, stamp, stamp)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.read(1); !errors.Is(err, ErrStorage) || !store.readFailed {
				t.Fatalf("accepted %s: %v", mutation, err)
			}
			if mutation != "replacement" {
				canary, err := os.ReadFile(outside)
				if err != nil || !bytes.Equal(canary, original) {
					t.Fatal("read changed an unrelated file")
				}
			}
		})
	}
}

func TestStoreReadFailureBlocksFreshWritesBeforeEffects(t *testing.T) {
	s, engines, dir, confirmed := unsavedRunning(t)
	before := status(t, s)
	if err := os.Chmod(filepath.Join(dir, fmt.Sprintf("%08d.json", len(s.store.records))), 0644); err != nil {
		t.Fatal(err)
	}
	// Authorization must precede disk access, even when historical files are bad.
	if _, err := s.Revisions(Principal{ID: "nobody", Role: RoleViewer}, 0, 100); !errors.Is(err, ErrDenied) || s.store.readFailed {
		t.Fatalf("unauthorized history touched storage: %v", err)
	}
	if revisions, err := s.Revisions(admin, 0, 100); !errors.Is(err, ErrStorage) || revisions != nil {
		t.Fatal("returned partial or unverified revision history")
	}
	if history, err := s.History(admin); !errors.Is(err, ErrStorage) || history != nil {
		t.Fatal("concealed known journal integrity failure")
	}
	if !status(t, s).RecoveryRequired {
		t.Fatal("status concealed journal integrity failure")
	}
	count := len(s.store.records)
	for _, operation := range []string{OpSave, OpRecover, OpRollback} {
		guard := &admissionGuard{check: func(Request, Snapshot, *Revision) error {
			t.Fatal("fresh mutation reached admission after storage failure")
			return nil
		}}
		_, err := s.ExecuteManaged(context.Background(), admin, API, Request{Operation: operation, Key: operation + "-read-failure", ExpectedGeneration: before.Generation, Target: confirmed.Startup.Hash}, guard)
		if !errors.Is(err, ErrStorage) || len(s.store.records) != count {
			t.Fatalf("fresh %s after read failure: %v", operation, err)
		}
	}
	for _, engine := range engines {
		if engine.Current() != before.Running.Hash {
			t.Fatal("historical failure changed an engine")
		}
	}
}

func TestStoreReadFailureDoesNotCancelPendingSafety(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, engines, dir := fixture(t, Options{})
		initial := status(t, s)
		config := sample("pending-read")
		invoke(t, s, OpStage, &config, 0)
		confirmedSequence := len(s.store.records)
		pending := invoke(t, s, OpCommit, nil, time.Minute)
		count := confirmedSequence + 2 // commit intent and applied outcome
		if err := os.Chmod(filepath.Join(dir, fmt.Sprintf("%08d.json", confirmedSequence)), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Revisions(admin, 0, 100); !errors.Is(err, ErrStorage) {
			t.Fatal(err)
		}
		_, err := s.Execute(context.Background(), admin, API, Request{Operation: OpConfirm, Key: "confirm-read-failure", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash})
		if !errors.Is(err, ErrStorage) {
			t.Fatal("confirmed a state with untrusted history")
		}
		// A rejected request must also fail before append, rather than turning a
		// read-integrity latch into an unrelated write-failure emergency path.
		_, err = s.Execute(context.Background(), Principal{ID: "viewer", Role: RoleViewer}, API, Request{Operation: OpSave})
		if !errors.Is(err, ErrStorage) {
			t.Fatal("unauditable rejection was hidden")
		}
		s.mu.Lock()
		stillPending, halted := s.state.Snapshot.Pending != nil, s.halted
		s.mu.Unlock()
		if !stillPending || halted {
			t.Fatal("rejected request disturbed the pending safety timer")
		}
		time.Sleep(time.Minute + time.Second)
		synctest.Wait()
		s.mu.Lock()
		actualCount := len(s.store.records)
		automaticRollback := s.state.Snapshot.Pending == nil && !s.halted
		s.mu.Unlock()
		if !automaticRollback || actualCount != count+2 {
			t.Fatal("autonomous pending safety rollback was lost")
		}
		if !status(t, s).RecoveryRequired {
			t.Fatal("rollback concealed the journal integrity failure")
		}
		for _, engine := range engines {
			if engine.Current() != initial.Running.Hash {
				t.Fatal("pending rollback did not restore last known running")
			}
		}
	})
}

func TestStoreReadKeepsAuditSnapshotAndCompleteReplay(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	config := sample("receipt-source")
	request := Request{Operation: OpStage, Key: "original-stage", ExpectedGeneration: status(t, s).Generation, Config: &config}
	staged, err := s.Execute(context.Background(), admin, Web, request)
	if err != nil {
		t.Fatal(err)
	}
	active := invoke(t, s, OpCommit, nil, 0)
	invoke(t, s, OpSave, nil, 0)
	receipts := clone(s.state.Receipts)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !reflect.DeepEqual(receipts, s.state.Receipts) || !reflect.DeepEqual(receipts, s.store.latest.Receipts) {
		t.Fatal("reopen discarded durable operation keys")
	}
	count := len(s.store.records)
	replayed, err := s.Execute(context.Background(), admin, Web, request)
	if err != nil || replayed.ReplayedGeneration != staged.Generation || replayed.Running.Hash != active.Running.Hash || replayed.Generation != s.state.Snapshot.Generation || len(s.store.records) != count {
		t.Fatalf("legacy replay changed its result contract: %v", err)
	}
	before, err := s.History(admin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "00000001.json"), 0644); err != nil {
		t.Fatal(err)
	}
	after, err := s.History(admin)
	if err != nil || !reflect.DeepEqual(before, after) || s.store.readFailed {
		t.Fatal("History no longer returns the validated open/append snapshot")
	}
	after[0].Actor = "changed-copy"
	again, err := s.History(admin)
	if err != nil || !reflect.DeepEqual(before, again) {
		t.Fatal("audit copy alias")
	}
}

func TestStoreRollbackReadErrorIsNotAnUnknownTarget(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed-%t", managed), func(t *testing.T) {
			s, engines, dir, active := unsavedRunning(t)
			probe := &admissionEngine{SimEngine: engines[0]}
			s.engines = []Engine{probe}
			count := len(s.store.records)
			if err := os.Remove(filepath.Join(dir, fmt.Sprintf("%08d.json", count))); err != nil {
				t.Fatal(err)
			}
			guard := &admissionGuard{check: func(Request, Snapshot, *Revision) error {
				t.Fatal("unverified target reached activation admission")
				return nil
			}}
			request := Request{Operation: OpRollback, Key: "read-error-target", ExpectedGeneration: active.Generation, Target: active.Running.Hash}
			var err error
			if managed {
				_, err = s.ExecuteManaged(context.Background(), admin, API, request, guard)
			} else {
				_, err = s.Execute(context.Background(), admin, API, request)
			}
			if !errors.Is(err, ErrStorage) || probe.applies.Load() != 0 || guard.checks != 0 || len(s.store.records) != count || !s.store.readFailed {
				t.Fatalf("storage miss was re-admitted or treated as an ordinary bad target: %v", err)
			}
		})
	}
}
