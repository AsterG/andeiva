package configpoc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func unsavedRunning(t *testing.T) (*Service, []*SimEngine, string, Snapshot) {
	t.Helper()
	s, engines, dir := fixture(t, Options{})
	c := sample("confirmed-running")
	invoke(t, s, OpStage, &c, 0)
	running := invoke(t, s, OpCommit, nil, 0)
	if running.Running.Hash == running.Startup.Hash {
		t.Fatal("fixture needs distinct running and startup")
	}
	return s, engines, dir, running
}

func readLastRecord(t *testing.T, dir string) journalRecord {
	t.Helper()
	store, err := openStore(dir, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer store.lock.Close()
	return clone(store.records[len(store.records)-1])
}

func TestBootApplyFailureRetainsConfirmedAnchor(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("pending-%t", pending), func(t *testing.T) {
			s, engines, dir, confirmed := unsavedRunning(t)
			if pending {
				c := sample("unconfirmed")
				invoke(t, s, OpStage, &c, 0)
				invoke(t, s, OpCommit, nil, time.Minute)
			}
			_ = s.Close()
			engines[1].FailNext("after")
			if _, err := Open(dir, []Engine{engines[0], engines[1]}, Options{Boot: true}); !errors.Is(err, ErrEngine) {
				t.Fatal(err)
			}
			for _, engine := range engines {
				if engine.Current() != confirmed.Running.Hash {
					t.Fatal("failed boot did not compensate to confirmed running")
				}
			}
			record := readLastRecord(t, dir)
			if record.State.Snapshot.Running.Hash != confirmed.Running.Hash || record.State.Snapshot.LastGood.Hash != confirmed.Running.Hash || record.State.Snapshot.Pending != nil || record.State.Intent != nil || record.State.Snapshot.RecoveryRequired {
				t.Fatal("failed boot published a different revision")
			}
			if record.Audit.Result != "compensated" {
				t.Fatal("wrong boot audit outcome")
			}
		})
	}
}

func TestBootCompensationFailurePreservesRecoveryAnchor(t *testing.T) {
	s, engines, dir, confirmed := unsavedRunning(t)
	_ = s.Close()
	engines[0].SetFailure(confirmed.Running.Hash, "before")
	engines[1].SetFailure(confirmed.Startup.Hash, "after")
	if _, err := Open(dir, []Engine{engines[0], engines[1]}, Options{Boot: true}); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
	record := readLastRecord(t, dir)
	if !record.State.Snapshot.RecoveryRequired || record.State.Intent == nil || record.State.Intent.Previous.Hash != confirmed.Running.Hash || record.State.Snapshot.LastGood.Hash != confirmed.Running.Hash || record.Audit.Result != "compensation_failed" {
		t.Fatal("failed compensation lost stable anchor")
	}
	for _, engine := range engines {
		engine.ClearFailure()
	}
	s, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if status(t, s).Running.Hash != confirmed.Running.Hash {
		t.Fatal("reopen promoted failed startup")
	}
}

func TestBootWithInterruptedIntentAndStorageFailure(t *testing.T) {
	s, engines, dir, confirmed := unsavedRunning(t)
	c := sample("interrupted")
	invoke(t, s, OpStage, &c, 0)
	before := status(t, s)
	s.hook = func(point string) error {
		if point == "after_apply:first" {
			return ErrInterrupted
		}
		return nil
	}
	if _, err := s.Execute(context.Background(), admin, API, Request{Operation: OpCommit, Key: "interrupted", ExpectedGeneration: before.Generation}); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	_ = s.Close()
	if engines[0].Current() == confirmed.Running.Hash {
		t.Fatal("fixture did not leave partial apply")
	}
	if _, err := Open(dir, []Engine{engines[0], engines[1]}, Options{Boot: true, Hook: func(point string) error {
		if point == "before_persist" {
			return ErrStorage
		}
		return nil
	}}); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
	for _, engine := range engines {
		if engine.Current() != confirmed.Running.Hash {
			t.Fatal("boot storage failure retained interrupted policy")
		}
	}
	record := readLastRecord(t, dir)
	if record.State.Intent == nil || record.State.Intent.Previous.Hash != confirmed.Running.Hash {
		t.Fatal("original durable anchor changed")
	}
}

type rejectingStartupEngine struct {
	*SimEngine
	rejected string
}

func (engine *rejectingStartupEngine) Validate(config Config) error {
	revision, err := Canonical(config)
	if err != nil {
		return err
	}
	if revision.Hash == engine.rejected {
		return ErrInvalid
	}
	return nil
}

func TestBootRecoveryContextsRejectBeforeApply(t *testing.T) {
	for _, state := range []string{"pending", "recovery-required"} {
		for _, fault := range []string{"validation", "storage"} {
			t.Run(state+"-"+fault, func(t *testing.T) {
				s, engines, dir, confirmed := unsavedRunning(t)
				if state == "pending" {
					c := sample("unconfirmed")
					invoke(t, s, OpStage, &c, 0)
					invoke(t, s, OpCommit, nil, time.Minute)
				} else {
					engines[0].Drift("untrusted")
					_, err := s.Execute(context.Background(), admin, API, Request{Operation: OpSave, Key: "detect-drift", ExpectedGeneration: confirmed.Generation})
					if !errors.Is(err, ErrRecovery) {
						t.Fatal(err)
					}
				}
				_ = s.Close()
				options := Options{Boot: true}
				var first Engine = engines[0]
				want := ErrInvalid
				if fault == "validation" {
					first = &rejectingStartupEngine{SimEngine: engines[0], rejected: confirmed.Startup.Hash}
				} else {
					options.Hook = func(point string) error {
						if point == "before_persist" {
							return ErrStorage
						}
						return nil
					}
					want = ErrStorage
				}
				if _, err := Open(dir, []Engine{first, engines[1]}, options); !errors.Is(err, want) {
					t.Fatal(err)
				}
				for _, engine := range engines {
					if engine.Current() != confirmed.Running.Hash {
						t.Fatal("early boot failure left unconfirmed or drifted revision")
					}
				}
				record := readLastRecord(t, dir)
				if record.State.Snapshot.LastGood.Hash != confirmed.Running.Hash {
					t.Fatal("safe revision changed")
				}
			})
		}
	}
}

func TestBootProcessInterruption(t *testing.T) {
	if os.Getenv("ANDEIVA_POC_BOOT_CHILD") == "1" {
		_, err := Open(os.Getenv("ANDEIVA_POC_BOOT_STATE"), []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{Boot: true, Hook: func(point string) error {
			if point == "after_apply:first" {
				os.Exit(73)
			}
			return nil
		}})
		t.Fatalf("boot interruption missed: %v", err)
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux only")
	}
	s, _, dir, confirmed := unsavedRunning(t)
	_ = s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBootProcessInterruption$")
	command.Env = append(os.Environ(), "ANDEIVA_POC_BOOT_CHILD=1", "ANDEIVA_POC_BOOT_STATE="+dir)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 73 {
		t.Fatalf("child did not interrupt: %v", err)
	}
	record := readLastRecord(t, dir)
	if record.State.Intent == nil || record.State.Intent.Previous.Hash != confirmed.Running.Hash {
		t.Fatal("boot intent has wrong compensation anchor")
	}
	s, err = Open(dir, []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if status(t, s).Running.Hash != confirmed.Running.Hash {
		t.Fatal("interrupted boot promoted startup")
	}
}

func writePending(t *testing.T, dir, name string, size int64) string {
	t.Helper()
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBoundedOrphanCleanupDoesNotConsumeJournalBudget(t *testing.T) {
	s, _, dir := fixture(t, Options{})
	_ = s.Close()
	before, err := os.ReadFile(filepath.Join(dir, "00000001.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Sparse staging files exceed the committed journal budget without allocating it.
	for i := 0; i < 65; i++ {
		writePending(t, dir, fmt.Sprintf(".pending-%d", i), maxRecordBytes)
	}
	store, err := openStore(dir, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer store.lock.Close()
	if store.bytes >= maxJournalBytes {
		t.Fatal("orphan bytes retained in committed journal accounting")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(store.records)+1 {
		t.Fatal("orphans not removed")
	}
	after, err := os.ReadFile(filepath.Join(dir, "00000001.json"))
	if err != nil || string(before) != string(after) {
		t.Fatal("committed audit modified")
	}
}

func TestOrphanCleanupRequiresExclusiveLock(t *testing.T) {
	s, _, dir := fixture(t, Options{})
	pending := writePending(t, dir, ".pending-1", 0)
	if store, err := openStore(dir, 2048); !errors.Is(err, ErrLocked) {
		if store != nil {
			_ = store.lock.Close()
		}
		t.Fatal("cleanup ignored writer lock")
	}
	if _, err := os.Lstat(pending); err != nil {
		t.Fatal("locked store lost staging file")
	}
	_ = s.Close()
	store, err := openStore(dir, 2048)
	if err != nil {
		t.Fatal(err)
	}
	defer store.lock.Close()
	if _, err := os.Lstat(pending); !os.IsNotExist(err) {
		t.Fatal("orphan was not removed after locking")
	}
}

func TestInvalidOrExcessOrphansPreserveEvidence(t *testing.T) {
	for _, kind := range []string{"name", "symlink", "mode", "size", "count", "committed-corruption"} {
		t.Run(kind, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			_ = s.Close()
			keep := writePending(t, dir, ".pending-1", 0)
			switch kind {
			case "name":
				writePending(t, dir, ".pending-not-generated", 0)
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "00000001.json"), filepath.Join(dir, ".pending-2")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				path := writePending(t, dir, ".pending-2", 0)
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "size":
				writePending(t, dir, ".pending-2", maxRecordBytes+1)
			case "count":
				for i := 2; i <= 129; i++ {
					writePending(t, dir, fmt.Sprintf(".pending-%d", i), 0)
				}
			case "committed-corruption":
				if err := os.WriteFile(filepath.Join(dir, "00000001.json"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if store, err := openStore(dir, 2048); !errors.Is(err, ErrStorage) {
				if store != nil {
					_ = store.lock.Close()
				}
				t.Fatalf("invalid evidence accepted: %v", err)
			}
			if _, err := os.Lstat(keep); err != nil {
				t.Fatal("cleanup ran before full validation")
			}
		})
	}
}
