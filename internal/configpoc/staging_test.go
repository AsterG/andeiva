package configpoc

import (
	"bytes"
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

func TestStagingProcessInterruption(t *testing.T) {
	if point := os.Getenv("ANDEIVA_POC_STAGE_CHILD"); point != "" {
		store, err := openStore(os.Getenv("ANDEIVA_POC_STAGE_STATE"), 2048)
		if err != nil {
			t.Fatal(err)
		}
		defer store.lock.Close()
		last := store.records[len(store.records)-1]
		err = store.append(last.State, last.Audit, false, func(actual string) error {
			if actual == point {
				os.Exit(74)
			}
			return nil
		})
		t.Fatalf("interruption hook missed: %v", err)
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux durability experiment")
	}
	for _, point := range []string{"after_stage_create", "after_stage_partial_write", "after_stage_sync", "before_publish", "after_rename"} {
		t.Run(point, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			_ = s.Close()
			before, err := os.ReadFile(filepath.Join(dir, "00000001.json"))
			if err != nil {
				t.Fatal(err)
			}
			count := len(s.store.records)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStagingProcessInterruption$")
			command.Env = append(os.Environ(), "ANDEIVA_POC_STAGE_CHILD="+point, "ANDEIVA_POC_STAGE_STATE="+dir)
			err = command.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 74 {
				t.Fatalf("child did not stop at %s: %v", point, err)
			}
			payload := filepath.Join(dir, stagingDirectory, stagingPayload)
			info, err := os.Lstat(payload)
			if point == "after_rename" {
				if !os.IsNotExist(err) {
					t.Fatal("published payload remains staged")
				}
				count++
			} else if err != nil || (point == "after_stage_create" && info.Size() != 0) || (point != "after_stage_create" && info.Size() == 0) {
				t.Fatal("crash did not leave expected incomplete payload")
			}
			store, err := openStore(dir, 2048)
			if err != nil {
				t.Fatal(err)
			}
			defer store.lock.Close()
			if len(store.records) != count {
				t.Fatal("recovery lost or invented committed records")
			}
			if _, err := os.Lstat(payload); !os.IsNotExist(err) {
				t.Fatal("registered interrupted payload not removed")
			}
			after, err := os.ReadFile(filepath.Join(dir, "00000001.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("committed audit changed")
			}
		})
	}
}

func TestStagingOwnershipFailuresPreservePayload(t *testing.T) {
	for _, kind := range []string{"registration-missing", "marker-missing", "registration-empty", "marker-partial", "marker-mismatch", "marker-oversized", "marker-mode", "marker-symlink", "marker-hardlink", "directory-mode", "directory-symlink", "unregistered-clone", "lock-hardlink"} {
		t.Run(kind, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			_ = s.Close()
			stage := filepath.Join(dir, stagingDirectory)
			marker := filepath.Join(stage, stagingMarker)
			registration := filepath.Join(dir, stagingRegistration)
			payload := writePending(t, stage, stagingPayload, 13)
			var err error
			switch kind {
			case "registration-missing":
				err = os.Remove(registration)
			case "marker-missing":
				err = os.Remove(marker)
			case "registration-empty":
				err = os.Truncate(registration, 0)
			case "marker-partial":
				err = os.WriteFile(marker, []byte(`{"format":`), 0600)
			case "marker-mismatch":
				err = os.WriteFile(marker, []byte(`{"format":"andeiva.config.staging.v1","store_id":"00000000000000000000000000000000"}`), 0600)
			case "marker-oversized":
				err = os.Truncate(marker, maxMarkerBytes+1)
			case "marker-mode":
				err = os.Chmod(marker, 0644)
			case "marker-symlink", "marker-hardlink":
				if err = os.Remove(marker); err == nil {
					if kind == "marker-symlink" {
						err = os.Symlink(registration, marker)
					} else {
						err = os.Link(registration, marker)
					}
				}
			case "directory-mode":
				err = os.Chmod(stage, 0755)
			case "directory-symlink":
				relocated := filepath.Join(t.TempDir(), "relocated")
				if err = os.Rename(stage, relocated); err == nil {
					err = os.Symlink(relocated, stage)
				}
			case "unregistered-clone":
				if err = os.Remove(marker); err == nil {
					err = os.Remove(registration)
				}
			case "lock-hardlink":
				err = os.Link(filepath.Join(dir, "state.lock"), filepath.Join(t.TempDir(), "lock-copy"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if store, err := openStore(dir, 2048); !errors.Is(err, ErrStorage) {
				if store != nil {
					_ = store.lock.Close()
				}
				t.Fatalf("unsafe ownership accepted: %v", err)
			}
			info, err := os.Stat(payload)
			if err != nil || info.Size() != 13 {
				t.Fatal("unverified payload deleted or modified")
			}
		})
	}
}

func TestStagingBootstrapRequiresCompleteJournal(t *testing.T) {
	for _, kind := range []string{"clean", "corrupt", "unknown", "registration-only"} {
		t.Run(kind, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			_ = s.Close()
			before, err := os.ReadFile(filepath.Join(dir, "00000001.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, stagingDirectory, stagingMarker)); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, stagingDirectory)); err != nil {
				t.Fatal(err)
			}
			if kind != "registration-only" {
				if err := os.Remove(filepath.Join(dir, stagingRegistration)); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "corrupt":
				if err := os.WriteFile(filepath.Join(dir, "00000001.json"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				writePending(t, dir, ".pending-legacy", 0)
			}
			store, err := openStore(dir, 2048)
			if kind != "clean" {
				if !errors.Is(err, ErrStorage) {
					if store != nil {
						_ = store.lock.Close()
					}
					t.Fatal("invalid bootstrap repaired automatically")
				}
				if _, err := os.Lstat(filepath.Join(dir, stagingDirectory)); !os.IsNotExist(err) {
					t.Fatal("bootstrap mutated invalid store")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer store.lock.Close()
			root, err := store.openScopedRoot()
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if _, err := store.validateStaging(root); err != nil {
				t.Fatal("clean journal not adopted")
			}
			after, err := os.ReadFile(filepath.Join(dir, "00000001.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("adoption modified audit")
			}
		})
	}
}

func TestStagingPublicationRejectsChangedMetadataAndExistingTarget(t *testing.T) {
	for _, kind := range []string{"existing-target", "payload-hardlink", "payload-replaced", "unexpected-entry", "marker-changed"} {
		t.Run(kind, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			store := s.store
			last := store.records[len(store.records)-1]
			final := filepath.Join(dir, fmt.Sprintf("%08d.json", len(store.records)+1))
			payload := filepath.Join(dir, stagingDirectory, stagingPayload)
			canary := []byte("unrelated content")
			err := store.append(last.State, last.Audit, false, func(point string) error {
				if point != "before_publish" {
					return nil
				}
				switch kind {
				case "existing-target":
					return os.WriteFile(final, canary, 0600)
				case "payload-hardlink":
					return os.Link(payload, filepath.Join(t.TempDir(), "foreign-link"))
				case "payload-replaced":
					if err := os.Rename(payload, filepath.Join(t.TempDir(), "old-payload")); err != nil {
						return err
					}
					return os.WriteFile(payload, canary, 0600)
				case "unexpected-entry":
					return os.WriteFile(filepath.Join(dir, stagingDirectory, "foreign.tmp"), canary, 0600)
				case "marker-changed":
					return os.WriteFile(filepath.Join(dir, stagingDirectory, stagingMarker), canary, 0600)
				}
				return nil
			})
			if !errors.Is(err, ErrStorage) {
				t.Fatalf("unsafe publication accepted: %v", err)
			}
			data, err := os.ReadFile(final)
			if kind == "existing-target" {
				if err != nil || !bytes.Equal(data, canary) {
					t.Fatal("existing committed path overwritten")
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("changed staging data published")
			}
			if kind == "payload-replaced" {
				data, err := os.ReadFile(payload)
				if err != nil || !bytes.Equal(data, canary) {
					t.Fatal("replaced payload deleted")
				}
			}
		})
	}
}
