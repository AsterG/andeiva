//go:build linux

package configpoc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func journalPublishPayload(t *testing.T, s *Service) (*os.Root, os.FileInfo, []byte) {
	t.Helper()
	root, err := s.store.openScopedRoot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	name := filepath.Join(s.store.dir, stagingDirectory, stagingPayload)
	data := []byte("owned staging bytes retained after syscall refusal")
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return root, info, data
}

func TestJournalUnsupportedNoReplaceDoesNotFallBack(t *testing.T) {
	for _, errno := range []error{unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			root, sourceInfo, sourceBytes := journalPublishPayload(t, s)
			before := journalFiles(t, dir)
			latest := clone(s.store.latest)
			sequence := uint64(len(s.store.records)) + 1
			rootInfo, err := root.Stat(".")
			if err != nil {
				t.Fatal(err)
			}
			stageInfo, err := root.Lstat(stagingDirectory)
			if err != nil {
				t.Fatal(err)
			}
			rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("missing root identity")
			}
			stageStat, ok := stageInfo.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("missing staging identity")
			}
			called := 0
			err = s.store.renameJournalRecord(root, sequence, sourceInfo, func(oldFD int, oldName string, newFD int, newName string, flags uint) error {
				called++
				if oldFD == newFD || oldName != stagingPayload || newName != fmt.Sprintf("%08d.json", sequence) || flags != unix.RENAME_NOREPLACE {
					t.Fatal("unsafe rename arguments")
				}
				var source, destination unix.Stat_t
				if err := unix.Fstat(oldFD, &source); err != nil || source.Ino != stageStat.Ino || uint64(source.Dev) != uint64(stageStat.Dev) {
					t.Fatal("unbound source directory", err)
				}
				if err := unix.Fstat(newFD, &destination); err != nil || destination.Ino != rootStat.Ino || uint64(destination.Dev) != uint64(rootStat.Dev) {
					t.Fatal("unbound destination directory", err)
				}
				return errno
			})
			if !errors.Is(err, ErrStorage) || called != 1 {
				t.Fatal("unsupported syscall retried or accepted", err, called)
			}
			if _, err := os.Lstat(filepath.Join(dir, fmt.Sprintf("%08d.json", sequence))); !os.IsNotExist(err) {
				t.Fatal("fallback published a record", err)
			}
			afterInfo, err := os.Stat(filepath.Join(dir, stagingDirectory, stagingPayload))
			if err != nil || !os.SameFile(sourceInfo, afterInfo) {
				t.Fatal("source inode lost", err)
			}
			afterBytes, err := os.ReadFile(filepath.Join(dir, stagingDirectory, stagingPayload))
			if err != nil || !bytes.Equal(sourceBytes, afterBytes) {
				t.Fatal("source bytes changed", err)
			}
			if !reflect.DeepEqual(before, journalFiles(t, dir)) || !reflect.DeepEqual(latest, s.store.latest) {
				t.Fatal("unsupported syscall changed committed state")
			}
		})
	}
}

func TestJournalNoReplaceAcceptsOnlyNextBoundedSequence(t *testing.T) {
	s, _, dir := fixture(t, Options{})
	root, sourceInfo, _ := journalPublishPayload(t, s)
	before := journalFiles(t, dir)
	for _, sequence := range []uint64{0, 1, uint64(len(s.store.records)), uint64(len(s.store.records)) + 2, 100000000, ^uint64(0)} {
		t.Run(fmt.Sprint(sequence), func(t *testing.T) {
			called := false
			err := s.store.renameJournalRecord(root, sequence, sourceInfo, func(int, string, int, string, uint) error { called = true; return nil })
			if !errors.Is(err, ErrStorage) || called {
				t.Fatal("invalid sequence reached syscall", err)
			}
		})
	}
	limit := s.store.limit
	s.store.limit = len(s.store.records)
	called := false
	err := s.store.renameJournalRecord(root, uint64(len(s.store.records))+1, sourceInfo, func(int, string, int, string, uint) error { called = true; return nil })
	s.store.limit = limit
	if !errors.Is(err, ErrStorage) || called {
		t.Fatal("capacity guard bypassed", err)
	}
	foreignPath := filepath.Join(t.TempDir(), "other")
	if err := os.Mkdir(foreignPath, 0700); err != nil {
		t.Fatal(err)
	}
	foreignRoot, err := os.OpenRoot(foreignPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreignRoot.Close() }()
	err = s.store.renameJournalRecord(foreignRoot, uint64(len(s.store.records))+1, sourceInfo, func(int, string, int, string, uint) error { called = true; return nil })
	if !errors.Is(err, ErrStorage) || called {
		t.Fatal("foreign root reached syscall", err)
	}
	if !reflect.DeepEqual(before, journalFiles(t, dir)) {
		t.Fatal("invalid request changed source history")
	}
}

func TestJournalChangedStagingDoesNotDeleteReplacement(t *testing.T) {
	for _, kind := range []string{"regular", "mode", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			armed := false
			var foreignInfo os.FileInfo
			var ownedPath, payloadPath, target string
			foreign := []byte("replacement not created by this append")
			s, engines, dir := fixture(t, Options{Hook: func(point string) error {
				if !armed || point != "after_record_destination_check" {
					return nil
				}
				if err := os.Rename(payloadPath, ownedPath); err != nil {
					return err
				}
				if kind == "symlink" {
					if err := os.Symlink(target, payloadPath); err != nil {
						return err
					}
				} else {
					mode := os.FileMode(0600)
					if kind == "mode" {
						mode = 0644
					}
					if err := os.WriteFile(payloadPath, foreign, mode); err != nil {
						return err
					}
				}
				var err error
				foreignInfo, err = os.Lstat(payloadPath)
				return err
			}})
			ownedPath = filepath.Join(t.TempDir(), "owned-original")
			payloadPath = filepath.Join(dir, stagingDirectory, stagingPayload)
			target = filepath.Join(t.TempDir(), "foreign-target")
			if err := os.WriteFile(target, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			before := journalFiles(t, dir)
			latest := clone(s.store.latest)
			records := len(s.store.records)
			current := status(t, s)
			config := sample("not-published")
			armed = true
			_, err := s.Execute(context.Background(), admin, CLI, Request{Operation: OpStage, Key: "source-race", ExpectedGeneration: current.Generation, Config: &config})
			if !errors.Is(err, ErrStorage) {
				t.Fatal("substituted source published", err)
			}
			actualInfo, err := os.Lstat(payloadPath)
			if err != nil || !os.SameFile(foreignInfo, actualInfo) {
				t.Fatal("deferred cleanup deleted replacement", err)
			}
			actual, err := os.ReadFile(payloadPath)
			if err != nil || !bytes.Equal(foreign, actual) {
				t.Fatal("replacement changed", err)
			}
			if !reflect.DeepEqual(before, journalFiles(t, dir)) || !reflect.DeepEqual(latest, s.store.latest) {
				t.Fatal("substituted staging changed committed state")
			}
			if _, err := os.Lstat(filepath.Join(dir, fmt.Sprintf("%08d.json", records+1))); !os.IsNotExist(err) {
				t.Fatal("substitution reached destination", err)
			}
			for _, engine := range engines {
				if engine.Current() != latest.Snapshot.Running.Hash {
					t.Fatal("substitution changed enforcement")
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if kind != "regular" {
				if reopened, err := Open(dir, []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{}); !errors.Is(err, ErrStorage) {
					if reopened != nil {
						_ = reopened.Close()
					}
					t.Fatal("unsafe staging reopened", err)
				}
				actualInfo, err := os.Lstat(payloadPath)
				if err != nil || !os.SameFile(foreignInfo, actualInfo) {
					t.Fatal("reopen removed unsafe staging", err)
				}
			}
			// The existing v1 ownership registration declares a regular 0600
			// payload in its staging namespace owned on reopen. It cannot prove
			// another same-UID writer's intent across processes. This fixture
			// removes only its own verified replacement before testing recovery.
			if err := os.Remove(payloadPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(ownedPath, payloadPath); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir, []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{})
			if err != nil {
				t.Fatal("registered interrupted append did not recover", err)
			}
			defer func() { _ = reopened.Close() }()
			if status(t, reopened).Candidate != nil || status(t, reopened).Running.Hash != latest.Snapshot.Running.Hash {
				t.Fatal("unpublished state recovered as committed")
			}
		})
	}
}
