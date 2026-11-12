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
	"testing"
	"time"
)

func TestJournalDestinationCreatedAfterGuardIsNotOverwritten(t *testing.T) {
	for _, kind := range []string{"regular", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			armed := false
			afterGuard := make(chan struct{})
			created := make(chan error, 1)
			hit := false
			s, engines, dir := fixture(t, Options{Hook: func(point string) error {
				if armed && point == "after_record_destination_check" {
					hit = true
					close(afterGuard)
					return <-created
				}
				return nil
			}})
			before := journalFiles(t, dir)
			latest := clone(s.store.latest)
			records := len(s.store.records)
			destination := filepath.Join(dir, fmt.Sprintf("%08d.json", records+1))
			foreign := []byte("foreign entry created after the absence check")
			target := filepath.Join(t.TempDir(), "foreign-target")
			if err := os.WriteFile(target, foreign, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var foreignInfo os.FileInfo
			go func() {
				select {
				case <-afterGuard:
				case <-ctx.Done():
					created <- ctx.Err()
					return
				}
				if kind == "regular" {
					file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if err != nil {
						created <- err
						return
					}
					_, writeErr := file.Write(foreign)
					syncErr := file.Sync()
					closeErr := file.Close()
					if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
						created <- err
						return
					}
				} else if err := os.Symlink(target, destination); err != nil {
					created <- err
					return
				}
				var err error
				foreignInfo, err = os.Lstat(destination)
				created <- err
			}()
			current := status(t, s)
			config := sample("not-published")
			armed = true
			_, err := s.Execute(context.Background(), admin, Web, Request{Operation: OpStage, Key: "race-stage", ExpectedGeneration: current.Generation, Config: &config})
			if !hit || !errors.Is(err, ErrStorage) {
				t.Fatal("collision after guard was not refused", err)
			}
			actualInfo, err := os.Lstat(destination)
			if err != nil || !os.SameFile(foreignInfo, actualInfo) {
				t.Fatal("foreign inode overwritten", err)
			}
			actualBytes, err := os.ReadFile(destination)
			if err != nil || !bytes.Equal(foreign, actualBytes) {
				t.Fatal("foreign bytes changed", err)
			}
			if kind == "symlink" {
				link, err := os.Readlink(destination)
				if err != nil || link != target {
					t.Fatal("foreign link changed", err)
				}
			}
			for name, data := range before {
				after, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(data, after) {
					t.Fatal("protected journal changed", name, err)
				}
			}
			if len(s.store.records) != records || !reflect.DeepEqual(latest, s.store.latest) {
				t.Fatal("failed write published committed metadata")
			}
			for _, engine := range engines {
				if engine.Current() != latest.Snapshot.Running.Hash {
					t.Fatal("failed write changed engine policy")
				}
			}
			if _, err := s.Execute(context.Background(), admin, API, Request{Operation: OpStatus}); !errors.Is(err, ErrRecovery) {
				t.Fatal("uncertain coordinator remained mutable", err)
			}
			if _, err := os.Lstat(filepath.Join(dir, stagingDirectory, stagingPayload)); !os.IsNotExist(err) {
				t.Fatal("owned staging payload not cleaned", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(dir, []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{}); !errors.Is(err, ErrStorage) {
				if reopened != nil {
					_ = reopened.Close()
				}
				t.Fatal("foreign malformed tail silently accepted", err)
			}
			finalInfo, err := os.Lstat(destination)
			if err != nil || !os.SameFile(foreignInfo, finalInfo) {
				t.Fatal("reopen removed foreign entry", err)
			}
			// The test owns this deliberately invalid entry. The store never
			// deletes it; remove only the verified fixture to test v1 recovery.
			if err := os.Remove(destination); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(dir, []Engine{NewSimEngine("first"), NewSimEngine("second")}, Options{})
			if err != nil {
				t.Fatal("source state no longer recoverable", err)
			}
			defer func() { _ = reopened.Close() }()
			if status(t, reopened).Candidate != nil || status(t, reopened).Running.Hash != latest.Snapshot.Running.Hash {
				t.Fatal("uncommitted candidate recovered as committed")
			}
			for name, data := range before {
				if !reflect.DeepEqual(data, journalFiles(t, dir)[name]) {
					t.Fatal("protected history changed after recovery", name)
				}
			}
		})
	}
}
