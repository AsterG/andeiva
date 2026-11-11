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
	"time"

	"golang.org/x/sys/unix"
)

func TestCheckpointDestinationCreatedAfterGuardIsNotOverwritten(t *testing.T) {
	for _, slot := range []int{1, 2} {
		for _, kind := range []string{"regular", "symlink"} {
			t.Run(fmt.Sprintf("slot-%d/%s", slot, kind), func(t *testing.T) {
				s, _, dir := fixture(t, Options{})
				area, path := checkpointFixtureArea(t)
				var selectedBefore []byte
				var firstBefore []byte
				if slot == 2 {
					if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
						t.Fatal(err)
					}
					var err error
					selectedBefore, err = os.ReadFile(filepath.Join(path, checkpointManifestName))
					if err != nil {
						t.Fatal(err)
					}
					firstBefore, err = os.ReadFile(filepath.Join(path, "checkpoint-1.json"))
					if err != nil {
						t.Fatal(err)
					}
					invoke(t, s, OpStage, ptrCheckpointConfig(sample("new")), 0)
				}
				before := journalFiles(t, dir)
				name := fmt.Sprintf("checkpoint-%d.json", slot)
				destination := filepath.Join(path, name)
				target := filepath.Join(t.TempDir(), "foreign-target")
				foreign := []byte("file from a writer that does not take the checkpoint lock")
				if err := os.WriteFile(target, foreign, 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				afterGuard := make(chan struct{})
				written := make(chan error, 1)
				var destinationInfo os.FileInfo
				go func() {
					select {
					case <-afterGuard:
					case <-ctx.Done():
						written <- ctx.Err()
						return
					}
					if kind == "symlink" {
						if err := os.Symlink(target, destination); err != nil {
							written <- err
							return
						}
					} else {
						file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
						if err != nil {
							written <- err
							return
						}
						_, writeErr := file.Write(foreign)
						syncErr := file.Sync()
						closeErr := file.Close()
						if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
							written <- err
							return
						}
					}
					var err error
					destinationInfo, err = os.Lstat(destination)
					written <- err
				}()
				hit := false
				var temporaryInfo os.FileInfo
				var temporaryBytes []byte
				err := s.prepareCheckpoint(area, checkpointOptions{hook: func(point string) error {
					if point != "after_image_destination_check" {
						return nil
					}
					hit = true
					var err error
					temporaryInfo, err = os.Lstat(filepath.Join(path, checkpointTemporaryName))
					if err != nil {
						return err
					}
					temporaryBytes, err = os.ReadFile(filepath.Join(path, checkpointTemporaryName))
					if err != nil {
						return err
					}
					close(afterGuard)
					return <-written
				}})
				if !hit || !errors.Is(err, ErrStorage) {
					t.Fatal("destination race must fail without replacing it", err)
				}
				afterInfo, err := os.Lstat(destination)
				if err != nil || !os.SameFile(destinationInfo, afterInfo) {
					t.Fatal("foreign inode was replaced", err)
				}
				after, err := os.ReadFile(destination)
				if err != nil || !bytes.Equal(after, foreign) {
					t.Fatal("foreign bytes changed", err)
				}
				if kind == "symlink" {
					link, err := os.Readlink(destination)
					if err != nil || link != target {
						t.Fatal("foreign symlink changed", err)
					}
				}
				afterTemporary, err := os.Lstat(filepath.Join(path, checkpointTemporaryName))
				if err != nil || !os.SameFile(temporaryInfo, afterTemporary) {
					t.Fatal("staging inode was removed on conflict", err)
				}
				afterBytes, err := os.ReadFile(filepath.Join(path, checkpointTemporaryName))
				if err != nil || !bytes.Equal(temporaryBytes, afterBytes) {
					t.Fatal("staging bytes changed on conflict", err)
				}
				if !reflect.DeepEqual(before, journalFiles(t, dir)) {
					t.Fatal("conflict changed protected source journal")
				}
				if slot == 1 {
					if _, err := os.Lstat(filepath.Join(path, checkpointManifestName)); !os.IsNotExist(err) {
						t.Fatal("first conflict selected a manifest")
					}
				} else {
					selectedAfter, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
					if err != nil || !bytes.Equal(selectedBefore, selectedAfter) {
						t.Fatal("last manifest changed", err)
					}
					firstAfter, err := os.ReadFile(filepath.Join(path, "checkpoint-1.json"))
					if err != nil || !bytes.Equal(firstBefore, firstAfter) {
						t.Fatal("last image changed", err)
					}
				}
			})
		}
	}
}

func TestCheckpointUnsupportedNoReplaceRefusesWithoutFallback(t *testing.T) {
	for _, errno := range []error{unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP} {
		t.Run(errno.Error(), func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			area, path := checkpointFixtureArea(t)
			if err := s.prepareCheckpoint(area, checkpointOptions{}); err != nil {
				t.Fatal(err)
			}
			selectedBefore, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
			if err != nil {
				t.Fatal(err)
			}
			imageBefore, err := os.ReadFile(filepath.Join(path, "checkpoint-1.json"))
			if err != nil {
				t.Fatal(err)
			}
			journalBefore := journalFiles(t, dir)
			source := filepath.Join(path, checkpointTemporaryName)
			payload := []byte("staging retained when atomic no-replace is unsupported")
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			sourceInfo, err := os.Stat(source)
			if err != nil {
				t.Fatal(err)
			}
			areaInfo, err := area.Stat(".")
			if err != nil {
				t.Fatal(err)
			}
			areaStat, ok := areaInfo.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("missing native directory identity")
			}
			called := 0
			err = checkpointRenameNoReplace(area, "checkpoint-2.json", func(oldFD int, oldName string, newFD int, newName string, flags uint) error {
				called++
				if oldFD != newFD || oldName != checkpointTemporaryName || newName != "checkpoint-2.json" || flags != unix.RENAME_NOREPLACE {
					t.Fatal("unsafe syscall arguments")
				}
				var actual unix.Stat_t
				if err := unix.Fstat(oldFD, &actual); err != nil || actual.Ino != areaStat.Ino || uint64(actual.Dev) != uint64(areaStat.Dev) {
					t.Fatal("syscall descriptor does not identify workspace", err)
				}
				return errno
			})
			if !errors.Is(err, ErrStorage) || called != 1 {
				t.Fatal("unsupported operation was retried or accepted", err, called)
			}
			if _, err := os.Lstat(filepath.Join(path, "checkpoint-2.json")); !os.IsNotExist(err) {
				t.Fatal("unsupported operation fell back to publication", err)
			}
			afterInfo, err := os.Stat(source)
			if err != nil || !os.SameFile(sourceInfo, afterInfo) {
				t.Fatal("source inode lost on unsupported syscall", err)
			}
			afterBytes, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(payload, afterBytes) {
				t.Fatal("source bytes changed on unsupported syscall", err)
			}
			selectedAfter, err := os.ReadFile(filepath.Join(path, checkpointManifestName))
			if err != nil || !bytes.Equal(selectedBefore, selectedAfter) {
				t.Fatal("unsupported syscall changed selected manifest", err)
			}
			imageAfter, err := os.ReadFile(filepath.Join(path, "checkpoint-1.json"))
			if err != nil || !bytes.Equal(imageBefore, imageAfter) {
				t.Fatal("unsupported syscall changed last image", err)
			}
			if !reflect.DeepEqual(journalBefore, journalFiles(t, dir)) {
				t.Fatal("unsupported syscall changed protected history")
			}
		})
	}
}

func TestCheckpointNoReplaceAcceptsOnlyGeneratedImageNames(t *testing.T) {
	area, path := checkpointFixtureArea(t)
	for _, name := range []string{"", "../checkpoint-1.json", "/checkpoint-1.json", "checkpoint-3.json", checkpointManifestName, checkpointPreviousName} {
		t.Run(name, func(t *testing.T) {
			called := false
			err := checkpointRenameNoReplace(area, name, func(int, string, int, string, uint) error { called = true; return nil })
			if !errors.Is(err, ErrStorage) || called {
				t.Fatal("caller path reached syscall", err)
			}
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 0 {
				t.Fatal("invalid name mutated workspace", err)
			}
		})
	}
	if err := checkpointRenameNoReplace(nil, "checkpoint-1.json", unix.Renameat2); !errors.Is(err, ErrStorage) {
		t.Fatal("nil workspace accepted", err)
	}
	if err := checkpointRenameNoReplace(area, "checkpoint-1.json", nil); !errors.Is(err, ErrStorage) {
		t.Fatal("nil syscall accepted", err)
	}
}
