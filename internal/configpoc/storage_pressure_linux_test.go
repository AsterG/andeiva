package configpoc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"syscall"
	"testing"
	"time"
)

// This opt-in test consumes only a small, dedicated tmpfs supplied by the
// laboratory harness. It never mounts filesystems or changes network state.
func TestRealStoragePressure(t *testing.T) {
	if os.Getenv("ANDEIVA_STORAGE_PRESSURE") != "1" {
		t.Skip("requires the isolated finite-filesystem laboratory harness")
	}
	root := os.Getenv("ANDEIVA_STORAGE_PRESSURE_ROOT")
	mode := os.Getenv("ANDEIVA_STORAGE_PRESSURE_MODE")
	if !regexp.MustCompile(`^/tmp/andeiva-storage-pressure\.[A-Za-z0-9]{8}/volume$`).MatchString(root) || os.Geteuid() != 1000 {
		t.Fatal("dedicated laboratory path and unprivileged test identity required")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		t.Fatal("laboratory path must not traverse symlinks")
	}
	var stat syscall.Statfs_t
	if syscall.Statfs(root, &stat) != nil || stat.Type != 0x01021994 || stat.Frsize <= 0 || stat.Blocks == 0 || stat.Blocks > (16*1024*1024)/uint64(stat.Frsize) || stat.Files == 0 || stat.Files > 256 {
		t.Fatal("dedicated tmpfs must be bounded to 16 MiB and 256 inodes")
	}
	dir := filepath.Join(root, "store")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		t.Fatal("precreated owned store directory required")
	}
	if mode == "readonly" {
		store := &fileStore{dir: dir}
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		space, probeErr := probeStorageSpace(f)
		closeErr := f.Close()
		if probeErr != nil || closeErr != nil || !space.ReadOnly || store.spaceCapacity(4) {
			t.Fatal("actual read-only filesystem was admitted")
		}
		path := filepath.Join(dir, "readonly-write")
		f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if f != nil {
			_ = f.Close()
			_ = os.Remove(path)
		}
		if !errors.Is(err, syscall.EROFS) {
			t.Fatalf("expected actual EROFS, got %v", err)
		}
		t.Log("actual EROFS and descriptor-scoped read-only admission verified; no service bootstrap or engine effects exercised in this mode")
		return
	}
	if mode != "bytes" && mode != "inodes" {
		t.Fatal("unknown laboratory mode")
	}
	if stat.Flags&1 != 0 {
		t.Fatal("writable bounded tmpfs required")
	}
	engines := []*SimEngine{NewSimEngine("first"), NewSimEngine("second")}
	s, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := firewallSample()
	stageRequest := Request{Operation: OpStage, Key: "finite-stage", ExpectedGeneration: status(t, s).Generation, Config: &c}
	staged, err := s.Execute(context.Background(), admin, API, stageRequest)
	if err != nil {
		t.Fatal(err)
	}
	before := clone(s.state)
	records := len(s.store.records)
	counted := &countedCapacityEngine{Engine: engines[0]}
	s.engines[0] = counted
	guard := &testGuard{}
	var fillers []string
	defer func() {
		for _, path := range fillers {
			_ = os.Remove(path)
		}
	}()
	if mode == "bytes" {
		path := filepath.Join(root, "filler-bytes")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		fillers = append(fillers, path)
		block := make([]byte, 1024*1024)
		var writeErr error
		for range 17 {
			if _, writeErr = f.Write(block); writeErr != nil {
				break
			}
		}
		closeErr := f.Close()
		if !errors.Is(writeErr, syscall.ENOSPC) || closeErr != nil {
			t.Fatalf("bounded byte fill did not observe ENOSPC: write=%v close=%v", writeErr, closeErr)
		}
	} else {
		var createErr error
		for i := range 257 {
			path := filepath.Join(root, fmt.Sprintf("filler-inode-%03d", i))
			f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				createErr = err
				break
			}
			fillers = append(fillers, path)
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if !errors.Is(createErr, syscall.ENOSPC) {
			t.Fatalf("bounded inode fill did not observe ENOSPC: %v", createErr)
		}
	}
	request := Request{Operation: OpCommit, Key: "finite-commit", ExpectedGeneration: staged.Generation, ConfirmFor: 30 * time.Second}
	if _, err = s.ExecuteManaged(context.Background(), admin, API, request, guard); !errors.Is(err, ErrStorage) || counted.applies.Load() != 0 || guard.arms != 0 || guard.confirms != 0 || len(s.store.records) != records || !reflect.DeepEqual(before, s.state) {
		t.Fatal("physical exhaustion reached effects or published state")
	}
	if s.halted || s.store.readFailed || status(t, s).RecoveryRequired {
		t.Fatal("physical pressure incorrectly latched corruption")
	}
	if _, err = s.History(admin); err != nil {
		t.Fatal(err)
	}
	if replay, err := s.Execute(context.Background(), admin, CLI, stageRequest); err != nil || replay.ReplayedGeneration != staged.Generation {
		t.Fatalf("exact replay unavailable under pressure: %v", err)
	}
	for _, path := range fillers {
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	fillers = nil
	out, err := s.ExecuteManaged(context.Background(), admin, API, request, guard)
	if err != nil || out.Pending == nil || guard.arms != 1 || counted.applies.Load() != 1 {
		t.Fatalf("release did not restore admission: %v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after := status(t, reopened)
	if after.Pending != nil || after.RecoveryRequired || after.Running.Hash != before.Snapshot.Running.Hash {
		t.Fatal("reopen did not roll back unconfirmed revision")
	}
	t.Logf("actual %s ENOSPC, rejection before simulated engines, read/replay continuity, release and unconfirmed reopen recovery verified", mode)
}
