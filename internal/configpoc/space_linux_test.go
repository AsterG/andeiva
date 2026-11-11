package configpoc

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func ampleStorageSpace() storageSpace {
	return storageSpace{AvailableBytes: 64 * maxRecordBytes, AvailableInodes: 256, BlockSize: 4096}
}

func TestStorageSpaceStatConversion(t *testing.T) {
	base := syscall.Statfs_t{Bsize: 4096, Frsize: 1024, Blocks: 128, Bavail: 64, Files: 100, Ffree: 50}
	space, err := storageSpaceFromStat(base)
	if err != nil || space.AvailableBytes != 64*1024 || space.BlockSize != 4096 || space.AvailableInodes != 50 || space.ReadOnly {
		t.Fatal("fragment counts were converted with I/O block size")
	}
	base.Bsize, base.Frsize = 512, 4096
	space, err = storageSpaceFromStat(base)
	if err != nil || space.AvailableBytes != 64*4096 || space.BlockSize != 4096 {
		t.Fatal("allocation granularity understated")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*syscall.Statfs_t)
	}{
		{"unknown-fragment", func(s *syscall.Statfs_t) { s.Frsize = 0 }},
		{"negative-fragment", func(s *syscall.Statfs_t) { s.Frsize = -1 }},
		{"unknown-io-block", func(s *syscall.Statfs_t) { s.Bsize = 0 }},
		{"unknown-blocks", func(s *syscall.Statfs_t) { s.Blocks = 0 }},
		{"unknown-inodes", func(s *syscall.Statfs_t) { s.Files = 0 }},
		{"excessive-free-blocks", func(s *syscall.Statfs_t) { s.Bavail = s.Blocks + 1 }},
		{"excessive-free-inodes", func(s *syscall.Statfs_t) { s.Ffree = s.Files + 1 }},
		{"byte-overflow", func(s *syscall.Statfs_t) { s.Blocks = math.MaxUint64; s.Bavail = math.MaxUint64 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stat := base
			tc.mutate(&stat)
			if _, err := storageSpaceFromStat(stat); !errors.Is(err, ErrStorage) {
				t.Fatal("accepted unknown or overflowing filesystem metrics")
			}
		})
	}
	base.Flags = 1
	space, err = storageSpaceFromStat(base)
	if err != nil || !space.ReadOnly {
		t.Fatal("read-only flag lost")
	}
}

func TestStorageSpaceBudget(t *testing.T) {
	const reserve = 4
	const records = reserve + 1
	exact := storageSpace{AvailableBytes: records*maxRecordBytes + 4096*(records+4), AvailableInodes: records + 3, BlockSize: 4096}
	for _, tc := range []struct {
		name    string
		mutate  func(*storageSpace)
		reserve int
		want    bool
	}{
		{"exact", func(*storageSpace) {}, reserve, true},
		{"short-byte", func(s *storageSpace) { s.AvailableBytes-- }, reserve, false},
		{"short-inode", func(s *storageSpace) { s.AvailableInodes-- }, reserve, false},
		{"readonly", func(s *storageSpace) { s.ReadOnly = true }, reserve, false},
		{"unknown-block-size", func(s *storageSpace) { s.BlockSize = 0 }, reserve, false},
		{"overflow", func(s *storageSpace) { s.BlockSize = math.MaxUint64; s.AvailableBytes = math.MaxUint64 }, reserve, false},
		{"negative-reserve", func(*storageSpace) {}, -1, false},
		{"excessive-reserve", func(*storageSpace) {}, 10000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			space := exact
			tc.mutate(&space)
			if got := space.admits(tc.reserve); got != tc.want {
				t.Fatalf("admission=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestStorageSpaceProbeUsesOwnedDescriptor(t *testing.T) {
	s, _, dir := fixture(t, Options{})
	if !s.store.spaceCapacity(4) {
		t.Fatal("fixture filesystem has insufficient admission capacity")
	}
	if _, err := probeStorageSpace(nil); !errors.Is(err, ErrStorage) {
		t.Fatal("accepted missing descriptor")
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := probeStorageSpace(f); !errors.Is(err, ErrStorage) {
		t.Fatal("accepted closed descriptor")
	}
	called := false
	s.store.spaceProbe = func(f *os.File) (storageSpace, error) {
		called = true
		got, err := f.Stat()
		want, statErr := os.Stat(dir)
		if err != nil || statErr != nil || !os.SameFile(got, want) {
			t.Fatal("probe not pinned to store directory")
		}
		return ampleStorageSpace(), nil
	}
	if !s.store.spaceCapacity(4) || !called {
		t.Fatal("probe not used")
	}
	called = false
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if s.store.spaceCapacity(4) || called {
		t.Fatal("probed directory with invalid permissions")
	}
}

func TestStorageSpaceAdmissionBeforeEffects(t *testing.T) {
	for _, boundary := range []string{"bytes", "inodes", "readonly", "error"} {
		t.Run(boundary, func(t *testing.T) {
			s, engines, _ := fixture(t, Options{})
			c := firewallSample()
			staged := invoke(t, s, OpStage, &c, 0)
			before := clone(s.state)
			records := len(s.store.records)
			engine := &countedCapacityEngine{Engine: engines[0]}
			s.engines[0] = engine
			guard := &admissionGuard{check: func(Request, Snapshot, *Revision) error { return nil }}
			s.store.spaceProbe = func(*os.File) (storageSpace, error) {
				space := ampleStorageSpace()
				switch boundary {
				case "bytes":
					space.AvailableBytes = 0
				case "inodes":
					space.AvailableInodes = 0
				case "readonly":
					space.ReadOnly = true
				case "error":
					return storageSpace{}, ErrStorage
				}
				return space, nil
			}
			request := Request{Operation: OpCommit, Key: "space-commit", ExpectedGeneration: staged.Generation, ConfirmFor: 30 * time.Second}
			_, err := s.ExecuteManaged(context.Background(), admin, API, request, guard)
			if !errors.Is(err, ErrStorage) || guard.checks != 0 || guard.arms != 0 || guard.confirms != 0 || engine.applies.Load() != 0 || len(s.store.records) != records || !reflect.DeepEqual(s.state, before) {
				t.Fatal("pressure admission reached effects, audit or state")
			}
			if s.halted || s.store.readFailed || status(t, s).RecoveryRequired {
				t.Fatal("transient pressure latched corruption/recovery")
			}
			if _, err := s.History(admin); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Execute(context.Background(), Principal{ID: "viewer", Role: RoleViewer}, Web, Request{Operation: OpSave}); !errors.Is(err, ErrStorage) || len(s.store.records) != records {
				t.Fatal("unadmitted rejection audit consumed physical headroom")
			}
			s.store.spaceProbe = func(*os.File) (storageSpace, error) { return ampleStorageSpace(), nil }
			out, err := s.ExecuteManaged(context.Background(), admin, API, request, guard)
			if err != nil || out.Pending == nil || guard.arms != 1 || engine.applies.Load() != 1 {
				t.Fatalf("capacity release did not restore admission: %v", err)
			}
		})
	}
}

func TestStorageSpaceReplayBypassesProbeButNotAuthorization(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	c := sample("receipt")
	request := Request{Operation: OpStage, Key: "space-replay", ExpectedGeneration: status(t, s).Generation, Config: &c}
	staged, err := s.Execute(context.Background(), admin, CLI, request)
	if err != nil {
		t.Fatal(err)
	}
	records := len(s.store.records)
	probes := 0
	s.store.spaceProbe = func(*os.File) (storageSpace, error) { probes++; return storageSpace{}, ErrStorage }
	out, err := s.Execute(context.Background(), admin, API, request)
	if err != nil || out.ReplayedGeneration != staged.Generation || probes != 0 || len(s.store.records) != records {
		t.Fatal("exact replay consumed capacity")
	}
	if _, err := s.Execute(context.Background(), Principal{ID: admin.ID, Role: RoleViewer}, API, request); !errors.Is(err, ErrStorage) || len(s.store.records) != records {
		t.Fatal("unauthorized replay reached result/effects")
	}
	if probes != 1 {
		t.Fatal("unauthorized request bypassed rejection admission")
	}
}

func TestStorageSpacePressurePreservesPendingTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, _ := fixture(t, Options{})
		initial := status(t, s)
		c := sample("temporary")
		invoke(t, s, OpStage, &c, 0)
		pending := invoke(t, s, OpCommit, nil, time.Second)
		probes := 0
		s.store.spaceProbe = func(*os.File) (storageSpace, error) { probes++; return storageSpace{}, ErrStorage }
		if _, err := s.Execute(context.Background(), admin, API, Request{Operation: OpConfirm, Key: "pressure-confirm", ExpectedGeneration: pending.Generation, Target: pending.Running.Hash}); !errors.Is(err, ErrStorage) {
			t.Fatal("confirmation should fail admission")
		}
		if s.halted || s.store.readFailed || s.timer == nil {
			t.Fatal("admission disabled pending timeout")
		}
		beforeProbes := probes
		time.Sleep(time.Second)
		synctest.Wait()
		s.mu.Lock()
		timerRecovered := s.state.Snapshot.Pending == nil && s.state.Snapshot.Running.Hash == initial.Running.Hash && !s.state.Snapshot.RecoveryRequired
		if len(s.store.records) == 0 || s.store.records[len(s.store.records)-1].audit.Operation != "timeout" {
			timerRecovered = false
		}
		s.mu.Unlock()
		if !timerRecovered {
			t.Fatal("autonomous timer did not finish before any status read")
		}
		after := status(t, s)
		if after.Pending != nil || after.RecoveryRequired || after.Running.Hash != initial.Running.Hash || probes != beforeProbes {
			t.Fatal("critical timeout was blocked by ordinary pressure threshold")
		}
		history, err := s.History(admin)
		if err != nil || history[len(history)-1].Operation != "timeout" {
			t.Fatal("timeout outcome not durable")
		}
	})
}

func TestStorageSpaceConcurrentAdmissionAndRelease(t *testing.T) {
	s, engines, dir := fixture(t, Options{})
	c := firewallSample()
	staged := invoke(t, s, OpStage, &c, 0)
	before := clone(s.state)
	counted := &countedCapacityEngine{Engine: engines[0]}
	s.engines[0] = counted
	s.store.spaceProbe = func(*os.File) (storageSpace, error) { return storageSpace{}, ErrStorage }
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			_, err := s.Execute(context.Background(), admin, API, Request{Operation: OpCommit, Key: fmt.Sprintf("pressure-%d", i), ExpectedGeneration: staged.Generation})
			if !errors.Is(err, ErrStorage) {
				t.Errorf("unexpected concurrent result: %v", err)
			}
		})
	}
	wg.Wait()
	if counted.applies.Load() != 0 || !reflect.DeepEqual(before, s.state) {
		t.Fatal("concurrent pressure published a partial state")
	}
	s.store.spaceProbe = nil
	committed := invoke(t, s, OpCommit, nil, 0)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, []Engine{engines[0], engines[1]}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if status(t, reopened).Running.Hash != committed.Running.Hash {
		t.Fatal("released admission did not survive reopen")
	}
}

func TestStorageSpaceRequiredRecoveryRetainsCriticalPath(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	before := status(t, s)
	s.state.Snapshot.RecoveryRequired = true
	probes := 0
	s.store.spaceProbe = func(*os.File) (storageSpace, error) { probes++; return storageSpace{}, ErrStorage }
	out, err := s.Execute(context.Background(), admin, API, Request{Operation: OpRecover, Key: "critical-space-recovery", ExpectedGeneration: before.Generation})
	if err != nil || out.RecoveryRequired || out.Running.Hash != before.Running.Hash || probes != 0 {
		t.Fatalf("required recovery lost its existing critical persistence path: %v", err)
	}
	if _, err := s.Execute(context.Background(), admin, API, Request{Operation: OpRecover, Key: "ordinary-space-recovery", ExpectedGeneration: out.Generation}); !errors.Is(err, ErrStorage) || probes != 1 {
		t.Fatal("healthy recovery bypassed ordinary physical admission")
	}
}

func TestStorageSpaceObservationDoesNotRecheckAfterEffects(t *testing.T) {
	s, _, _ := fixture(t, Options{})
	c := firewallSample()
	invoke(t, s, OpStage, &c, 0)
	probes := 0
	s.store.spaceProbe = func(*os.File) (storageSpace, error) {
		probes++
		if probes == 1 {
			return ampleStorageSpace(), nil
		}
		return storageSpace{}, ErrStorage
	}
	committed := invoke(t, s, OpCommit, nil, 0)
	if probes != 1 || committed.RecoveryRequired || committed.Candidate != nil {
		t.Fatal("an observational threshold interrupted an admitted transition")
	}
}

func BenchmarkStorageSpaceAdmission(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "state")
	s, err := Open(dir, []Engine{NewSimEngine("measure")}, Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !s.store.spaceCapacity(4) {
			b.Fatal("insufficient benchmark capacity")
		}
	}
}
