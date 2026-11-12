//go:build linux

package configpoc

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func ampleV2Space(*os.File) (storageSpace, error) {
	return storageSpace{AvailableBytes: 1 << 40, AvailableInodes: 1 << 30, BlockSize: 4096}, nil
}

// Compare incremental accounting with an independent, descriptor-based census.
// This runs only in tests; normal admission must not enumerate the catalogue.
func checkV2Physical(t *testing.T, s *v2Store) {
	t.Helper()
	dir, err := s.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	di, err := dir.Stat()
	if err != nil {
		t.Fatal(err)
	}
	allocated, err := v2Allocated(di)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := dir.ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}
	var files, logical uint64
	for _, entry := range entries {
		f, err := openRecordFile(s.root, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		info, statErr := f.Stat()
		closeErr := f.Close()
		if statErr != nil || closeErr != nil {
			t.Fatal(statErr, closeErr)
		}
		blocks, err := v2Allocated(info)
		if err != nil {
			t.Fatal(err)
		}
		files += blocks
		logical += uint64(info.Size())
	}
	if s.physical.files != files || s.physical.directory != allocated || s.physical.inodes != uint64(len(entries))+1 {
		t.Fatalf("physical counter mismatch: files=%d/%d directory=%d/%d inodes=%d/%d", s.physical.files, files, s.physical.directory, allocated, s.physical.inodes, len(entries)+1)
	}
	if s.used.Bytes != logical || s.used.Inodes != uint64(len(entries)) {
		t.Fatalf("logical counter mismatch: %+v bytes=%d files=%d", s.used, logical, len(entries))
	}
}

func TestV2PhysicalIncrementalSelectorsAndReopen(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	checkV2Physical(t, s)
	old, err := openRecordFile(area, "selected.json")
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close() // A replaced selector may remain allocated until this closes.
	peaks := 0
	s.hook = func(at string) error {
		if at == "before_select" {
			peaks++
			checkV2Physical(t, s)
			if _, err := area.Lstat("selected.json"); err != nil {
				return err
			}
			if _, err := area.Lstat("selection.pending"); err != nil {
				return err
			}
		}
		return nil
	}
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v2Cycle(t, s, subject, ns.ID, now)
	if peaks < 4 {
		t.Fatal("publication peak not exercised", peaks)
	}
	checkV2Physical(t, s)
	before := s.physical
	state, selection := clone(s.state), s.selector
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	checkV2Physical(t, reopened)
	if reopened.physical.files != before.files || reopened.physical.directory != before.directory || reopened.physical.inodes != before.inodes || !reflect.DeepEqual(state, reopened.state) || selection != reopened.selector {
		t.Fatal("cold measurement changed canonical state or allocation")
	}
	t.Logf("logical=%d allocated_files=%d directory=%d inodes=%d selector_peaks=%d", s.used.Bytes, before.files, before.directory, before.inodes, peaks)
}

func TestV2PhysicalExistingObjectIsNotChargedTwice(t *testing.T) {
	s, _, _, _ := v2Fixture(t, 64)
	value := struct {
		Value string `json:"value"`
	}{Value: "same immutable object"}
	first, err := s.object(value)
	if err != nil {
		t.Fatal(err)
	}
	used, physical := s.used, s.physical
	second, err := s.object(value)
	if err != nil || second != first || used != s.used || !reflect.DeepEqual(physical, s.physical) {
		t.Fatal("deduplication changed allocation", err)
	}
	checkV2Physical(t, s)
}

func TestV2PhysicalPartialObjectIsRetainedAndCountedOnReopen(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	value := struct {
		Value string `json:"value"`
	}{Value: string(bytes.Repeat([]byte("x"), 8192))}
	data, hash, err := v2Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	name := "object-" + hash + ".json"
	selected := s.selector
	s.hook = func(at string) error {
		if at != "object_written" {
			return nil
		}
		// Model the file left by a partial write; the error must fence this
		// handle without unlinking or pretending its allocation was released.
		f, err := area.OpenFile(name, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		truncated := f.Truncate(int64(len(data) / 2))
		synced, closed := f.Sync(), f.Close()
		if truncated != nil || synced != nil || closed != nil {
			t.Fatal(truncated, synced, closed)
		}
		return errors.New("injected partial write")
	}
	if _, err = s.object(value); err == nil || !s.blocked {
		t.Fatal("partial write was not fenced", err)
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	checkV2Physical(t, reopened)
	info, err := area.Lstat(name)
	if err != nil || info.Size() != int64(len(data)/2) || reopened.selector != selected {
		t.Fatal("partial object lost or canonical state changed", err)
	}
}

func TestV2PhysicalColdScanCountsSparseAllocationSeparately(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	name := "object-" + checkpointDigest([]byte("unreferenced sparse fixture")) + ".json"
	f, err := area.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(v2ObjectLimit); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	allocated, err := v2Allocated(info)
	if err != nil {
		t.Fatal(err)
	}
	before := s.physical.files
	logical := s.used.Bytes
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	checkV2Physical(t, reopened)
	if reopened.physical.files != before+allocated || reopened.used.Bytes != logical+v2ObjectLimit {
		t.Fatal("logical size substituted for allocation")
	}
}

func TestV2PhysicalAdmissionPressureHasNoDurableEffects(t *testing.T) {
	for _, kind := range []string{"filesystem-bytes", "filesystem-inodes", "owned-files", "owned-directory", "owned-inodes", "readonly", "probe-error"} {
		t.Run(kind, func(t *testing.T) {
			c, _, engines, p, now := coordinatorV2Fixture(t, false)
			s := c.store
			ns, err := s.namespace(p.Subject, "firewall", *now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			before, selected, used := clone(s.state), s.selector, s.used
			original := s.physical
			space, _ := ampleV2Space(nil)
			want := errV2Limited
			switch kind {
			case "filesystem-bytes":
				space.AvailableBytes = 0
			case "filesystem-inodes":
				space.AvailableInodes = 0
			case "owned-files":
				s.physical.files = s.budget.Bytes
			case "owned-directory":
				// Leave the actual observed directory allocation as the deciding byte.
				future, _ := v2PhysicalEnvelope(2*v2OperationReserveBytes, 2*v2OperationReserveInodes, space.BlockSize)
				s.physical.files = s.budget.Bytes - future
				if s.physical.directory == 0 {
					t.Skip("filesystem reports no directory allocation")
				}
			case "owned-inodes":
				s.physical.inodes = s.budget.Inodes
			case "readonly":
				space.ReadOnly = true
				want = errV2Unavailable
			case "probe-error":
				want = errV2Unavailable
			}
			s.spaceProbe = func(f *os.File) (storageSpace, error) {
				info, e := f.Stat()
				if e != nil || !os.SameFile(info, original.directoryInfo) {
					t.Fatal("probe did not receive pinned directory")
				}
				if kind == "probe-error" {
					return storageSpace{}, errors.New("injected probe error")
				}
				return space, nil
			}
			for _, engine := range engines {
				engine.reset()
			}
			_, err = s.admit(p.Subject, ns.ID, s.state.Generation, v2Request{Kind: OpValidate}, *now)
			if !errors.Is(err, want) || s.blocked || selected != s.selector || used != s.used || !reflect.DeepEqual(before, s.state) {
				t.Fatal("pressure consumed a slot/reservation/publication or fenced canonical reads", err)
			}
			for _, engine := range engines {
				if engine.applies.Load() != 0 || engine.validations.Load() != 0 || engine.reads.Load() != 0 {
					t.Fatal("admission pressure reached engine")
				}
			}
			if _, _, err = c.status(p); err != nil {
				t.Fatal("verified current state unavailable", err)
			}
			s.physical = original
			s.spaceProbe = ampleV2Space
			if _, err = s.admit(p.Subject, ns.ID, s.state.Generation, v2Request{Kind: OpValidate}, *now); err != nil {
				t.Fatal("space recovery required reopening", err)
			}
		})
	}
}

func TestV2PhysicalOwnedAllowanceCannotBorrowAnother(t *testing.T) {
	s, _, _, _ := v2Fixture(t, 64)
	s.state.ReservedBytes = 2 * v2OperationReserveBytes
	s.state.ReservedInodes = 2 * v2OperationReserveInodes
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	other, _ := v2PhysicalEnvelope(v2OperationReserveBytes, v2OperationReserveInodes, 4096)
	next, _ := v2PhysicalEnvelope(100, 1, 4096)
	available := other + next
	s.spaceProbe = func(*os.File) (storageSpace, error) {
		return storageSpace{AvailableBytes: available, AvailableInodes: v2OperationReserveInodes + 1, BlockSize: 4096}, nil
	}
	if err := s.physicalCapacity(100, 1); err != nil {
		t.Fatal("own allowance unavailable", err)
	}
	available--
	if err := s.physicalCapacity(100, 1); !errors.Is(err, errV2Limited) {
		t.Fatal("consumed another operation's allowance", err)
	}
	s.allowance.Bytes = s.state.ReservedBytes + 1
	if err := s.physicalCapacity(100, 1); !errors.Is(err, errV2Unavailable) {
		t.Fatal("invalid allowance accepted", err)
	}
}

func TestV2PhysicalColdPressurePreservesVerifiedRetainedReads(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op := v2Cycle(t, s, subject, ns.ID, now)
	for s.used.Inodes < 256 {
		if _, err = s.object(fmt.Sprintf("unreferenced accounting fixture %d", s.used.Inodes)); err != nil {
			t.Fatal(err)
		}
	}
	limits := s.budget
	limits.Inodes = s.used.Inodes // File-only logical usage fits; the directory does not.
	selected := s.selector
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, limits)
	if err != nil {
		t.Fatal("physical pressure blocked canonical open", err)
	}
	defer reopened.close()
	checkV2Physical(t, reopened)
	if reopened.physical.inodes != limits.Inodes+1 {
		t.Fatal("directory inode omitted")
	}
	got, err := reopened.lookup(subject, op.ID)
	if err != nil || !reflect.DeepEqual(got, op) {
		t.Fatal("retained observation under pressure", err)
	}
	got, err = reopened.begin(subject, op.ID, now)
	if err != nil || !reflect.DeepEqual(got, op) || reopened.selector != selected {
		t.Fatal("terminal replay under pressure changed state", err)
	}
	if err = reopened.physicalCapacity(0, 0); !errors.Is(err, errV2Limited) || reopened.blocked {
		t.Fatal("physical overage not enforced independently", err)
	}
	hash, err := reopened.indexGet(reopened.state.Index, op.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	f, err := area.OpenFile("object-"+hash+".json", os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write([]byte("{}"))
	syncErr, closeErr := f.Sync(), f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal(writeErr, syncErr, closeErr)
	}
	if _, err = reopened.lookup(subject, op.ID); !errors.Is(err, errV2Unavailable) {
		t.Fatal("pressure bypassed retained object integrity", err)
	}
}

func TestV2PhysicalFailureAfterEffectsKeepsFence(t *testing.T) {
	for _, point := range []string{"object_written", "before_select", "after_select", "publication-pressure"} {
		t.Run(point, func(t *testing.T) {
			s, area, _, _ := v2Fixture(t, 64)
			selected, before := s.selector, s.physical.files
			s.hook = func(at string) error {
				if at == point {
					return errors.New("injected write failure")
				}
				return nil
			}
			if point == "publication-pressure" {
				s.spaceProbe = func(*os.File) (storageSpace, error) { return storageSpace{BlockSize: 4096}, nil }
			}
			st := clone(s.state)
			st.Clock = st.Clock.Add(time.Second)
			if err := s.publish(st); err == nil || !s.blocked {
				t.Fatal("publication failure was not fenced", err)
			}
			s.spaceProbe = ampleV2Space
			if err := s.physicalCapacity(1, 1); err != nil || !s.blocked {
				t.Fatal("space probe cleared uncertainty", err)
			}
			if selected != s.selector {
				t.Fatal("failed publication changed canonical in-memory selector")
			}
			if err := s.close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openV2(area, s.budget)
			if err != nil {
				t.Fatal("cold scan", err)
			}
			defer reopened.close()
			checkV2Physical(t, reopened)
			if reopened.physical.files < before {
				t.Fatal("partial objects discarded")
			}
			if point == "before_select" && !reopened.blocked {
				t.Fatal("pending selector cleared uncertainty")
			}
		})
	}
}

type v2PhysicalInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (i v2PhysicalInfo) Sys() any { return i.stat }

func TestV2PhysicalOverflowAndDeviceValidation(t *testing.T) {
	s, _, _, _ := v2Fixture(t, 64)
	info := s.physical.directoryInfo
	for _, blocks := range []int64{-1, math.MaxInt64} {
		if _, err := v2Allocated(v2PhysicalInfo{info, &syscall.Stat_t{Blocks: blocks}}); err == nil {
			t.Fatal("invalid allocation accepted", blocks)
		}
	}
	if n, err := v2Allocated(v2PhysicalInfo{info, &syscall.Stat_t{Blocks: 9}}); err != nil || n != 9*512 {
		t.Fatal("st_blocks unit changed", n, err)
	}
	if v2PhysicalSameDevice(v2PhysicalInfo{info, &syscall.Stat_t{Dev: 1}}, v2PhysicalInfo{info, &syscall.Stat_t{Dev: 2}}) {
		t.Fatal("different filesystem accepted")
	}
	for _, input := range [][3]uint64{{1, 1, 0}, {math.MaxUint64, 1, 4096}, {1, math.MaxUint64, 4096}, {1, 1, math.MaxUint64}} {
		if _, ok := v2PhysicalEnvelope(input[0], input[1], input[2]); ok {
			t.Fatal("overflow accepted", input)
		}
	}
	s.spaceProbe = ampleV2Space
	s.physical.files = math.MaxUint64
	if err := s.physicalCapacity(1, 1); !errors.Is(err, errV2Unavailable) {
		t.Fatal("counter overflow accepted", err)
	}
}

func BenchmarkV2PhysicalPreflight(b *testing.B) {
	path := b.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		b.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		b.Fatal(err)
	}
	info, err := dir.Stat()
	if err != nil {
		b.Fatal(err)
	}
	if err = dir.Close(); err != nil {
		b.Fatal(err)
	}
	s := &v2Store{root: root, budget: v2Budget{Bytes: 1 << 40, Inodes: 1 << 26}, physical: v2PhysicalUsage{inodes: 1, directoryInfo: info}}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := s.physicalCapacity(2*v2OperationReserveBytes, 2*v2OperationReserveInodes); err != nil {
			b.Fatal(err)
		}
	}
}
