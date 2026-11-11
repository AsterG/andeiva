//go:build linux

package configpoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func readFixture(tb testing.TB, kind string) (string, int, int64) {
	tb.Helper()
	dir := filepath.Join(tb.TempDir(), "journal")
	store, err := openStore(dir, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	defer store.lock.Close()
	revision, err := Canonical(Config{SchemaVersion: 1, DefaultAction: "deny"})
	if err != nil {
		tb.Fatal(err)
	}
	state := durableState{Snapshot: Snapshot{Generation: 1, Running: revision, Startup: revision, LastGood: revision, Revoked: []string{}}, Receipts: map[string]receipt{}}
	if kind == "bytes" {
		for i := 0; i < 1020; i++ {
			state.Receipts[fmt.Sprintf("alice:fixture-%04d", i)] = receipt{strings.Repeat("a", 64), 1}
		}
	}
	for store.capacity(2) && (kind != "small" || len(store.records) < 8) && (kind != "records" || len(store.records) < 2046) {
		audit := Audit{At: time.Unix(int64(len(store.records)+1), 0).UTC(), Actor: "system", Surface: API, Operation: "read-fixture", Result: "ok", RunningHash: revision.Hash}
		if kind == "audit" {
			// Legacy readers impose no per-field Audit limit. This deliberately
			// valid fixture shows that metadata is not a fixed heap guarantee.
			audit.Operation = strings.Repeat("a", 120*1024)
		}
		if err := store.append(state, audit, true, nil); err != nil {
			tb.Fatal(err)
		}
	}
	return dir, len(store.records), store.bytes
}

type storeReadProfile struct {
	Workload          string `json:"workload"`
	RecordsBeforeOpen int    `json:"records_before_open"`
	JournalBytes      int64  `json:"journal_bytes"`
	ResumeWrites      int    `json:"resume_writes"`
	OpenNanoseconds   int64  `json:"open_nanoseconds"`
	RetainedHeapBytes int64  `json:"retained_heap_bytes"`
	AllocatedBytes    uint64 `json:"allocated_bytes"`
	Mallocs           uint64 `json:"mallocs"`
	PeakRSSBytes      int64  `json:"peak_rss_bytes"`
	FixtureSHA256     string `json:"fixture_sha256"`
}

func TestStoreReadProfileChild(t *testing.T) {
	dir := os.Getenv("ANDEIVA_STORE_PROFILE_DIR")
	if dir == "" {
		t.Skip("resource measurement subprocess")
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	s, err := Open(dir, []Engine{NewSimEngine("read-fixture")}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	runtime.GC()
	runtime.ReadMemStats(&after)
	var usage syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	profile := storeReadProfile{RecordsBeforeOpen: len(s.store.records) - 2, JournalBytes: s.store.bytes, ResumeWrites: 2, OpenNanoseconds: elapsed.Nanoseconds(), RetainedHeapBytes: int64(after.HeapAlloc) - int64(before.HeapAlloc), AllocatedBytes: after.TotalAlloc - before.TotalAlloc, Mallocs: after.Mallocs - before.Mallocs, PeakRSSBytes: usage.Maxrss * 1024}
	runtime.KeepAlive(s)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("STORE_READ_PROFILE %s\n", data)
}

func TestStoreReadResourceProfile(t *testing.T) {
	if os.Getenv("ANDEIVA_STORE_PROFILE") != "1" {
		t.Skip("run explicitly to measure subprocess cold reopen resources")
	}
	for _, kind := range []string{"small", "records", "bytes", "audit"} {
		t.Run(kind, func(t *testing.T) {
			dir, records, journalBytes := readFixture(t, kind)
			digest := sha256.New()
			for sequence := 1; sequence <= records; sequence++ {
				data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%08d.json", sequence)))
				if err != nil {
					t.Fatal(err)
				}
				_, _ = digest.Write(data)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStoreReadProfileChild$", "-test.v")
			command.Env = append(os.Environ(), "ANDEIVA_STORE_PROFILE_DIR="+dir)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("resource subprocess: %v\n%s", err, output)
			}
			for _, line := range strings.Split(string(output), "\n") {
				if !strings.HasPrefix(line, "STORE_READ_PROFILE ") {
					continue
				}
				var profile storeReadProfile
				if err = json.Unmarshal([]byte(strings.TrimPrefix(line, "STORE_READ_PROFILE ")), &profile); err != nil || profile.RecordsBeforeOpen != records || profile.ResumeWrites != 2 {
					t.Fatal("invalid resource subprocess observations", err)
				}
				profile.Workload, profile.JournalBytes = kind, journalBytes
				profile.FixtureSHA256 = hex.EncodeToString(digest.Sum(nil))
				encoded, err := json.Marshal(profile)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("STORE_READ_PROFILE %s", encoded)
				return
			}
			t.Fatal("resource subprocess observation missing")
		})
	}
}

// Reopen measurements include validation and retain the OS filesystem cache.
// They are not physical cold-I/O timings, an appliance boot or packet benchmarks.
func BenchmarkStoreReadOpen(b *testing.B) {
	for _, kind := range []string{"small", "records", "bytes"} {
		b.Run(kind, func(b *testing.B) {
			dir, records, journalBytes := readFixture(b, kind)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				store, err := openStore(dir, 2048)
				if err != nil {
					b.Fatal(err)
				}
				if err = store.lock.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(records), "records")
			b.ReportMetric(float64(journalBytes), "journal-B")
		})
	}
}

func BenchmarkStoreReadHistory(b *testing.B) {
	for _, kind := range []string{"small", "records", "bytes"} {
		b.Run(kind, func(b *testing.B) {
			dir, _, _ := readFixture(b, kind)
			s, err := Open(dir, []Engine{NewSimEngine("read-fixture")}, Options{})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := s.History(admin); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkStoreReadRevisions(b *testing.B) {
	for _, kind := range []string{"small", "records", "bytes"} {
		b.Run(kind, func(b *testing.B) {
			dir, _, _ := readFixture(b, kind)
			s, err := Open(dir, []Engine{NewSimEngine("read-fixture")}, Options{})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := s.Revisions(admin, 0, 100); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
