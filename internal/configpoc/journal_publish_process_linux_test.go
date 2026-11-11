//go:build linux

package configpoc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestJournalNoReplaceProcessInterruption(t *testing.T) {
	for _, point := range []string{"after_record_destination_check", "after_rename"} {
		t.Run(point, func(t *testing.T) {
			s, _, dir := fixture(t, Options{})
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			before := journalFiles(t, dir)
			count := len(s.store.records)
			latest := clone(s.store.latest)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			// Reuse the existing v1 crash helper; only the new publication
			// boundary and the real no-replace syscall path differ here.
			command := exec.CommandContext(ctx, executable, "-test.run=^TestStagingProcessInterruption$")
			command.Env = append(os.Environ(), "ANDEIVA_POC_STAGE_CHILD="+point, "ANDEIVA_POC_STAGE_STATE="+dir)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 74 {
				t.Fatalf("child missed publication boundary: %v %s", err, output)
			}
			store, err := openStore(dir, 2048)
			if err != nil {
				t.Fatal("v1 reopen failed", err)
			}
			defer func() { _ = store.lock.Close() }()
			if point == "after_rename" {
				count++
			}
			if len(store.records) != count {
				t.Fatal("reopen invented or lost a record")
			}
			if _, err := os.Lstat(filepath.Join(dir, stagingDirectory, stagingPayload)); !os.IsNotExist(err) {
				t.Fatal("owned crash staging not recovered", err)
			}
			if !reflect.DeepEqual(latest, store.latest) {
				t.Fatal("crash changed last committed state")
			}
			for name, data := range before {
				after, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || !bytes.Equal(data, after) {
					t.Fatal("protected history changed after child exit", name, err)
				}
			}
		})
	}
}

func BenchmarkJournalAppendNoReplace(b *testing.B) {
	b.StopTimer()
	var s *Service
	defer func() {
		if s != nil {
			_ = s.Close()
		}
	}()
	var state durableState
	var audit Audit
	for i := 0; i < b.N; i++ {
		// Fresh batches keep the existing lifetime limits intact; this measures
		// one append, not sustained operation beyond those limits.
		if s == nil || !s.store.capacity(2) {
			if s != nil {
				if err := s.Close(); err != nil {
					b.Fatal(err)
				}
			}
			var err error
			s, err = Open(filepath.Join(b.TempDir(), "state"), []Engine{NewSimEngine("first")}, Options{})
			if err != nil {
				b.Fatal(err)
			}
			state = clone(s.store.latest)
			audit = s.store.records[len(s.store.records)-1].audit
		}
		b.StartTimer()
		if err := s.store.append(state, audit, false, nil); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
	}
	b.ReportMetric(float64(s.store.bytes)/float64(len(s.store.records)), "journal-bytes/record")
}
