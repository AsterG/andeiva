package main

import (
	"bytes"
	"path/filepath"
	"runtime"
	"testing"
)

func TestArgumentBoundary(t *testing.T) {
	for _, args := range [][]string{nil, {"-state-dir", "relative"}, {"-state-dir", "/tmp/example", "-iterations", "0"}, {"-state-dir", "/tmp/example", "-iterations", "101"}} {
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr); code != 2 || out.Len() != 0 {
			t.Fatalf("invalid argument accepted: code=%d", code)
		}
	}
}

func TestExperimentUsesRealStoreAndSimulatedEngines(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux experimental store")
	}
	r, err := experiment(filepath.Join(t.TempDir(), "state"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if r.Result != "PASS" || r.RunningHash != r.StartupHash || len(r.RunningHash) != 64 || r.AuditRecords < 3 || r.StoreBytes <= 0 || r.CommitP95NS <= 0 {
		t.Fatalf("incomplete experiment result: %+v", r)
	}
}
