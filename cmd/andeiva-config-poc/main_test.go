package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInvalidStateDirectoryHasNoSideEffects(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		t.Skip("unprivileged Linux runner")
	}
	parent := t.TempDir()
	realParent := filepath.Join(parent, "real")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(realParent, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{parent + "/./state", parent + "//state", parent + "/real/../state", parent + "/state/", link + "/state"} {
		t.Run(path, func(t *testing.T) {
			var out, stderr bytes.Buffer
			if code := run([]string{"-state-dir", path}, &out, &stderr); code != 2 || out.Len() != 0 {
				t.Fatalf("invalid path accepted: code=%d output=%s", code, out.String())
			}
			for _, unexpected := range []string{filepath.Join(parent, "state"), filepath.Join(realParent, "state")} {
				if _, err := os.Lstat(unexpected); !os.IsNotExist(err) {
					t.Fatalf("invalid path created %s: %v", unexpected, err)
				}
			}
		})
	}
}

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
