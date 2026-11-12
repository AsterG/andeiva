//go:build linux

package recoveryreserve

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestReadOnlyV2BoundedFile(t *testing.T) {
	_, _, area, access, path := sharedPoolV2(t)
	before := snapshotV2(t, area)
	data, err := access.ReadFile(context.Background(), area, "pool.json", 4096)
	if err != nil || len(data) == 0 {
		t.Fatal(err)
	}
	if _, err = access.ReadFile(context.Background(), area, "pool.json", len(data)-1); err != ErrUnavailable {
		t.Fatal("size limit not enforced")
	}
	for _, name := range []string{"../pool.json", "/pool.json", ".", "..", "pool.json/", "POOL.json", "a\\b", "a\x00b"} {
		if _, err = access.ReadFile(context.Background(), area, name, 4096); err != ErrInvalid {
			t.Fatalf("invalid name %q: %v", name, err)
		}
	}
	for _, limit := range []int{-1, 0, (1 << 20) + 1} {
		if _, err = access.ReadFile(context.Background(), area, "pool.json", limit); err != ErrInvalid {
			t.Fatal("invalid byte limit accepted")
		}
	}
	if _, err = access.ReadFile(nil, area, "pool.json", 4096); err != ErrInvalid {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = access.ReadFile(ctx, area, "pool.json", 4096); err != ErrUnavailable {
		t.Fatal("cancel ignored")
	}
	if !reflect.DeepEqual(before, snapshotV2(t, area)) {
		t.Fatal("bounded read wrote pool")
	}
	if err = syscall.Mkfifo(filepath.Join(path, "pipe"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err = access.ReadFile(context.Background(), area, "pipe", 4096); err != ErrUnavailable {
		t.Fatal("FIFO accepted")
	}
	if err = os.Symlink("pool.json", filepath.Join(path, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err = access.ReadFile(context.Background(), area, "link", 4096); err != ErrUnavailable {
		t.Fatal("symlink accepted")
	}
	if err = os.Link(filepath.Join(path, "pool.json"), filepath.Join(path, "hard")); err != nil {
		t.Fatal(err)
	}
	if _, err = access.ReadFile(context.Background(), area, "pool.json", 4096); err != ErrUnavailable {
		t.Fatal("hardlink accepted")
	}
}

// Umask changes are confined to separate test processes, never the test runner.
func TestReadOnlyV2Umask(t *testing.T) {
	args := flag.Args()
	if len(args) == 1 && (args[0] == "reader-umask-077" || args[0] == "reader-umask-027") {
		mask := 0077
		if args[0] == "reader-umask-027" {
			mask = 0027
		}
		syscall.Umask(mask)
		_, r, _, _, _ := sharedPoolV2(t)
		if _, err := r.Snapshot(context.Background()); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mask := range []string{"reader-umask-077", "reader-umask-027"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestReadOnlyV2Umask$", "--", mask)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated %s: %v %s", mask, err, out)
		}
	}
}
