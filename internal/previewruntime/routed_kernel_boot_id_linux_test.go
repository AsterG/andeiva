//go:build linux

package previewruntime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRoutedKernelBootIDReadsProcfs(t *testing.T) {
	id, err := readRoutedKernelBootID()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(routedKernelBootIDPath)
	if err != nil || string(raw) != id+"\n" {
		t.Fatal("boot identity differs from the running kernel", err)
	}
}

func TestRoutedKernelBootIDRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "boot_id")
	if err := os.WriteFile(path, []byte("12345678-1234-1234-1234-123456789abc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if id, err := readRoutedProcBootID(file); id != "" || !errors.Is(err, ErrIdentity) {
		t.Fatal("regular file supplied a boot identity", err)
	}
}
