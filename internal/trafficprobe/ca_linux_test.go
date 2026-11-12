//go:build linux

package trafficprobe

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCAOpenSubstitutedFIFOAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	// Exercise the actual opener after an adversarial substitution, not Lstat's
	// earlier rejection. A blocking O_RDONLY open would hang this test.
	file, err := openCAFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if closeErr := file.Close(); err != nil || closeErr != nil {
		t.Fatal("FIFO descriptor failure")
	}
	if info.Mode().IsRegular() {
		t.Fatal("FIFO accepted as regular")
	}
	if _, err := readCA(path); err != errInvalid {
		t.Fatal("FIFO accepted as CA")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.pem")
	if err := os.WriteFile(target, []byte("certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if file, err := openCAFile(path); err == nil || file != nil {
		t.Fatal("substituted symlink followed")
	}
}
