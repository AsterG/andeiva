package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestProvisionModesIgnoreRestrictiveUmask(t *testing.T) {
	switch os.Getenv("ANDEIVA_TEST_PROVISION_UMASK") {
	case "077":
		syscall.Umask(0077)
	case "027":
		syscall.Umask(0027)
	default:
		for _, mask := range []string{"077", "027"} {
			t.Run(mask, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestProvisionModesIgnoreRestrictiveUmask$")
				child.Env = append(os.Environ(), "ANDEIVA_TEST_PROVISION_UMASK="+mask)
				if output, err := child.CombinedOutput(); err != nil {
					t.Fatalf("umask %s: %v\n%s", mask, err, output)
				}
			})
		}
		return
	}
	// Only this isolated child changes umask; no process-wide state in the parent
	// test binary can race with unrelated tests or file creation.
	dir := t.TempDir()
	for _, item := range []struct {
		name string
		mode os.FileMode
	}{{"accounts.json", 0440}, {"ca.crt", 0644}, {"credentials.json", 0600}, {"server.key", 0400}} {
		t.Run(item.name, func(t *testing.T) {
			path := filepath.Join(dir, item.name)
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, item.mode)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("provisioned test data\n")
			writeErr := writeOwnedContents(file, payload, item.mode, os.Geteuid(), os.Getegid())
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				t.Fatal(writeErr, closeErr)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != item.mode || int64(owner.Uid) != int64(os.Geteuid()) || int64(owner.Gid) != int64(os.Getegid()) {
				t.Fatalf("incorrect provisioned ownership/mode: got %v want %v", info.Mode(), item.mode)
			}
			contents, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(contents, payload) {
				t.Fatal("provisioned content mismatch", err)
			}
		})
	}
}
