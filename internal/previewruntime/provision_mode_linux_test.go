//go:build linux

package previewruntime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSocketDirectoryRestrictiveUmask(t *testing.T) {
	switch os.Getenv("ANDEIVA_PREVIEW_TEST_UMASK") {
	case "077":
		syscall.Umask(0077)
	case "027":
		syscall.Umask(0027)
	default:
		for _, mask := range []string{"077", "027"} {
			t.Run(mask, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSocketDirectoryRestrictiveUmask$")
				cmd.Env = append(os.Environ(), "ANDEIVA_PREVIEW_TEST_UMASK="+mask)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("umask %s: %v\n%s", mask, err, output)
				}
			})
		}
		return
	}
	// Only the isolated child changes process-wide umask.
	parent := privateDir(t)
	path := filepath.Join(parent, "socket.d")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if createSocketDirectory(path, uid, gid) != nil {
		t.Fatal("fresh directory rejected")
	}
	if ownedDirectory(path, uid, gid, 0755) != nil {
		t.Fatal("exact mode or ownership missing")
	}
	if createSocketDirectory(path, uid, gid) != nil {
		t.Fatal("valid existing directory rejected")
	}
	if os.Chmod(path, 0700) != nil {
		t.Fatal("chmod")
	}
	if createSocketDirectory(path, uid, gid) == nil {
		t.Fatal("existing invalid mode accepted")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("existing directory was repaired")
	}
	link := filepath.Join(parent, "linked.d")
	if os.Symlink(path, link) != nil {
		t.Fatal("symlink")
	}
	if createSocketDirectory(link, uid, gid) == nil {
		t.Fatal("existing link accepted")
	}
}
