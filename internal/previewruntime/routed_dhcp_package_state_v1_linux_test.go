//go:build linux

package previewruntime

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRoutedDHCPPackageStateV1(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to test the dedicated service directory")
	}
	const uid, gid = 62010, 62011
	for _, test := range []string{"initial", "retry after mkdir", "root-owned lease state", "symlink"} {
		t.Run(test, func(t *testing.T) {
			area := t.TempDir()
			if err := os.Chmod(area, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(area)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			leases := filepath.Join(area, routedDHCPPackageDirectoryV1, routedDHCPPackageLeasesV1)
			switch test {
			case "retry after mkdir", "root-owned lease state":
				if err := os.MkdirAll(leases, 0700); err != nil {
					t.Fatal(err)
				}
				if test == "root-owned lease state" {
					if err := os.WriteFile(filepath.Join(leases, "lease-fixture"), []byte("retained"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "symlink":
				target := t.TempDir()
				if err := root.Symlink(target, routedDHCPPackageDirectoryV1); err != nil {
					t.Fatal(err)
				}
			}
			if err := prepareRoutedDHCPStateUnderV1(root, uid, gid); test == "symlink" || test == "root-owned lease state" {
				if err == nil {
					t.Fatal("unsafe storage accepted")
				}
				return
			} else if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(leases, "lease-fixture"), []byte("retained"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := prepareRoutedDHCPStateUnderV1(root, uid, gid); err != nil {
				t.Fatal("idempotent provisioning rejected an existing service directory", err)
			}
			info, err := os.Stat(leases)
			if err != nil {
				t.Fatal(err)
			}
			owner := info.Sys().(*syscall.Stat_t)
			if info.Mode().Perm() != 0700 || owner.Uid != uid || owner.Gid != gid {
				t.Fatal("incorrect lease directory ownership or mode")
			}
			data, err := os.ReadFile(filepath.Join(leases, "lease-fixture"))
			if err != nil || string(data) != "retained" {
				t.Fatal("existing lease state was changed", err)
			}
		})
	}
}
