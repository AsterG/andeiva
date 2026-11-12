//go:build linux

package storagevol

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// This is opt-in and invoked only by storage-pressure.sh in private namespaces.
func TestNativeVolumePressure(t *testing.T) {
	if os.Getenv("ANDEIVA_STORAGE_NATIVE_VOLUMES") != "1" {
		t.Skip("authorized native harness only")
	}
	base := os.Getenv("ANDEIVA_STORAGE_VOLUME_ROOT")
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/andeiva-storage-pressure/test\.[A-Za-z0-9]{8}$`).MatchString(base) {
		t.Fatal("unsafe native scope")
	}
	for _, pair := range [][2]string{{"mnt", "ANDEIVA_STORAGE_NATIVE_PARENT_MNT"}, {"net", "ANDEIVA_STORAGE_NATIVE_PARENT_NET"}} {
		parent := os.Getenv(pair[1])
		actual, err := os.Readlink("/proc/self/ns/" + pair[0])
		if parent == "" || err != nil || actual == parent {
			t.Fatal("private namespaces required")
		}
	}
	roots := map[string]*os.Root{}
	devices := map[uint64]bool{}
	for _, domain := range []string{"config", "audit", "observations", "recovery"} {
		path := filepath.Join(base, domain)
		info, err := os.Lstat(path)
		if err != nil || !ownedDirectory(info, 0, 0) || info.Mode().Perm()&0077 != 0 {
			t.Fatal("unsafe volume root", domain, err)
		}
		native := info.Sys().(*syscall.Stat_t)
		if devices[native.Dev] {
			t.Fatal("volumes share a filesystem")
		}
		devices[native.Dev] = true
		root, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		roots[domain] = root
		defer root.Close()
		file, err := root.Open(".")
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Statfs_t
		err = unix.Fstatfs(int(file.Fd()), &stat)
		file.Close()
		requiredFlags := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
		if err != nil || stat.Type != unix.EXT4_SUPER_MAGIC || int64(stat.Flags)&requiredFlags != requiredFlags {
			t.Fatal("ext4 required")
		}
	}
	caseName := os.Getenv("ANDEIVA_STORAGE_VOLUME_CASE")
	if caseName != "bytes" && caseName != "inodes" && caseName != "readonly" && caseName != "open-deleted" {
		t.Fatal("unknown native case")
	}
	for _, domain := range []string{"config", "recovery"} {
		nativeHealthy(t, roots[domain])
	}
	before := map[string]unix.Statfs_t{}
	for _, domain := range []string{"config", "audit", "recovery"} {
		before[domain] = nativeStat(t, roots[domain])
	}
	observations := roots["observations"]
	switch caseName {
	case "bytes":
		file, err := observations.OpenFile("pressure-bytes", os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			file.Close()
			if err := observations.Remove("pressure-bytes"); err != nil {
				t.Error(err)
			}
			_ = syncRoot(observations)
		}()
		block := make([]byte, 1024*1024)
		var total int
		exhausted := false
		for total < 65*1024*1024 {
			n, err := file.Write(block)
			total += n
			if err != nil {
				if !errors.Is(err, unix.ENOSPC) {
					t.Fatal(err)
				}
				exhausted = true
				break
			}
		}
		if !exhausted {
			t.Fatal("finite observations byte budget not enforced")
		}
		t.Logf("observations ENOSPC after %d written bytes", total)
	case "inodes":
		created := []string{}
		defer func() {
			for _, name := range created {
				if err := observations.Remove(name); err != nil {
					t.Error(err)
				}
			}
			_ = syncRoot(observations)
		}()
		exhausted := false
		for i := 0; i < 1025; i++ {
			name := fmt.Sprintf("pressure-inode-%04d", i)
			file, err := observations.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
			if err != nil {
				if !errors.Is(err, unix.ENOSPC) {
					t.Fatal(err)
				}
				exhausted = true
				break
			}
			created = append(created, name)
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if !exhausted {
			t.Fatal("finite observations inode budget not enforced")
		}
		t.Logf("observations ENOSPC after %d new files", len(created))
	case "readonly":
		file, err := observations.OpenFile("pressure-readonly", os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW, 0600)
		if file != nil {
			file.Close()
			t.Fatal("readonly volume accepted a write")
		}
		if !errors.Is(err, unix.EROFS) {
			t.Fatalf("expected EROFS: %v", err)
		}
	case "open-deleted":
		initial := nativeStat(t, observations)
		file, err := observations.OpenFile("pressure-deleted", os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if file != nil {
				_ = file.Close()
			}
		}()
		block := make([]byte, 1024*1024)
		for i := 0; i < 8; i++ {
			if _, err = file.Write(block); err != nil {
				t.Fatal(err)
			}
		}
		if err = file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err = observations.Remove("pressure-deleted"); err != nil {
			t.Fatal(err)
		}
		_ = syncRoot(observations)
		held := nativeStat(t, observations)
		if held.Bfree >= initial.Bfree {
			t.Fatal("open-deleted allocation was not retained")
		}
		closeErr := file.Close()
		file = nil
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		_ = syncRoot(observations)
		released := nativeStat(t, observations)
		if released.Bfree <= held.Bfree {
			t.Fatal("closing deleted file did not release blocks")
		}
		t.Logf("open-deleted held blocks=%d reclaimed=%d", initial.Bfree-held.Bfree, released.Bfree-held.Bfree)
	}
	for _, domain := range []string{"config", "audit", "recovery"} {
		after := nativeStat(t, roots[domain])
		if after.Bfree != before[domain].Bfree || after.Ffree != before[domain].Ffree {
			t.Fatalf("%s budget changed under observations pressure", domain)
		}
		t.Logf("%s independent free blocks=%d inodes=%d", domain, after.Bfree, after.Ffree)
	}
	for _, domain := range []string{"config", "recovery"} {
		nativeHealthy(t, roots[domain])
	}
	fmt.Printf("ANDEIVA_NATIVE_VOLUME_CASE_PASS=%s\n", caseName)
}

func nativeStat(t *testing.T, root *os.Root) unix.Statfs_t {
	t.Helper()
	file, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var result unix.Statfs_t
	if err = unix.Syncfs(int(file.Fd())); err != nil {
		t.Fatal(err)
	}
	if err = unix.Fstatfs(int(file.Fd()), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func nativeHealthy(t *testing.T, root *os.Root) {
	t.Helper()
	file, err := root.OpenFile("health-probe", os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("ANDEIVA storage isolation probe\n")); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = root.Remove("health-probe"); err != nil {
		t.Fatal(err)
	}
	if err = syncRoot(root); err != nil {
		t.Fatal(err)
	}
}
