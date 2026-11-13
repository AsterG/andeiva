//go:build linux

package previewruntime

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func integrityFenceFixtureV3(t *testing.T) (*os.Root, uint32, uint32) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	area, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = area.Close() })
	if os.Geteuid() <= 0 || os.Getegid() <= 0 {
		t.Fatal("test requires unprivileged Linux UID/GID; no skip")
	}
	return area, uint32(os.Geteuid()), uint32(os.Getegid())
}
func preparedIntegrityFenceV3(t *testing.T) (*os.Root, *routedIntegrityFenceV3, uint32, uint32) {
	t.Helper()
	area, uid, gid := integrityFenceFixtureV3(t)
	if err := prepareRoutedIntegrityFenceV3(area, uid, gid); err != nil {
		t.Fatal(err)
	}
	g, err := openRoutedIntegrityFenceV3(area, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Close() })
	return area, g, uid, gid
}
func TestRoutedIntegrityFenceV3Lifecycle(t *testing.T) {
	area, g, uid, gid := preparedIntegrityFenceV3(t)
	if err := g.Check(); err != nil {
		t.Fatal(err)
	}
	before, err := area.ReadFile(routedIntegrityFenceNameV3)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 4096 || before[routedIntegrityFenceStateV3] != 0 {
		t.Fatal("incorrect fixed encoding")
	}
	if _, err := openRoutedIntegrityFenceV3(area, uid, gid); err == nil {
		t.Fatal("second owner opened latch")
	}
	if err := prepareRoutedIntegrityFenceV3(area, uid, gid); err == nil {
		t.Fatal("prepare reset existing latch")
	}
	if err := g.MarkBlocked(); err != nil {
		t.Fatal(err)
	}
	after, err := area.ReadFile(routedIntegrityFenceNameV3)
	if err != nil {
		t.Fatal(err)
	}
	for i := range before {
		if i == routedIntegrityFenceStateV3 {
			if after[i] != 1 {
				t.Fatal("marker missing")
			}
		} else if before[i] != after[i] {
			t.Fatal("MarkBlocked changed other bytes")
		}
	}
	if g.Check() == nil {
		t.Fatal("blocked became clean")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := openRoutedIntegrityFenceV3(area, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.Check() == nil {
		t.Fatal("reopen cleared fence")
	}
	if err := g.Close(); err != nil {
		t.Fatal("double close", err)
	}
	if g.Check() == nil {
		t.Fatal("closed became clean")
	}
	if _, err := area.Stat("."); err != nil {
		t.Fatal("Close closed borrowed root", err)
	}
}
func TestRoutedIntegrityFenceV3PrepareRejectsUnexpectedRoot(t *testing.T) {
	for _, kind := range []string{"nil", "mode", "owner", "group", "nonempty", "directory-acl"} {
		t.Run(kind, func(t *testing.T) {
			area, uid, gid := integrityFenceFixtureV3(t)
			switch kind {
			case "nil":
				area = nil
			case "mode":
				if err := area.Chmod(".", 0750); err != nil {
					t.Fatal(err)
				}
			case "owner":
				uid++
			case "group":
				gid++
			case "nonempty":
				if err := area.WriteFile("foreign", []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-acl":
				f, err := area.Open(".")
				if err != nil {
					t.Fatal(err)
				}
				setFenceACLV3(t, f)
				_ = f.Close()
			}
			if err := prepareRoutedIntegrityFenceV3(area, uid, gid); err == nil {
				t.Fatal("unexpected root accepted")
			}
			if area != nil {
				if _, err := area.Stat(routedIntegrityFenceNameV3); !os.IsNotExist(err) {
					t.Fatal("prepare mutated rejected root", err)
				}
			}
		})
	}
}
func setFenceACLV3(t *testing.T, f *os.File) {
	t.Helper()
	// Version2 POSIX ACL: user_obj rw, named user 62001 r, group_obj none,
	// mask none, other none. The zero mask preserves exact 0700/0600 so
	// the ACL check, rather than a mode mismatch, must reject the object.
	data := []byte{2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 4, 0, 49, 242, 0, 0, 4, 0, 0, 0, 255, 255, 255, 255, 16, 0, 0, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		data[6] = 7
	}
	if err := unix.Fsetxattr(int(f.Fd()), "system.posix_acl_access", data, 0); err != nil {
		t.Fatal("ACL qualification unavailable", err)
	}
	after, err := f.Stat()
	if err != nil || after.Mode() != info.Mode() {
		t.Fatal("ACL fixture changed exact mode", err)
	}
}
func TestRoutedIntegrityFenceV3RejectsTampering(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "fifo", "hardlink", "replacement", "short", "long", "magic", "state", "padding", "mode", "file-acl", "directory-mode", "foreign-uid", "foreign-gid"} {
		t.Run(kind, func(t *testing.T) {
			area, g, uid, gid := preparedIntegrityFenceV3(t)
			switch kind {
			case "missing", "symlink", "fifo", "replacement":
				if err := area.Rename(routedIntegrityFenceNameV3, "old"); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "symlink":
					if err := area.Symlink("old", routedIntegrityFenceNameV3); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := unix.Mkfifo(area.Name()+"/"+routedIntegrityFenceNameV3, 0600); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					data, err := area.ReadFile("old")
					if err != nil {
						t.Fatal(err)
					}
					if err := area.WriteFile(routedIntegrityFenceNameV3, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "hardlink":
				if err := area.Link(routedIntegrityFenceNameV3, "alias"); err != nil {
					t.Fatal(err)
				}
			case "short":
				if err := g.file.Truncate(4095); err != nil {
					t.Fatal(err)
				}
			case "long":
				if err := g.file.Truncate(4097); err != nil {
					t.Fatal(err)
				}
			case "magic":
				if _, err := g.file.WriteAt([]byte("X"), 0); err != nil {
					t.Fatal(err)
				}
			case "state":
				if _, err := g.file.WriteAt([]byte{2}, int64(routedIntegrityFenceStateV3)); err != nil {
					t.Fatal(err)
				}
			case "padding":
				if _, err := g.file.WriteAt([]byte{1}, 4095); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := g.file.Chmod(0640); err != nil {
					t.Fatal(err)
				}
			case "file-acl":
				setFenceACLV3(t, g.file)
			case "directory-mode":
				if err := area.Chmod(".", 0750); err != nil {
					t.Fatal(err)
				}
			case "foreign-uid":
				g.uid = uid + 1
			case "foreign-gid":
				g.gid = gid + 1
			}
			if g.Check() == nil {
				t.Fatal("tampered latch accepted")
			}
			if !g.blocked {
				t.Fatal("error did not latch in memory")
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			if kind != "foreign-uid" && kind != "foreign-gid" && kind != "replacement" {
				if reopened, err := openRoutedIntegrityFenceV3(area, uid, gid); err == nil {
					_ = reopened.Close()
					t.Fatal("invalid latch reopened")
				}
			}
		})
	}
}
func TestRoutedIntegrityFenceV3WriteFailuresStayBlocked(t *testing.T) {
	for _, kind := range []string{"write", "short-write", "written-error", "sync"} {
		t.Run(kind, func(t *testing.T) {
			area, g, uid, gid := preparedIntegrityFenceV3(t)
			switch kind {
			case "write":
				g.writeAt = func([]byte, int64) (int, error) { return 0, unix.ENOSPC }
			case "short-write":
				g.writeAt = func([]byte, int64) (int, error) { return 0, nil }
			case "written-error":
				original := g.writeAt
				g.writeAt = func(data []byte, offset int64) (int, error) {
					n, err := original(data, offset)
					if err != nil {
						return n, err
					}
					return n, io.ErrUnexpectedEOF
				}
			case "sync":
				g.syncFile = func() error { return unix.EIO }
			}
			if err := g.MarkBlocked(); err == nil {
				t.Fatal("failed persistence acknowledged")
			}
			if g.Check() == nil {
				t.Fatal("failed persistence cleared RAM fence")
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			next, err := openRoutedIntegrityFenceV3(area, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			defer next.Close()
			// Failed writes can leave a clean byte. It means only that a fresh helper
			// must perform cold full integrity qualification, never that IO was durable.
			if (kind == "sync" || kind == "written-error") && next.Check() == nil {
				t.Fatal("actual written state lost")
			}
		})
	}
}
func TestRoutedIntegrityFenceV3Concurrent(t *testing.T) {
	_, g, _, _ := preparedIntegrityFenceV3(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = g.Check(); _ = g.MarkBlocked(); _ = g.Check() }()
	}
	wg.Wait()
	if g.Check() == nil {
		t.Fatal("concurrency cleared fence")
	}
	if !errors.Is(g.Check(), errRoutedIntegrityFenceV3) {
		t.Fatal("unstable error")
	}
}
func TestRoutedIntegrityFenceV3NoInProcessReset(t *testing.T) {
	area, g, _, _ := preparedIntegrityFenceV3(t)
	if err := area.Chmod(".", 0750); err != nil {
		t.Fatal(err)
	}
	if g.Check() == nil {
		t.Fatal("invalid root accepted")
	}
	if err := area.Chmod(".", 0700); err != nil {
		t.Fatal(err)
	}
	if g.Check() == nil {
		t.Fatal("profile repair cleared RAM latch")
	}
	if err := g.MarkBlocked(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.file.WriteAt([]byte{0}, int64(routedIntegrityFenceStateV3)); err != nil {
		t.Fatal(err)
	}
	if g.Check() == nil {
		t.Fatal("external clean byte cleared RAM latch")
	}
}
func TestRoutedIntegrityFenceV3RejectsAppendDescriptor(t *testing.T) {
	_, g, _, _ := preparedIntegrityFenceV3(t)
	flags, err := unix.FcntlInt(g.file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(g.file.Fd(), unix.F_SETFL, flags|unix.O_APPEND); err != nil {
		t.Fatal(err)
	}
	if g.Check() == nil {
		t.Fatal("append descriptor accepted")
	}
	if _, err := unix.FcntlInt(g.file.Fd(), unix.F_SETFL, flags); err != nil {
		t.Fatal(err)
	}
	if g.Check() == nil {
		t.Fatal("descriptor repair cleared fence")
	}
}
