//go:build linux

package recoveryreserve

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The external laboratory harness must provide a dedicated, disposable ext4
// mount. This test never mounts, formats or accepts a block device itself.
func TestNativeReservePressure(t *testing.T) {
	if os.Getenv("ANDEIVA_RESERVE_NATIVE_QUALIFY") != "1" {
		t.Skip("requires isolated native pressure harness")
	}
	area := os.Getenv("ANDEIVA_RESERVE_NATIVE_AREA")
	if !filepath.IsAbs(area) || filepath.Clean(area) != area || os.Geteuid() == 0 {
		t.Fatal("requires explicit private mount and non-root execution")
	}
	info, err := os.Lstat(area)
	if err != nil || !privateDirectory(info) {
		t.Fatal("invalid private area")
	}
	var fs unix.Statfs_t
	if unix.Statfs(area, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Blocks*uint64(fs.Bsize) > 128<<20 || fs.Files > 8192 {
		t.Fatal("requires bounded disposable ext4 profile")
	}
	parentInfo, err := os.Stat(filepath.Dir(area))
	if err != nil {
		t.Fatal(err)
	}
	dev := info.Sys().(*syscall.Stat_t).Dev
	if parentInfo.Sys().(*syscall.Stat_t).Dev == dev {
		t.Fatal("area is not a separate mount")
	}
	for _, kind := range []string{"bytes", "inodes"} {
		t.Run(kind, func(t *testing.T) {
			poolArea := filepath.Join(area, "pool-"+kind)
			if err := os.Mkdir(poolArea, 0700); err != nil {
				t.Fatal(err)
			}
			r, err := os.OpenRoot(poolArea)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			p, err := Prepare(r, 2, 65536)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			filler := filepath.Join(area, "filler-"+kind)
			if err = os.Mkdir(filler, 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "bytes" {
				f, err := os.OpenFile(filepath.Join(filler, "bytes"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 65536)
				for total := 0; ; total += len(buf) {
					if total > 128<<20 {
						t.Fatal("byte pressure exceeded profile")
					}
					_, err = f.Write(buf)
					if err != nil {
						if !errors.Is(err, unix.ENOSPC) && !errors.Is(err, unix.EDQUOT) {
							t.Fatal(err)
						}
						break
					}
				}
				_ = f.Sync()
				if err = f.Close(); err != nil && !errors.Is(err, unix.ENOSPC) && !errors.Is(err, unix.EDQUOT) {
					t.Fatal(err)
				}
				if unix.Statfs(area, &fs) != nil || fs.Bavail > 16 {
					t.Fatalf("byte pressure not established: %d", fs.Bavail)
				}
			} else {
				for i := 0; ; i++ {
					if i > 8192 {
						t.Fatal("inode pressure exceeded profile")
					}
					f, e := os.OpenFile(filepath.Join(filler, fmt.Sprintf("%04d", i)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if e != nil {
						if !errors.Is(e, unix.ENOSPC) {
							t.Fatal(e)
						}
						break
					}
					if e = f.Close(); e != nil {
						t.Fatal(e)
					}
				}
				if unix.Statfs(area, &fs) != nil || fs.Ffree != 0 {
					t.Fatalf("inode pressure not established: %d", fs.Ffree)
				}
			}
			lease, err := p.Claim("admitted-operation")
			if err != nil {
				t.Fatalf("claim under %s pressure: %v", kind, err)
			}
			payload := bytes.Repeat([]byte("verified-recovery"), 2048)
			lease, err = p.Write(lease, payload)
			if err != nil {
				t.Fatalf("write under %s pressure: %v", kind, err)
			}
			binding, err := p.Binding(lease)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			p, err = Open(r)
			if err != nil {
				t.Fatalf("reopen under pressure: %v", err)
			}
			defer p.Close()
			got, err := p.ReadBound(binding)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("retained recovery: %v", err)
			}
			// Only entries generated inside this newly created disposable fixture are
			// removed. Production pool code never performs this test-only cleanup.
			entries, err := os.ReadDir(filler)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if err = os.Remove(filepath.Join(filler, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.Remove(filler); err != nil {
				t.Fatal(err)
			}
		})
	}
}
