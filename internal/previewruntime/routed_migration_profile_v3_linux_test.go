//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"golang.org/x/sys/unix"
)

// These fixtures exercise metadata, locks and byte conservation only. Their
// selector/banks are not presented as a valid selected configuration or G1.
func profileFixtureV3(t *testing.T) ([4]*os.Root, uint32, uint32) {
	t.Helper()
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 || gid == 0 {
		t.Skip("metadata fixture requires unprivileged owner; native converter has an explicit opt-in")
	}
	return profileFixtureOwnedV3(t, uid, gid), uid, gid
}
func profileFixtureOwnedV3(t *testing.T, uid, gid uint32) [4]*os.Root {
	t.Helper()
	var roots [4]*os.Root
	for i := range roots {
		path := filepath.Join(t.TempDir(), "area")
		if e := os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		root, e := os.OpenRoot(path)
		if e != nil {
			t.Fatal(e)
		}
		roots[i] = root
		t.Cleanup(func() { _ = root.Close() })
		directory, e := root.Open(".")
		if e != nil {
			t.Fatal(e)
		}
		if e = directory.Chown(int(uid), int(gid)); e != nil {
			t.Fatal(e)
		}
		_ = directory.Close()
		write := func(name string, data []byte) {
			f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.Write(data); e != nil {
				t.Fatal(e)
			}
			if e = f.Chown(int(uid), int(gid)); e != nil {
				t.Fatal(e)
			}
			if e = f.Close(); e != nil {
				t.Fatal(e)
			}
		}
		if i == 0 {
			write("checkpoint.lock", nil)
			write("selected.json", []byte("{}"))
			data := []byte("fixture metadata only")
			sum := sha256.Sum256(data)
			write("object-"+hex.EncodeToString(sum[:])+".json", data)
		} else {
			write("pool.json", []byte("{}"))
			for n := 0; n < 18; n++ {
				write(fmt.Sprintf("reserve-%02d.bin", n), []byte("bank fixture"))
			}
		}
	}
	return roots
}
func TestRoutedMigrationProfileV3ScanLocksAndConservation(t *testing.T) {
	roots, uid, gid := profileFixtureV3(t)
	scan, e := scanRoutedProfileV3(context.Background(), roots, uid, gid, routedWriteBudgetV3{Bytes: 1 << 30, Inodes: 32768})
	if e != nil {
		t.Fatal(e)
	}
	defer scan.Close()
	if e = scan.revalidate(context.Background(), gid, false); e != nil {
		t.Fatal(e)
	}
	for i, area := range scan.areas {
		another, e := roots[i].OpenFile(area.lockName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if e != nil {
			t.Fatal(e)
		}
		e = unix.Flock(int(another.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		_ = another.Close()
		if e == nil {
			t.Fatal("writer lock released during conversion scope")
		}
	}
	if os.Geteuid() != 0 {
		access, e := scan.convert(context.Background(), gid+1, nil)
		if e == nil || access != ([4]routedAccessRecordV3{}) {
			t.Fatal("capless caller changed permissions")
		}
	}
	if e = scan.revalidate(context.Background(), gid, false); e != nil {
		t.Fatal("refusal changed files", e)
	}
	if e = roots[0].WriteFile("selected.json", []byte("[]"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = scan.revalidate(context.Background(), gid, false); e == nil {
		t.Fatal("changed file bytes accepted")
	}
}
func TestRoutedMigrationProfileV3RejectsUnsafePhysicalLayout(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "mode", "object-hash", "foreign-owner", "root-alias", "pending", "fifo"} {
		t.Run(mode, func(t *testing.T) {
			roots, uid, gid := profileFixtureV3(t)
			switch mode {
			case "symlink":
				if e := roots[1].Remove("reserve-00.bin"); e != nil {
					t.Fatal(e)
				}
				if e := roots[1].Symlink("pool.json", "reserve-00.bin"); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(filepath.Join(roots[1].Name(), "pool.json"), filepath.Join(t.TempDir(), "extra")); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := roots[2].Chmod("reserve-00.bin", 0640); e != nil {
					t.Fatal(e)
				}
			case "object-hash":
				if e := roots[0].WriteFile("object-"+strings.Repeat("a", 64)+".json", []byte("mismatch"), 0600); e != nil {
					t.Fatal(e)
				}
			case "foreign-owner":
				uid++
			case "root-alias":
				roots[2] = roots[1]
			case "fifo":
				if e := roots[1].Remove("pool.json"); e != nil {
					t.Fatal(e)
				}
				if e := unix.Mkfifo(filepath.Join(roots[1].Name(), "pool.json"), 0600); e != nil {
					t.Fatal(e)
				}
			case "pending":
				if e := roots[0].WriteFile("selection.pending", []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if scan, e := scanRoutedProfileV3(context.Background(), roots, uid, gid, routedWriteBudgetV3{Bytes: 1 << 30, Inodes: 32768}); e == nil {
				_ = scan.Close()
				t.Fatal("unsafe layout accepted")
			}
		})
	}
}
func TestRoutedMigrationProfileV3RegistryExclusive(t *testing.T) {
	ids := nativeIdentitiesV3
	registry := marshal(routedReaderRegistryV3{Version: 1, Name: routedReaderGroupNameV3, GID: 62004})
	groups := []byte("root:x:0:\nandeiva-config-reader:x:62004:\n")
	if gid, e := readerGroupFromV3(registry, groups, ids); e != nil || gid != 62004 {
		t.Fatal(gid, e)
	}
	for _, bad := range [][]byte{[]byte("andeiva-config-reader:x:62004:other\n"), []byte("andeiva-config-reader:x:62004:\nalias:x:62004:\n"), []byte("andeiva-config-reader:x:62003:\n"), []byte("root:x:0:\n")} {
		if _, e := readerGroupFromV3(registry, bad, ids); e == nil {
			t.Fatal("nonexclusive/unregistered reader group accepted")
		}
	}
}

func TestRoutedMigrationProfileV3NamedDirectorySwapIsNotAdopted(t *testing.T) {
	roots, uid, gid := profileFixtureV3(t)
	scan, e := scanRoutedProfileV3(context.Background(), roots, uid, gid, routedWriteBudgetV3{Bytes: 1 << 30, Inodes: 32768})
	if e != nil {
		t.Fatal(e)
	}
	defer scan.Close()
	path := roots[0].Name()
	if e = os.Rename(path, path+"-retained"); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e = scan.revalidate(context.Background(), gid, false); e == nil {
		t.Fatal("replacement directory adopted")
	}
	entries, e := os.ReadDir(path)
	if e != nil || len(entries) != 0 {
		t.Fatal("replacement modified", entries, e)
	}
}

func TestRoutedMigrationProfileV3ActualPoolTupleAndBounds(t *testing.T) {
	roots, uid, gid := profileFixtureV3(t)
	var profiles [3]routedProfileRecordV3
	roles := [3]recoveryreserve.RoleV2{recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2}
	capacities := [3]int{4096, 16384, 8192}
	for i := 1; i < 4; i++ {
		entries, e := os.ReadDir(roots[i].Name())
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if e = roots[i].Remove(entry.Name()); e != nil {
				t.Fatal(e)
			}
		}
		pool, e := recoveryreserve.PrepareV2(roots[i], 18, capacities[i-1], roles[i-1])
		if e != nil {
			t.Fatal(e)
		}
		profile, e := pool.Profile()
		if e != nil {
			t.Fatal(e)
		}
		profiles[i-1] = routedProfileRecordV3{ID: profile.ID, Role: profile.Role, Slots: profile.Slots, Capacity: profile.Capacity}
		if e = pool.Close(); e != nil {
			t.Fatal(e)
		}
	}
	budget := routedWriteBudgetV3{Bytes: 1 << 30, Inodes: 32768}
	scan, e := scanRoutedProfileV3(context.Background(), roots, uid, gid, budget)
	if e != nil {
		t.Fatal(e)
	}
	if e = scan.validatePoolProfilesV3(profiles); e != nil {
		t.Fatal(e)
	}
	bad := profiles
	bad[1].Capacity *= 2
	if scan.validatePoolProfilesV3(bad) == nil {
		t.Fatal("wrong prepared profile accepted")
	}
	used := scan.bytes
	if e = scan.Close(); e != nil {
		t.Fatal(e)
	}
	for _, small := range []routedWriteBudgetV3{{Bytes: used - 1, Inodes: 32768}, {Bytes: 1 << 30, Inodes: 1}} {
		if got, e := scanRoutedProfileV3(context.Background(), roots, uid, gid, small); e == nil {
			_ = got.Close()
			t.Fatal("budget exceeded")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, e := scanRoutedProfileV3(ctx, roots, uid, gid, budget); e == nil {
		_ = got.Close()
		t.Fatal("cancel ignored")
	}
	// Failed scans release the actual manifest locks.
	scan, e = scanRoutedProfileV3(context.Background(), roots, uid, gid, budget)
	if e != nil {
		t.Fatal(e)
	}
	if e = scan.Close(); e != nil {
		t.Fatal(e)
	}
}
