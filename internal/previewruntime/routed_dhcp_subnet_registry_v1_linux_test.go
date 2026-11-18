//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func subnetRegistryFSV1(t *testing.T) (*os.File, *os.File, uint32, uint32) {
	t.Helper()
	path, e := os.MkdirTemp("", "andeiva-subnet-registry-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(path); e != nil {
			t.Error(e)
		}
	})
	if e = os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(path, "leases"), 0700); e != nil {
		t.Fatal(e)
	}
	root, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	leases, e := os.Open(filepath.Join(path, "leases"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = leases.Close(); _ = root.Close() })
	var st unix.Stat_t
	if e = unix.Fstat(int(root.Fd()), &st); e != nil {
		t.Fatal(e)
	}
	return root, leases, st.Uid, st.Gid
}

func TestDHCPSubnetRegistryV1FilesystemAndConcurrentWriters(t *testing.T) {
	root, leases, uid, gid := subnetRegistryFSV1(t)
	b := subnetBindingFixtureV1()
	const n = 12
	var wg sync.WaitGroup
	errors := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ids, e := ensureDHCPSubnetIDsV1(ctx, root, leases, []RoutedDHCPSubnetBindingV1{b}, uid, gid)
			if e != nil || !reflect.DeepEqual(ids, []uint32{1}) {
				errors <- fmt.Errorf("ids=%v error=%w", ids, e)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for e := range errors {
		t.Error(e)
	}
	r, missing, e := readDHCPSubnetRegistryV1(root, uid, gid)
	if e != nil || missing || len(r.Entries) != 1 || r.HighWater != 1 {
		t.Fatal("concurrent allocation diverged", e)
	}
	before, e := os.Stat(filepath.Join(root.Name(), routedDHCPSubnetRegistryNameV1))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(leases.Name(), "existing.csv"), []byte("existing lease"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ensureDHCPSubnetIDsV1(context.Background(), root, leases, []RoutedDHCPSubnetBindingV1{b}, uid, gid); e != nil {
		t.Fatal(e)
	}
	after, e := os.Stat(filepath.Join(root.Name(), routedDHCPSubnetRegistryNameV1))
	if e != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		t.Fatal("lookup wrote registry")
	}
}

func TestDHCPSubnetRegistryV1UnsafeFilesAndUnmappedLeases(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "permissions", "corrupt", "oversize", "leases", "directory", "foreign-lease-pin", "pending"} {
		t.Run(kind, func(t *testing.T) {
			root, leases, uid, gid := subnetRegistryFSV1(t)
			name := filepath.Join(root.Name(), routedDHCPSubnetRegistryNameV1)
			valid, err := json.Marshal(routedDHCPSubnetRegistryV1{Version: 1, HighWater: 1, Entries: []routedDHCPSubnetEntryV1{{subnetBindingFixtureV1(), 1}}})
			if err != nil {
				t.Fatal(err)
			}
			var e error
			switch kind {
			case "symlink":
				e = os.WriteFile(name+".target", valid, 0600)
				if e == nil {
					e = os.Symlink(filepath.Base(name)+".target", name)
				}
			case "hardlink":
				e = os.WriteFile(name, valid, 0600)
				if e == nil {
					e = os.Link(name, name+".alias")
				}
			case "fifo":
				e = unix.Mkfifo(name, 0600)
			case "permissions":
				e = os.WriteFile(name, valid, 0600)
				if e == nil {
					e = os.Chmod(name, 0644)
				}
			case "corrupt":
				e = os.WriteFile(name, []byte("{}"), 0600)
			case "oversize":
				e = os.WriteFile(name, make([]byte, routedDHCPSubnetRegistryBytesV1+1), 0600)
			case "leases":
				e = os.WriteFile(filepath.Join(leases.Name(), "old.csv"), []byte("old"), 0600)
			case "directory":
				e = os.Chmod(root.Name(), 0750)
			case "foreign-lease-pin":
				leases = root
			case "pending":
				e = os.WriteFile(filepath.Join(root.Name(), routedDHCPSubnetRegistryPendingV1), []byte("partial"), 0600)
			}
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if ids, e := ensureDHCPSubnetIDsV1(ctx, root, leases, []RoutedDHCPSubnetBindingV1{subnetBindingFixtureV1()}, uid, gid); e == nil || ids != nil {
				t.Fatal("unsafe state accepted", ids, e)
			}
		})
	}
}

func TestDHCPSubnetRegistryV1FullFileStillServesExisting(t *testing.T) {
	root, leases, uid, gid := subnetRegistryFSV1(t)
	r := routedDHCPSubnetRegistryV1{Version: 1, HighWater: routedDHCPSubnetRegistryEntriesV1, Entries: []routedDHCPSubnetEntryV1{}}
	for i := 1; i <= routedDHCPSubnetRegistryEntriesV1; i++ {
		b := subnetBindingFixtureV1()
		b.ScopeID = fmt.Sprintf("s-%d", i)
		r.Entries = append(r.Entries, routedDHCPSubnetEntryV1{b, uint32(i)})
	}
	if e := publishDHCPSubnetRegistryV1(context.Background(), root, r, uid, gid, (*os.File).Sync); e != nil {
		t.Fatal(e)
	}
	if ids, e := ensureDHCPSubnetIDsV1(context.Background(), root, leases, []RoutedDHCPSubnetBindingV1{r.Entries[0].Binding}, uid, gid); e != nil || ids[0] != 1 {
		t.Fatal(e)
	}
	if ids, e := ensureDHCPSubnetIDsV1(context.Background(), root, leases, []RoutedDHCPSubnetBindingV1{subnetBindingFixtureV1()}, uid, gid); !errors.Is(e, ErrRoutedDHCPSubnetRegistryFullV1) || ids != nil {
		t.Fatal("full registry allocated")
	}
	current, _, e := readDHCPSubnetRegistryV1(root, uid, gid)
	if e != nil || !reflect.DeepEqual(current, r) {
		t.Fatal("quota failure changed history", e)
	}
}

func TestDHCPSubnetRegistryV1ExhaustedIDPreservesManifest(t *testing.T) {
	root, leases, uid, gid := subnetRegistryFSV1(t)
	ctx := context.Background()
	key := subnetBindingFixtureV1()
	const lastID = math.MaxUint32 - 1
	sparse := routedDHCPSubnetRegistryV1{
		Version: 1, HighWater: lastID,
		Entries: []routedDHCPSubnetEntryV1{{key, lastID}},
	}
	if err := publishDHCPSubnetRegistryV1(ctx, root, sparse, uid, gid, (*os.File).Sync); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root.Name(), routedDHCPSubnetRegistryNameV1)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	newKey := key
	newKey.ScopeID = "new"
	ids, err := ensureDHCPSubnetIDsV1(ctx, root, leases, []RoutedDHCPSubnetBindingV1{key, newKey}, uid, gid)
	if !errors.Is(err, ErrRoutedDHCPSubnetRegistryFullV1) || ids != nil {
		t.Errorf("exhausted registry accepted a new scope: IDs=%v error=%v", ids, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("exhaustion changed the manifest", err)
	}
	ids, err = ensureDHCPSubnetIDsV1(ctx, root, leases, []RoutedDHCPSubnetBindingV1{key}, uid, gid)
	if err != nil || !reflect.DeepEqual(ids, []uint32{lastID}) {
		t.Fatalf("last usable ID inaccessible: IDs=%v error=%v", ids, err)
	}
}

type subnetPublicationCancelV1 struct {
	context.Context
	cancel     context.CancelFunc
	checks, at int
}

func (c *subnetPublicationCancelV1) Err() error {
	c.checks++
	if c.checks == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestDHCPSubnetRegistryV1InterruptedPublication(t *testing.T) {
	for _, at := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			root, leases, uid, gid := subnetRegistryFSV1(t)
			b := subnetBindingFixtureV1()
			if _, e := ensureDHCPSubnetIDsV1(context.Background(), root, leases, []RoutedDHCPSubnetBindingV1{b}, uid, gid); e != nil {
				t.Fatal(e)
			}
			old, _, e := readDHCPSubnetRegistryV1(root, uid, gid)
			if e != nil {
				t.Fatal(e)
			}
			b.ScopeID = "new"
			next, _, _, e := allocateDHCPSubnetRegistryV1(old, []RoutedDHCPSubnetBindingV1{b})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if e = publishDHCPSubnetRegistryV1(&subnetPublicationCancelV1{Context: ctx, cancel: cancel, at: at}, root, next, uid, gid, (*os.File).Sync); e == nil {
				t.Fatal("cancellation accepted")
			}
			actual, _, e := readDHCPSubnetRegistryV1(root, uid, gid)
			if e != nil {
				t.Fatal(e)
			}
			want := old
			if at == 3 {
				want = next
			}
			if !reflect.DeepEqual(actual, want) {
				t.Fatal("partial registry published")
			}
			ids, e := ensureDHCPSubnetIDsV1(context.Background(), root, leases, []RoutedDHCPSubnetBindingV1{old.Entries[0].Binding}, uid, gid)
			if at == 2 {
				if e == nil || ids != nil {
					t.Fatal("uncertain pending publication adopted")
				}
			} else if e != nil || ids[0] != 1 {
				t.Fatal("stable old ID lost", e)
			}
		})
	}
}

func TestDHCPSubnetRegistryV1RejectsRetryWhileDirectorySyncFails(t *testing.T) {
	root, leases, uid, gid := subnetRegistryFSV1(t)
	ctx := context.Background()
	original := subnetBindingFixtureV1()
	if ids, err := ensureDHCPSubnetIDsV1(ctx, root, leases, []RoutedDHCPSubnetBindingV1{original}, uid, gid); err != nil || !reflect.DeepEqual(ids, []uint32{1}) {
		t.Fatalf("initialize registry: IDs=%v error=%v", ids, err)
	}
	added := original
	added.ScopeID = "new"
	bindings := []RoutedDHCPSubnetBindingV1{original, added}
	syncFails := func(*os.File) error { return unix.EIO }

	ids, err := ensureDHCPSubnetIDsWithDirectorySyncV1(ctx, root, leases, bindings, uid, gid, syncFails)
	if !errors.Is(err, ErrRoutedDHCPSubnetRegistryV1) || ids != nil {
		t.Fatalf("directory fsync failure returned IDs: %v, error=%v", ids, err)
	}
	record, missing, err := readDHCPSubnetRegistryV1(root, uid, gid)
	if err != nil || missing || record.HighWater != 2 {
		t.Fatalf("expected complete renamed manifest, got high_water=%d missing=%v error=%v", record.HighWater, missing, err)
	}
	ids, err = ensureDHCPSubnetIDsWithDirectorySyncV1(ctx, root, leases, bindings, uid, gid, syncFails)
	if !errors.Is(err, ErrRoutedDHCPSubnetRegistryV1) || ids != nil {
		t.Fatalf("retry returned IDs without successful directory fsync: %v, error=%v", ids, err)
	}
	ids, err = ensureDHCPSubnetIDsV1(ctx, root, leases, bindings, uid, gid)
	if err != nil || !reflect.DeepEqual(ids, []uint32{1, 2}) {
		t.Fatalf("retry after storage recovered: IDs=%v error=%v", ids, err)
	}
}

func TestDHCPSubnetRegistryV1CanceledLockWait(t *testing.T) {
	root, leases, uid, gid := subnetRegistryFSV1(t)
	if e := unix.Flock(int(root.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	defer unix.Flock(int(root.Fd()), unix.LOCK_UN)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if ids, e := ensureDHCPSubnetIDsV1(ctx, root, leases, []RoutedDHCPSubnetBindingV1{subnetBindingFixtureV1()}, uid, gid); e == nil || ids != nil {
		t.Fatal("blocked writer ignored cancellation")
	}
}

func TestDHCPSubnetRegistryV1RootLifecycleNative(t *testing.T) {
	if os.Getenv("ANDEIVA_NATIVE_DHCP_SUBNET_REGISTRY") != "1" {
		t.Skip("root filesystem qualification opt-in")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("root uid/gid required")
	}
	root, leases, _, _ := subnetRegistryFSV1(t)
	b := subnetBindingFixtureV1()
	ids, e := EnsureRoutedDHCPSubnetIDsV1(context.Background(), root, leases, []RoutedDHCPSubnetBindingV1{b})
	if e != nil || ids[0] != 1 {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(root.Name(), routedDHCPSubnetRegistryNameV1))
	if e != nil {
		t.Fatal(e)
	}
	var record routedDHCPSubnetRegistryV1
	if json.Unmarshal(raw, &record) != nil || record.HighWater != 1 {
		t.Fatal("durable native registry missing")
	}
	if _, e = EnsureRoutedDHCPSubnetIDsV1(context.Background(), root, leases, nil); e != nil {
		t.Fatal(e)
	}
	ids, e = EnsureRoutedDHCPSubnetIDsV1(context.Background(), root, leases, []RoutedDHCPSubnetBindingV1{b})
	if e != nil || ids[0] != 1 {
		t.Fatal("native re-enable changed ID", e)
	}
}
