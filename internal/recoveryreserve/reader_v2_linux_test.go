//go:build linux

package recoveryreserve

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func sharedAreaV2(t testing.TB) (*os.Root, ReaderAccessV2, string) {
	t.Helper()
	path, err := os.MkdirTemp("", "andeiva-reader-v2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(path, os.ModeSetgid|0750); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	i, err := r.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	s := i.Sys().(*syscall.Stat_t)
	if s.Uid == 0 || s.Gid == 0 {
		t.Fatal("run reader profile tests under a non-root account")
	}
	return r, ReaderAccessV2{Version: 1, OwnerUID: s.Uid, ReaderGID: s.Gid, Device: s.Dev, Inode: s.Ino}, path
}

func sharedPoolV2(t testing.TB) (*PoolV2, *ReadOnlyPoolV2, *os.Root, ReaderAccessV2, string) {
	t.Helper()
	a, access, path := sharedAreaV2(t)
	p, err := PrepareSharedV2(a, 18, 16384, PlanV2, access)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	profile, err := p.Profile()
	if err != nil {
		t.Fatal(err)
	}
	r, err := OpenReadOnlyV2(a, access, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return p, r, a, access, path
}

func TestReadOnlyV2WriterLockAndBoundEvidence(t *testing.T) {
	p, r, a, _, _ := sharedPoolV2(t)
	before := snapshotV2(t, a)
	s, err := r.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Slots()) != 18 || !reflect.DeepEqual(before, snapshotV2(t, a)) {
		t.Fatal("read modified pool")
	}
	if data, err := json.Marshal(s); err != nil || string(data) != "{}" {
		t.Fatal("snapshot became a wire capability")
	}
	if fmt.Sprintf("%+v %#v", s, s) != "reserve snapshot (opaque) reserve snapshot (opaque)" {
		t.Fatal("snapshot formatting exposed records")
	}
	for _, f := range append([]slotV2{{file: r.pool.lock}}, r.pool.slots...) {
		flags, err := unix.FcntlInt(f.file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("reader descriptor is writable")
		}
	}
	claim, err := p.ClaimClass("reader-bundle", OrdinaryV2)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Revalidate(context.Background(), s); err != ErrConflict {
		t.Fatalf("old snapshot survived claim: %v", err)
	}
	b, err := p.WriteOnce(claim, []byte("bounded-plan"), scopeForV2(claim.Owner))
	if err != nil {
		t.Fatal(err)
	}
	s, err = r.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := s.ReadBound(b)
	if err != nil || string(data) != "bounded-plan" {
		t.Fatal(err)
	}
	data[0] = 'x'
	slots := s.Slots()
	slots[claim.Slot].Binding.ScopeHash = digest([]byte("foreign"))
	data, err = s.ReadBound(b)
	if err != nil || string(data) != "bounded-plan" {
		t.Fatal("snapshot aliases caller memory")
	}
	foreign := b
	foreign.ScopeHash = digest([]byte("foreign"))
	if _, err = s.ReadBound(foreign); err != ErrConflict {
		t.Fatal("foreign binding accepted")
	}
	if err = r.Revalidate(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenV2(a); err == nil {
		t.Fatal("private reader adopted shared profile")
	}
}

func TestReadOnlyV2ChangedOlderBankTornAndABA(t *testing.T) {
	p, r, _, _, _ := sharedPoolV2(t)
	c, err := p.Claim("bank-change")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.WriteOnce(c, []byte("p"), scopeForV2(c.Owner))
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Synchronizing the older bank preserves the winning binding, but changes
	// the exact bank evidence and must invalidate the earlier snapshot.
	newer, payload, err := p.readBank(c.Slot, int(b.Sequence%2))
	if err != nil {
		t.Fatal(err)
	}
	offset := int64(1-b.Sequence%2) * bankSizeV2(p.manifest.Capacity)
	if _, err = p.slots[c.Slot].file.WriteAt(payload, offset+headerV2); err != nil {
		t.Fatal(err)
	}
	if err = writeHeaderV2(p.slots[c.Slot].file, offset, newer); err != nil {
		t.Fatal(err)
	}
	if err = r.Revalidate(context.Background(), s); err != ErrConflict {
		t.Fatalf("older bank change: %v", err)
	}
	if err = p.RetireCAS(ExpectedV2{Claim: c, Written: &b}, proofForV2(scopeForV2(c.Owner))); err != nil {
		t.Fatal(err)
	}
	c2, err := p.Claim(c.Owner)
	if err != nil || c2.Epoch <= c.Epoch {
		t.Fatalf("reuse: %v", err)
	}
	s, err = r.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadBound(b); err == nil {
		t.Fatal("retired binding survived epoch reuse")
	}
	if _, err = p.slots[c.Slot].file.WriteAt([]byte("!"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Snapshot(context.Background()); err != ErrUnavailable {
		t.Fatal("torn bank accepted")
	}
}

func TestReadOnlyV2RejectsIdentityModesLinksAndACL(t *testing.T) {
	for _, kind := range []string{"file-mode", "directory-mode", "hardlink", "symlink", "rename", "file-acl", "directory-acl", "default-acl"} {
		t.Run(kind, func(t *testing.T) {
			_, r, _, _, path := sharedPoolV2(t)
			name := filepath.Join(path, slotName(0))
			s, err := r.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "file-mode":
				err = os.Chmod(name, 0600)
			case "directory-mode":
				err = os.Chmod(path, 0750)
			case "hardlink":
				err = os.Link(name, filepath.Join(path, "foreign-link"))
			case "symlink", "rename":
				err = os.Rename(name, name+".old")
				if err == nil && kind == "symlink" {
					err = os.Symlink(name+".old", name)
				}
				if err == nil && kind == "rename" {
					err = os.WriteFile(name, []byte("foreign"), 0640)
				}
			case "file-acl", "directory-acl", "default-acl":
				target, attr := name, "system.posix_acl_access"
				if kind != "file-acl" {
					target = path
				}
				if kind == "default-acl" {
					attr = "system.posix_acl_default"
				}
				// Linux xattr ACL v2 with an additional named reader. Existing mode
				// bits stay 0640/02750, so a mode-only check would miss this grant.
				acl := make([]byte, 4+5*8)
				binary.LittleEndian.PutUint32(acl, 2)
				perms := []uint16{6, 4, 4, 4, 0}
				if kind != "file-acl" {
					perms = []uint16{7, 5, 5, 5, 0}
				}
				for i, tag := range []uint16{1, 2, 4, 16, 32} {
					off := 4 + i*8
					binary.LittleEndian.PutUint16(acl[off:], tag)
					binary.LittleEndian.PutUint16(acl[off+2:], perms[i])
					id := uint32(0xffffffff)
					if tag == 2 {
						id = uint32(os.Geteuid() + 1)
					}
					binary.LittleEndian.PutUint32(acl[off+4:], id)
				}
				err = unix.Setxattr(target, attr, acl, 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = r.Revalidate(context.Background(), s); err != ErrUnavailable {
				t.Fatalf("%s accepted: %v", kind, err)
			}
		})
	}
}

func TestReadOnlyV2AdmissionCancelCloseAndConcurrentReads(t *testing.T) {
	_, r, a, access, _ := sharedPoolV2(t)
	profile := profileOfV2(r.pool.manifest)
	for _, mutate := range []func(*ReaderAccessV2){func(a *ReaderAccessV2) { a.Version++ }, func(a *ReaderAccessV2) { a.OwnerUID++ }, func(a *ReaderAccessV2) { a.ReaderGID++ }, func(a *ReaderAccessV2) { a.Device++ }, func(a *ReaderAccessV2) { a.Inode++ }} {
		wrong := access
		mutate(&wrong)
		if x, err := OpenReadOnlyV2(a, wrong, profile); err == nil {
			_ = x.Close()
			t.Fatal("wrong trusted identity accepted")
		}
	}
	wrong := profile
	wrong.ID = "ffffffffffffffffffffffffffffffff"
	if x, err := OpenReadOnlyV2(a, access, wrong); err == nil {
		_ = x.Close()
		t.Fatal("wrong pool accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Snapshot(ctx); err != ErrUnavailable {
		t.Fatal("cancel accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := r.Snapshot(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			if err = r.Revalidate(context.Background(), s); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Snapshot(context.Background()); err != ErrUnavailable {
		t.Fatal("closed reader accepted")
	}
	var nilReader *ReadOnlyPoolV2
	for _, x := range []*ReadOnlyPoolV2{nilReader, {}} {
		if _, err := x.Snapshot(context.Background()); err != ErrInvalid {
			t.Fatal("zero reader accepted")
		}
		if err := x.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (PoolSnapshotV2{}).ReadBound(BindingV2{}); err != ErrInvalid {
		t.Fatal("zero snapshot accepted")
	}
}

func TestReadOnlyV2NoMigrationAndReopen(t *testing.T) {
	p, r, a, access, _ := sharedPoolV2(t)
	profile := profileOfV2(p.manifest)
	before := snapshotV2(t, a)
	if _, err := PrepareSharedV2(a, 18, 16384, PlanV2, access); err == nil {
		t.Fatal("adopted existing pool")
	}
	if !reflect.DeepEqual(before, snapshotV2(t, a)) {
		t.Fatal("failed prepare changed pool")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := OpenSharedV2(a, access)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	}()
	r, err = OpenReadOnlyV2(a, access, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err = r.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshotV2(t, a)) {
		t.Fatal("reopen changed bytes")
	}
}

func BenchmarkReadOnlyV2Snapshot(b *testing.B) {
	p, r, _, _, _ := sharedPoolV2(b)
	for i := 0; i < 18; i++ {
		owner := string(rune('a' + i))
		c, err := p.Claim(owner)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = p.WriteOnce(c, bytes.Repeat([]byte{byte(i)}, 16384), scopeForV2(owner)); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := r.Snapshot(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
