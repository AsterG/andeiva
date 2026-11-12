//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// Only test fixtures are converted here. Production conversion is an offline
// operator responsibility; the library never changes existing permissions.
func sharedTestAreaV2(t *testing.T, area *os.Root, lockName string) recoveryreserve.ReaderAccessV2 {
	t.Helper()
	if err := os.Chmod(area.Name(), os.ModeSetgid|0750); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(area.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		mode := os.FileMode(0640)
		if entry.Name() == lockName {
			mode = 0600
		}
		if err = os.Chmod(filepath.Join(area.Name(), entry.Name()), mode); err != nil {
			t.Fatal(err)
		}
	}
	info, err := area.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return recoveryreserve.ReaderAccessV2{Version: 1, OwnerUID: st.Uid, ReaderGID: st.Gid, Device: st.Dev, Inode: st.Ino}
}

func sharedTestStoreV2(t *testing.T, s *v2Store) *v2Store {
	t.Helper()
	state := clone(s.state)
	addFeatureV2(&state, v2SharedReaderFeature)
	s.preparingShared = true
	err := s.publish(state)
	s.preparingShared = false
	if err != nil {
		t.Fatal(err)
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	if unexpected, e := openV2(s.root, s.budget); e == nil {
		_ = unexpected.close()
		t.Fatal("private reader accepted shared marker")
	}
	access := sharedTestAreaV2(t, s.root, "checkpoint.lock")
	opened, err := openSharedStoreV2(s.root, s.budget, access)
	if err != nil {
		t.Fatal("shared reopen", err)
	}
	t.Cleanup(func() { _ = opened.close() })
	return opened
}

func TestSharedProfileV2WriterAndReclamation(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	s = sharedTestStoreV2(t, s)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var last v2Operation
	for range 40 {
		last = v2Cycle(t, s, subject, ns.ID, now)
	}
	state := clone(s.state)
	report, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || !report.Complete || report.Removed == 0 {
		t.Fatal(report, err)
	}
	if !reflect.DeepEqual(state, s.state) {
		t.Fatal("GC changed selected state")
	}
	got, err := s.lookup(subject, last.ID)
	if err != nil || !reflect.DeepEqual(got, last) {
		t.Fatal("replay changed", err)
	}
	entries, err := os.ReadDir(area.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, e := area.Lstat(entry.Name())
		want := os.FileMode(0640)
		if entry.Name() == "checkpoint.lock" {
			want = 0600
		}
		if e != nil || info.Mode().Perm() != want {
			t.Fatal("wrong persisted mode", entry.Name(), e)
		}
	}
	selected, used := s.selector, s.used
	bad := clone(s.state)
	bad.RequiredFeatures = nil
	if err = s.publish(bad); err == nil || s.selector != selected || s.used != used {
		t.Fatal("feature removal changed state", err)
	}
}

func TestSharedProfileV2ExplicitPreparationFencesWithoutChmod(t *testing.T) {
	c, area, engines, _, _ := coordinatorV2Fixture(t, false)
	service := &ServiceV2{coordinator: c}
	for _, engine := range engines {
		engine.reset()
	}
	if err := service.PrepareSharedReaderV2(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.store.blocked || !hasFeatureV2(c.store.state, v2SharedReaderFeature) {
		t.Fatal("preparation did not fence")
	}
	info, err := area.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("preparation changed directory", err)
	}
	entries, err := os.ReadDir(area.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, e := area.Stat(entry.Name())
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("preparation changed existing file", e)
		}
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("preparation applied engine")
		}
	}
	if err = service.PrepareSharedReaderV2(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatal(err)
	}
}

func TestSharedProfileV2ReclamationRefusesChangedProvenance(t *testing.T) {
	for _, mode := range []string{"hardlink", "mode", "replacement", "cancelled", "promotion"} {
		t.Run(mode, func(t *testing.T) {
			original, area, _, _ := v2Fixture(t, 64)
			s := sharedTestStoreV2(t, original)
			if err := s.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
			hash := reclaimOrphanV2(t, s, "new-page")
			name, _ := v2ObjectName(hash)
			path := filepath.Join(area.Name(), name)
			ctx := context.Background()
			switch mode {
			case "hardlink":
				if err := os.Link(path, filepath.Join(t.TempDir(), "held")); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(path, path+".held"); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, raw, 0640); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "promotion":
				var page v2Page
				if err := s.readObject(hash, &page); err != nil {
					t.Fatal(err)
				}
				if _, err := s.object(page); err != nil {
					t.Fatal(err)
				}
			}
			report, err := s.reclaimIndexPages(ctx, reachabilityBudgetV2())
			if mode == "promotion" {
				if err != nil || !report.AuthorityRevoked || report.Removed != 0 {
					t.Fatal(report, err)
				}
			} else if err == nil {
				t.Fatal("invalid provenance accepted", mode)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("held file removed", err)
			}
		})
	}
}

func selectedReaderFixtureV2(t *testing.T) (*RoutedSelectionReaderV2, *v2Coordinator, v2TrustedPrincipal) {
	t.Helper()
	c, _, _, principal, _ := coordinatorV2Fixture(t, false)
	manager, areas := attachReserveAreasV2(t, c)
	if err := c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); err != nil {
		t.Fatal(err)
	}
	c.store = sharedTestStoreV2(t, c.store)
	pools := []*recoveryreserve.PoolV2{manager.admission, manager.plan, manager.emergency}
	readers := make([]*recoveryreserve.ReadOnlyPoolV2, 3)
	sharedPools := make([]*recoveryreserve.PoolV2, 3)
	for i, pool := range pools {
		profile, err := pool.Profile()
		if err != nil {
			t.Fatal(err)
		}
		if err = pool.Close(); err != nil {
			t.Fatal(err)
		}
		access := sharedTestAreaV2(t, areas[i], "")
		sharedPools[i], err = recoveryreserve.OpenSharedV2(areas[i], access)
		if err != nil {
			t.Fatal("pool writer", err)
		}
		t.Cleanup(func() { _ = sharedPools[i].Close() })
		readers[i], err = recoveryreserve.OpenReadOnlyV2(areas[i], access, profile)
		if err != nil {
			t.Fatal("pool reader", err)
		}
		t.Cleanup(func() { _ = readers[i].Close() })
	}
	var err error
	manager, err = newReserveManagerV2(sharedPools[0], sharedPools[1], sharedPools[2])
	if err != nil {
		t.Fatal(err)
	}
	c.store.reserves = manager
	c.options.Reserves = manager
	identity := networkexecutor.OwnedNamespaceIdentity{UID: c.store.access.OwnerUID + 1, GID: c.store.access.ReaderGID, Host: 11, Namespace: 22, BootID: "12345678-1234-1234-1234-123456789abc", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	reader, err := NewRoutedSelectionReaderV2(c.store.root, SelectionReaderOptionsV2{Access: *c.store.access, Identity: identity, Admission: readers[0], Plan: readers[1], Emergency: readers[2], Budget: reachabilityBudgetV2()})
	if err != nil {
		t.Fatal(err)
	}
	return reader, c, principal
}

func TestSelectedReaderV2RealStoreAndStaleSelection(t *testing.T) {
	r, c, p := selectedReaderFixtureV2(t)
	ref, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal("observe", err)
	}
	if ref.Mode != "prepare" || ref.State != c.store.selection.State || ref.Generation != c.store.state.Generation {
		t.Fatal(ref)
	}
	before := c.store.selector
	view, err := r.PrepareView(context.Background(), ref)
	if err != nil || view.Startup.Composite.Hash != c.store.state.Configuration.Startup.Hash {
		t.Fatal("prepare", err)
	}
	if c.store.selector != before {
		t.Fatal("reader wrote selection")
	}
	if _, err = r.Resolve(context.Background(), ref, SelectionArmV2); err == nil {
		t.Fatal("unselected plan authorized")
	}
	doc, objects := compositeRoutedFixture(t, true)
	fw := objects[doc.Domains.Firewall.Revision].Config
	if _, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &fw}); err != nil {
		t.Fatal("shared stage", err)
	}
	if _, err = r.PrepareView(context.Background(), ref); !errors.Is(err, ErrConflict) {
		t.Fatal("stale selection accepted", err)
	}
	current, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal("post-stage closure", err)
	}
	if current.Generation <= ref.Generation {
		t.Fatal("generation unchanged")
	}
	r.options.Budget.Objects = 1
	if _, err = r.Observe(context.Background()); err == nil {
		t.Fatal("budget ignored")
	}
}
