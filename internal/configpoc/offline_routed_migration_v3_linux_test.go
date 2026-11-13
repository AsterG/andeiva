//go:build linux

package configpoc

import (
	"bytes"
	"context"
	"errors"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

// Unit-only verifier: filesystem, history and pools are real; kernel evidence
// is supplied by trusted runtime assembly and is not claimed by these tests.
type offlineMigrationReadbackTestV3 struct {
	calls  int
	verify func(context.Context, [2]LegacyFingerprintV2, Revision, Revision) error
}

func (r *offlineMigrationReadbackTestV3) VerifyMigratedSources(ctx context.Context, fp [2]LegacyFingerprintV2, fw, ls Revision) error {
	r.calls++
	if r.verify != nil {
		return r.verify(ctx, fp, fw, ls)
	}
	return nil
}

type offlineMigrationFixtureV3 struct {
	area     *os.Root
	sources  [2]*os.Root
	pools    RuntimePoolsV2
	budget   BudgetV2
	expected [2]LegacyFingerprintV2
	now      time.Time
	before   v2State
	fw, ls   Revision
}

func newOfflineMigrationFixtureV3(t *testing.T, change func(int, *durableState)) offlineMigrationFixtureV3 {
	t.Helper()
	area, pools, _, ls, subjects, budget := offlineSeedFixtureV3(t)
	fw, err := Canonical(coordinatorV2Rule("preserved-rule"))
	if err != nil {
		t.Fatal(err)
	}
	f := offlineMigrationFixtureV3{area: area, pools: pools, budget: budget, fw: fw, ls: ls, now: time.Now().UTC()}
	var bindings []LegacyBindingV2
	for i, domain := range []string{"firewall", "local_services"} {
		source, path := checkpointFixtureArea(t)
		f.sources[i] = source
		store, err := openStore(path, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rev := fw
		if i == 1 {
			rev = ls
		}
		state := durableState{Snapshot: Snapshot{Generation: uint64(9 + i*18), Running: rev, Startup: rev, LastGood: rev, Revoked: []string{}}, Receipts: map[string]receipt{"alice:retained-key": {Fingerprint: checkpointDigest([]byte("request")), Generation: 3}}}
		if change != nil {
			change(i, &state)
		}
		if err = store.append(state, Audit{Sequence: 1, Actor: "alice", At: f.now, Operation: OpSave, Surface: API, Result: "success", RunningHash: rev.Hash}, true, nil); err != nil {
			t.Fatal(err)
		}
		if err = store.lock.Close(); err != nil {
			t.Fatal(err)
		}
		f.expected[i], err = InspectLegacyV2(source, domain)
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, LegacyBindingV2{Source: f.expected[i].Source, Actor: "alice", Subject: subjects[0].ID, ReceiptIndex: f.expected[i].ReceiptIndex})
	}
	if err = PrepareMigrationV2(area, f.sources[0], f.sources[1], f.expected, subjects, bindings, budget, f.now); err != nil {
		t.Fatal(err)
	}
	s, err := openV2(area, v2Budget{Bytes: budget.Bytes, Inodes: budget.Inodes})
	if err != nil {
		t.Fatal(err)
	}
	f.before = clone(s.state)
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f offlineMigrationFixtureV3) prepare(readback OfflineMigrationReadbackV3) error {
	return PrepareOfflineMigratedRoutedStoreV3(context.Background(), f.area, f.sources, f.budget, f.pools, f.expected, readback, f.now)
}

func TestOfflineMigratedRoutedV3PreservesHistoryAndRequiresPhysicalBoot(t *testing.T) {
	f := newOfflineMigrationFixtureV3(t, nil)
	sources := [2]map[string][]byte{journalFiles(t, f.sources[0].Name()), journalFiles(t, f.sources[1].Name())}
	// Keep all existing object bytes, including immutable migration and receipts.
	existing := journalFiles(t, f.area.Name())
	verifier := &offlineMigrationReadbackTestV3{verify: func(_ context.Context, fp [2]LegacyFingerprintV2, fw, ls Revision) error {
		if fp != f.expected || !reflect.DeepEqual(fw, f.fw) || !reflect.DeepEqual(ls, f.ls) {
			t.Fatal("readback not bound to imported sources")
		}
		// A trusted implementation cannot mutate the imported configuration through aliases.
		for _, source := range f.sources {
			lock, e := lockLegacyV2(source)
			if e == nil {
				_ = lock.Close()
				t.Fatal("source lock released before verification/publication")
			}
		}
		fw.Config.Rules[0].ID = "callback-copy"
		return nil
	}}
	started := time.Now()
	if err := f.prepare(verifier); err != nil {
		t.Fatal(err)
	}
	if verifier.calls != 1 {
		t.Fatal("missing source readback")
	}
	for i := range f.sources {
		if !reflect.DeepEqual(sources[i], journalFiles(t, f.sources[i].Name())) {
			t.Fatal("source history changed")
		}
	}
	after := journalFiles(t, f.area.Name())
	var beforeBytes, afterBytes int
	for _, data := range existing {
		beforeBytes += len(data)
	}
	for _, data := range after {
		afterBytes += len(data)
	}
	t.Logf("source-bound offline publication: elapsed=%s files_added=%d logical_bytes_added=%d (not RAM or physical free blocks)", time.Since(started), len(after)-len(existing), afterBytes-beforeBytes)
	for name, data := range existing {
		if name != "selected.json" && !reflect.DeepEqual(data, after[name]) {
			t.Fatal("migration object changed", name)
		}
	}
	if s, err := openV2(f.area, v2Budget{Bytes: f.budget.Bytes, Inodes: f.budget.Inodes}); err == nil {
		_ = s.close()
		t.Fatal("private runtime accepted shared marker")
	}
	access := sharedTestAreaV2(t, f.area, "checkpoint.lock")
	s, err := openSharedStoreV2(f.area, v2Budget{Bytes: f.budget.Bytes, Inodes: f.budget.Inodes}, access)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	cfg := s.state.Configuration
	if cfg == nil || cfg.Running.Config.SchemaVersion != 7 || cfg.Firewall.Running.Hash != f.fw.Hash || cfg.LocalServices.Running.Hash != f.ls.Hash || cfg.Firewall.Generation != 9 || cfg.LocalServices.Generation != 27 || cfg.LastCompletedBoot != "" || s.state.Operational || s.state.RoutedActive != nil {
		t.Fatal("source was lost or treated as new gateway authority")
	}
	restored := clone(s.state)
	restored.Configuration = f.before.Configuration
	restored.RequiredFeatures = f.before.RequiredFeatures
	restored.RecoveryReserveVersion = f.before.RecoveryReserveVersion
	restored.Clock = f.before.Clock
	if !reflect.DeepEqual(restored, f.before) {
		t.Fatal("unrelated migration state changed")
	}
	c := &v2Coordinator{store: s}
	if err = c.validateReferencesLocked(); err != nil {
		t.Fatal(err)
	}
	snap, generation, err := s.legacyReplay(s.state.Subjects[0].ID, "firewall", "alice", "retained-key", checkpointDigest([]byte("request")))
	if err != nil || generation != 3 || snap.Running.Hash != f.fw.Hash {
		t.Fatal("legacy replay lost", err)
	}
	root, _ := f.area.Stat(".")
	r := &v2ReachabilityReader{ctx: context.Background(), area: f.area, root: root, shared: &access, budget: reachabilityBudgetV2(), objects: map[string]bool{}, edges: map[string]uint8{}}
	if _, err = r.traceLocked(s.lock); err != nil {
		t.Fatal("full migration closure", err)
	}
	for _, missing := range []string{"routed", "boot", "reserves", "deadline"} {
		t.Run(missing, func(t *testing.T) {
			boot := v2BootID("12345678-1234-1234-1234-123456789abc")
			manager, e := newReserveManagerV2(f.pools.Admission, f.pools.Plan, f.pools.Emergency)
			if e != nil {
				t.Fatal(e)
			}
			boundary := &seedPreparationBoundaryV3{err: errors.New("physical boundary")}
			options := v2CoordinatorOptions{Routed: boundary, BootID: &boot, Reserves: manager, GuardDeadlines: true}
			switch missing {
			case "routed":
				options.Routed = nil
			case "boot":
				options.BootID = nil
			case "reserves":
				options.Reserves = nil
			case "deadline":
				options.GuardDeadlines = false
			}
			if _, e = openCoordinatorV2(context.Background(), s, []Engine{NewSimEngine("not-called-fw")}, []Engine{NewSimEngine("not-called-ls")}, options); !errors.Is(e, ErrRecovery) || boundary.called {
				t.Fatal("missing assembly reached effects", e)
			}
		})
	}
	boot := v2BootID("12345678-1234-1234-1234-123456789abc")
	manager, e := newReserveManagerV2(f.pools.Admission, f.pools.Plan, f.pools.Emergency)
	if e != nil {
		t.Fatal(e)
	}
	boundary := &seedPreparationBoundaryV3{identity: networkexecutor.OwnedNamespaceIdentity{UID: 123, GID: 124, Namespace: 125, Host: 126, BootID: string(boot), RunID: "12345678123412341234123456789abc"}, err: errors.New("physical new gateway intentionally unavailable")}
	opened, e := openCoordinatorV2(context.Background(), s, []Engine{NewSimEngine("never-used-fw")}, []Engine{NewSimEngine("never-used-ls")}, v2CoordinatorOptions{Routed: boundary, RoutedIdentity: boundary.identity, BootID: &boot, Reserves: manager, GuardDeadlines: true})
	if opened != nil {
		opened.close()
	}
	if !boundary.called || !errors.Is(e, boundary.err) || s.state.Configuration.LastCompletedBoot != "" {
		t.Fatal("new gateway bypassed physical boot", e)
	}
	changed := clone(s.state)
	changed.Migration = ""
	if v2ValidState(changed) {
		t.Fatal("marker accepted without provenance")
	}
	changed = clone(s.state)
	changed.RequiredFeatures = append(changed.RequiredFeatures, "unknown.future")
	if v2ValidState(changed) {
		t.Fatal("unknown feature accepted")
	}
	changed = clone(s.state)
	for i, v := range changed.RequiredFeatures {
		if v == v2RoutedOfflineMigrationFeature {
			changed.RequiredFeatures = append(changed.RequiredFeatures[:i], changed.RequiredFeatures[i+1:]...)
			break
		}
	}
	if preservesFeaturesV2(s.state, changed) {
		t.Fatal("cold migration gate could be removed")
	}
}

func TestOfflineMigratedRoutedV3RejectsWithoutPublication(t *testing.T) {
	for _, kind := range []string{"stale", "no_readback", "readback_error", "cancelled", "cancel_during_readback", "clock", "pools", "same_source", "source_destination", "startup", "last_good", "active_local"} {
		t.Run(kind, func(t *testing.T) {
			change := func(i int, s *durableState) {
				if i == 0 {
					switch kind {
					case "startup", "last_good":
						r, e := Canonical(coordinatorV2Rule("different"))
						if e != nil {
							t.Fatal(e)
						}
						if kind == "startup" {
							s.Snapshot.Startup = r
						} else {
							s.Snapshot.LastGood = r
						}
					}
				} else if kind == "active_local" {
					r, e := Canonical(localSample(t, 9443))
					if e != nil {
						t.Fatal(e)
					}
					s.Snapshot.Running = r
					s.Snapshot.Startup = r
					s.Snapshot.LastGood = r
				}
			}
			f := newOfflineMigrationFixtureV3(t, change)
			before := journalFiles(t, f.area.Name())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			verifier := &offlineMigrationReadbackTestV3{}
			var provider OfflineMigrationReadbackV3 = verifier
			switch kind {
			case "stale":
				f.expected[0].Projection++
			case "no_readback":
				provider = nil
			case "readback_error":
				verifier.verify = func(context.Context, [2]LegacyFingerprintV2, Revision, Revision) error { return ErrEngine }
			case "cancelled":
				cancel()
			case "cancel_during_readback":
				verifier.verify = func(context.Context, [2]LegacyFingerprintV2, Revision, Revision) error { cancel(); return nil }
			case "clock":
				f.now = f.now.Add(-time.Second)
			case "pools":
				f.pools.Plan = f.pools.Admission
			case "same_source":
				f.sources[1] = f.sources[0]
			case "source_destination":
				f.sources[0] = f.area
			}
			err := PrepareOfflineMigratedRoutedStoreV3(ctx, f.area, f.sources, f.budget, f.pools, f.expected, provider, f.now)
			if err == nil {
				t.Fatal("invalid preparation accepted")
			}
			if !reflect.DeepEqual(before, journalFiles(t, f.area.Name())) {
				t.Fatal("rejection wrote destination")
			}
			if kind != "readback_error" && kind != "cancel_during_readback" && verifier.calls != 0 {
				t.Fatal("invalid input reached readback")
			}
		})
	}
}

func TestOfflineMigratedRoutedV3PublicationFailureReopensConservatively(t *testing.T) {
	for _, point := range []string{"objects_durable", "before_select", "after_select"} {
		t.Run(point, func(t *testing.T) {
			f := newOfflineMigrationFixtureV3(t, nil)
			failure := errors.New("test interruption")
			verifier := &offlineMigrationReadbackTestV3{}
			err := prepareOfflineMigratedRoutedStoreV3(context.Background(), f.area, f.sources, f.budget, f.pools, f.expected, verifier, f.now, func(p string) error {
				if p == point {
					return failure
				}
				return nil
			})
			if err == nil || verifier.calls != 1 {
				t.Fatal("failure not injected", err)
			}
			if point == "after_select" {
				access := sharedTestAreaV2(t, f.area, "checkpoint.lock")
				s, e := openSharedStoreV2(f.area, v2Budget{Bytes: f.budget.Bytes, Inodes: f.budget.Inodes}, access)
				if e != nil {
					t.Fatal(e)
				}
				defer s.close()
				if s.state.Migration != f.before.Migration || !hasFeatureV2(s.state, v2RoutedOfflineMigrationFeature) || s.state.Configuration.LastCompletedBoot != "" {
					t.Fatal("lost ACK claimed runtime or lost history")
				}
			} else {
				s, e := openV2(f.area, v2Budget{Bytes: f.budget.Bytes, Inodes: f.budget.Inodes})
				if e != nil {
					t.Fatal(e)
				}
				if !reflect.DeepEqual(s.state, f.before) {
					t.Fatal("failed publication selected partial upgrade")
				}
				if e = s.close(); e != nil {
					t.Fatal(e)
				}
				if point == "objects_durable" {
					if e = f.prepare(&offlineMigrationReadbackTestV3{}); e != nil {
						t.Fatal("retry", e)
					}
				} else if e = f.prepare(&offlineMigrationReadbackTestV3{}); e == nil {
					t.Fatal("unresolved selector staging was silently retried")
				}
			}
		})
	}
}

func TestOfflineMigratedRoutedV3OldReaderBarrier(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("explicit prior-source compatibility binary required")
	}
	f := newOfflineMigrationFixtureV3(t, nil)
	run := func(want string) {
		t.Helper()
		output, err := exec.Command(*reclaimOldReader, "-test.run=^TestOfflineMigrationPriorReaderV3$", "-offline-migration-prior-area="+f.area.Name()).CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte(want)) {
			t.Fatalf("prior reader qualification: %v %s", err, output)
		}
	}
	run("PRIOR_MIGRATION_ACCEPTED")
	if err := f.prepare(&offlineMigrationReadbackTestV3{}); err != nil {
		t.Fatal(err)
	}
	_ = sharedTestAreaV2(t, f.area, "checkpoint.lock")
	before := journalFiles(t, f.area.Name())
	run("PRIOR_MIGRATION_REJECTED")
	if !reflect.DeepEqual(before, journalFiles(t, f.area.Name())) {
		t.Fatal("old reader changed selected upgrade")
	}
}

func TestOfflineMigratedRoutedV3ConcurrentPreparationLocksSources(t *testing.T) {
	f := newOfflineMigrationFixtureV3(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	provider := &offlineMigrationReadbackTestV3{verify: func(context.Context, [2]LegacyFingerprintV2, Revision, Revision) error {
		close(entered)
		<-release
		return nil
	}}
	result := make(chan error, 1)
	go func() { result <- f.prepare(provider) }()
	select {
	case <-entered:
	case err := <-result:
		t.Fatal("verification not reached", err)
	}
	second := &offlineMigrationReadbackTestV3{}
	err := f.prepare(second)
	close(release)
	firstErr := <-result
	if !errors.Is(err, ErrLocked) || second.calls != 0 || firstErr != nil {
		t.Fatal("concurrent preparer crossed source barrier", err, firstErr)
	}
}
