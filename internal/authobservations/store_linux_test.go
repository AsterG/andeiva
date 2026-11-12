//go:build linux

package authobservations

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testGuard struct {
	runtime, protected, backup string
	unsupported, pressure      atomic.Bool
	mu                         sync.Mutex
	selected                   Selection
}

func (g *testGuard) Selection(s Selection) error {
	if g.unsupported.Load() || s.Feature != Feature || s.Runtime != g.runtime {
		return ErrUnavailable
	}
	p, e := os.ReadFile(g.protected)
	b, be := os.ReadFile(g.backup)
	if e != nil || be != nil || digest(p) != s.Protected || digest(b) != s.Backup {
		return ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.selected.Version == 0 {
		g.selected = s
	}
	if g.selected != s {
		return ErrUnavailable
	}
	return nil
}
func (g *testGuard) Capacity(_ AreaIdentity, used, peak uint64) error {
	if g.pressure.Load() || used > MaximumBytes || peak > MaximumBytes-used {
		return ErrLimited
	}
	return nil
}

func observationFixture(t testing.TB) (*Store, *os.Root, *testGuard) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	old := filepath.Join(t.TempDir(), "protected.jsonl")
	backup := filepath.Join(t.TempDir(), "backup.jsonl")
	protected := []byte("historic protected denials: immutable\n")
	if os.WriteFile(old, protected, 0600) != nil || os.WriteFile(backup, protected, 0600) != nil {
		t.Fatal("fixture")
	}
	g := &testGuard{runtime: strings.Repeat("a", 64), protected: old, backup: backup}
	if err := Prepare(root, g.runtime, digest(protected), digest(protected), g); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root, g)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, root, g
}

func reportTotal(r Report) uint64 {
	var total uint64
	for _, i := range r.Intervals {
		total += i.Total
	}
	return total
}

func setPublicationHook(s *Store, hook func(string) error) {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	s.hook = hook
}

func TestObservationsAggregatePeerAndPreserveProtected(t *testing.T) {
	s, root, g := observationFixture(t)
	old, _ := os.ReadFile(g.protected)
	backup, _ := os.ReadFile(g.backup)
	for _, peer := range []string{"198.18.0.1", "::ffff:198.18.0.1", "2001:db8::1"} {
		s.Record(netip.MustParseAddr(peer))
	}
	s.Record(netip.Addr{})
	r := s.Report()
	if reportTotal(r) != 4 || len(r.Intervals) != 1 || len(r.Intervals[0].Peers) != 2 || r.Intervals[0].Overflow != 1 || r.Counters.Unattributed != 1 {
		t.Fatal("wrong aggregation")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root, g)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if r = reopened.Report(); reportTotal(r) != 4 || !r.UnknownGap || r.PersistedThrough.IsZero() {
		t.Fatal("reopen invented complete observation history")
	}
	after, _ := os.ReadFile(g.protected)
	afterBackup, _ := os.ReadFile(g.backup)
	if string(old) != string(after) || string(backup) != string(afterBackup) {
		t.Fatal("protected bytes changed")
	}
}

func TestObservationsCardinalityConcurrentAndPressure(t *testing.T) {
	s, _, g := observationFixture(t)
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func(n int) {
			defer workers.Done()
			for i := 0; i < 1000; i++ {
				s.Record(netip.AddrFrom4([4]byte{198, 18, byte(n), byte(i%250 + 1)}))
			}
		}(n)
	}
	workers.Wait()
	r := s.Report()
	if reportTotal(r) != 8000 || len(r.Intervals[0].Peers) != maximumPeers || r.Intervals[0].Overflow == 0 {
		t.Fatal("cardinality/overflow")
	}
	g.pressure.Store(true)
	if err := s.Flush(context.Background()); !errors.Is(err, ErrLimited) || !s.Report().Degraded {
		t.Fatal("pressure hidden", err)
	}
	s.Record(netip.MustParseAddr("198.18.0.1"))
	if reportTotal(s.Report()) != 8001 {
		t.Fatal("pressure stopped bounded volatile observations")
	}
	g.pressure.Store(false)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Report().AllocatedBytes > MaximumBytes {
		t.Fatal("observed allocation exceeded bound")
	}
}

func TestObservationsExpiryClockAndSnapshotIsolation(t *testing.T) {
	s, root, g := observationFixture(t)
	s.Record(netip.MustParseAddr("198.18.0.1"))
	r := s.Report()
	created := r.Intervals[0].Created
	// Snapshot callers cannot mutate retained data.
	r.Intervals[0].Peers[0].Peer = "forged"
	if s.Report().Intervals[0].Peers[0].Peer == "forged" {
		t.Fatal("report aliases storage")
	}
	s.mu.Lock()
	s.now = func() time.Time { return created.Add(MaximumAge) }
	s.mu.Unlock()
	if r = s.Report(); len(r.Intervals) != 0 || r.Counters.Expired != 1 {
		t.Fatal("expired detail retained")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root, g)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.Report().Intervals) != 0 {
		t.Fatal("expired detail reappeared")
	}
	reopened.Record(netip.MustParseAddr("198.18.0.1"))
	if reopened.Report().Counters.ClockRejected != 1 || !reopened.Report().Degraded {
		t.Fatal("backward clock accepted")
	}
}

func TestObservationsSelectionAndOldReaderRefusalSeam(t *testing.T) {
	s, root, g := observationFixture(t)
	g.unsupported.Store(true)
	if s.Admitted() == nil {
		t.Fatal("unsupported runtime selection admitted")
	}
	if err := s.Flush(context.Background()); err == nil {
		t.Fatal("selection mismatch wrote")
	}
	g.unsupported.Store(false)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	g.unsupported.Store(true)
	if _, err := Open(root, g); err == nil {
		t.Fatal("old mode reopened selected storage")
	}
	g.unsupported.Store(false)
	if os.WriteFile(g.backup, []byte("changed backup"), 0600) != nil {
		t.Fatal("fixture")
	}
	if _, err := Open(root, g); err == nil {
		t.Fatal("changed rollback precondition admitted")
	}
	// This tests the required selector seam, not an unwired old production
	// binary. No production selector currently enables this store.
}

func TestObservationsFilesFailClosed(t *testing.T) {
	for _, scenario := range []string{"unknown", "symlink", "hardlink", "version", "duplicate", "truncated-next", "wrong-area"} {
		t.Run(scenario, func(t *testing.T) {
			s, root, g := observationFixture(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unknown":
				if root.WriteFile("foreign", []byte("retain"), 0600) != nil {
					t.Fatal("fixture")
				}
			case "symlink":
				if root.Symlink("policy.json", "observations.next") != nil {
					t.Fatal("fixture")
				}
			case "hardlink":
				if root.Link("observations.json", "observations.next") != nil {
					t.Fatal("fixture")
				}
			case "version", "wrong-area":
				b, _ := root.ReadFile("policy.json")
				var p Selection
				if json.Unmarshal(b, &p) != nil {
					t.Fatal("fixture")
				}
				if scenario == "version" {
					p.Version = 2
				} else {
					p.Area.Inode++
				}
				b, _ = json.Marshal(p)
				if root.WriteFile("policy.json", b, 0600) != nil {
					t.Fatal("fixture")
				}
			case "duplicate":
				b, _ := root.ReadFile("policy.json")
				b = append([]byte(`{"Version":1,`), b[1:]...)
				if root.WriteFile("policy.json", b, 0600) != nil {
					t.Fatal("fixture")
				}
			case "truncated-next":
				if root.WriteFile("observations.next", []byte("{"), 0600) != nil {
					t.Fatal("fixture")
				}
			}
			if _, err := Open(root, g); err == nil {
				t.Fatal("unsafe file accepted")
			}
			if scenario == "unknown" {
				b, e := root.ReadFile("foreign")
				if e != nil || string(b) != "retain" {
					t.Fatal("foreign file removed")
				}
			}
		})
	}
}

func TestObservationsInterruptedSnapshotReopen(t *testing.T) {
	s, root, g := observationFixture(t)
	s.Record(netip.MustParseAddr("198.18.0.1"))
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := root.ReadFile("observations.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := decodeSnapshot(body, s.policy.ID)
	if err != nil {
		t.Fatal(err)
	}
	data.Generation++
	data.Intervals[0].Total++
	data.Intervals[0].Overflow++
	body, err = snapshotBytes(data)
	if err != nil || root.WriteFile("observations.next", body, 0600) != nil {
		t.Fatal("fixture")
	}
	reopened, err := Open(root, g)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reportTotal(reopened.Report()) != 1 || !reopened.Report().UnknownGap {
		t.Fatal("unselected snapshot promoted")
	}
}

func TestObservationsProcessExit(t *testing.T) {
	if len(os.Args) >= 5 && os.Args[len(os.Args)-4] == "observation-child" {
		args := os.Args[len(os.Args)-3:]
		root, e := os.OpenRoot(args[0])
		if e != nil {
			os.Exit(90)
		}
		g := &testGuard{runtime: strings.Repeat("a", 64), protected: args[1], backup: args[2]}
		s, e := Open(root, g)
		if e != nil {
			os.Exit(91)
		}
		s.Record(netip.MustParseAddr("198.18.0.1"))
		if s.Flush(context.Background()) != nil {
			os.Exit(92)
		}
		s.Record(netip.MustParseAddr("198.18.0.2"))
		os.Exit(74)
	}
	s, root, g := observationFixture(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestObservationsProcessExit$", "--", "observation-child", root.Name(), g.protected, g.backup)
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 74 {
		t.Fatalf("child did not reach exit: %v %s", err, output)
	}
	reopened, err := Open(root, g)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if r := reopened.Report(); reportTotal(r) != 1 || !r.UnknownGap {
		t.Fatal("crash fabricated exact counts")
	}
}

func TestObservationsNilAndBusy(t *testing.T) {
	var nilStore *Store
	if nilStore.Admitted() == nil || !nilStore.Report().Degraded || nilStore.Flush(context.Background()) == nil {
		t.Fatal("nil store accepted")
	}
	nilStore.Record(netip.Addr{})
	if nilStore.Close() != nil {
		t.Fatal("nil close")
	}
	zero := new(Store)
	if zero.Admitted() == nil || !zero.Report().Degraded {
		t.Fatal("zero store")
	}
	zero.Record(netip.Addr{})
	_ = zero.Close()
	s, root, g := observationFixture(t)
	if _, err := Open(root, g); err == nil {
		t.Fatal("two writers")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(s.Flush(ctx), context.Canceled) {
		t.Fatal("cancelled flush")
	}
}

func TestObservationsPublicationBoundaries(t *testing.T) {
	for _, point := range []string{"before_temporary", "after_temporary_sync", "after_rename", "after_directory_sync"} {
		t.Run(point, func(t *testing.T) {
			s, root, g := observationFixture(t)
			s.Record(netip.MustParseAddr("198.18.0.1"))
			setPublicationHook(s, func(p string) error {
				if p == point {
					return errors.New("interrupted publication")
				}
				return nil
			})
			if s.Flush(context.Background()) == nil {
				t.Fatal("failure not reached")
			}
			if !s.Report().Degraded || !s.Report().UnknownGap {
				t.Fatal("publication uncertainty hidden")
			}
			if point != "before_temporary" {
				setPublicationHook(s, nil)
				if s.Flush(context.Background()) == nil {
					t.Fatal("uncertain selection retried in same handle")
				}
			}
			_ = s.Close()
			reopened, err := Open(root, g)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			var want uint64
			if point == "after_rename" || point == "after_directory_sync" {
				want = 1
			}
			if reportTotal(reopened.Report()) != want || !reopened.Report().UnknownGap {
				t.Fatal("reopen invented observation outcome")
			}
		})
	}
}

func TestObservationsIntervalBoundAndSaturation(t *testing.T) {
	s, _, _ := observationFixture(t)
	base := time.Now().UTC().Truncate(time.Minute).Add(time.Minute)
	for i := 0; i <= maximumIntervals; i++ {
		now := base.Add(time.Duration(i) * time.Minute)
		if i == 0 {
			now = now.Add(59 * time.Second)
		}
		s.mu.Lock()
		s.now = func() time.Time { return now }
		s.mu.Unlock()
		s.Record(netip.MustParseAddr("198.18.0.1"))
	}
	r := s.Report()
	var overflow uint64
	for _, interval := range r.Intervals {
		overflow += interval.Overflow
	}
	if len(r.Intervals) != maximumIntervals || r.Counters.CapacityEvicted != 1 || overflow == 0 {
		t.Fatal("time/cardinality bounds not visible")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	last := &s.data.Intervals[len(s.data.Intervals)-1]
	last.Total, last.Overflow = ^uint64(0), ^uint64(0)
	last.Peers = nil
	s.mu.Unlock()
	s.Record(netip.MustParseAddr("198.18.0.1"))
	if !s.Report().Counters.Saturated {
		t.Fatal("counter overflow hidden")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkObservationsExistingPeer(b *testing.B) {
	s, _, _ := observationFixture(b)
	peer := netip.MustParseAddr("198.18.0.1")
	s.Record(peer)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Record(peer)
	}
}

func TestObservationsSelectedFilesCannotDrift(t *testing.T) {
	for _, name := range []string{"policy.json", "observations.json", "lock"} {
		t.Run(name, func(t *testing.T) {
			s, root, _ := observationFixture(t)
			before, err := root.ReadFile("observations.json")
			if err != nil {
				t.Fatal(err)
			}
			body, err := root.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if name != "lock" {
				body = append(body, '\n')
			}
			if err := root.Remove(name); err != nil {
				t.Fatal(err)
			}
			if err := writeNew(root, name, body); err != nil {
				t.Fatal(err)
			}
			s.Record(netip.MustParseAddr("198.18.0.1"))
			if err := s.Flush(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("drift admitted: %v", err)
			}
			after, err := root.ReadFile("observations.json")
			if err != nil {
				t.Fatal(err)
			}
			want := before
			if name == "observations.json" {
				want = body
			}
			if string(after) != string(want) {
				t.Fatal("drift overwritten")
			}
			if _, err := root.Lstat("observations.next"); !os.IsNotExist(err) {
				t.Fatal("temporary created after drift")
			}
		})
	}
}

func TestObservationsConcurrentRecordDuringPublication(t *testing.T) {
	s, root, guard := observationFixture(t)
	peer := netip.MustParseAddr("198.18.0.1")
	s.Record(peer)
	started, release := make(chan struct{}), make(chan struct{})
	setPublicationHook(s, func(point string) error {
		if point == "after_temporary_sync" {
			close(started)
			<-release
		}
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- s.Flush(context.Background()) }()
	<-started
	s.Record(peer)
	if got := reportTotal(s.Report()); got != 2 {
		t.Errorf("in-memory count: %d", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	setPublicationHook(s, nil)
	if !s.Report().Pending {
		t.Fatal("concurrent observation marked persisted")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root, guard)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reportTotal(reopened.Report()); got != 2 {
		t.Fatalf("concurrent observation lost: %d", got)
	}
}

func TestObservationsBoundedResourceSample(t *testing.T) {
	s, root, _ := observationFixture(t)
	base := time.Now().UTC().Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < maximumIntervals; i++ {
		now := base.Add(time.Duration(i) * time.Minute)
		s.mu.Lock()
		s.now = func() time.Time { return now }
		s.mu.Unlock()
		s.Record(netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"))
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := root.Stat("observations.json")
	if err != nil {
		t.Fatal(err)
	}
	r := s.Report()
	peers := 0
	for _, i := range r.Intervals {
		peers += len(i.Peers)
	}
	if peers != maximumPeers || len(r.Intervals) != maximumIntervals || r.AllocatedBytes > MaximumBytes || info.Size() > maximumSnapshot {
		t.Fatal("resource bound")
	}
	t.Logf("intervals=%d peer_minute_entries=%d snapshot_bytes=%d allocated_named_bytes=%d", len(r.Intervals), peers, info.Size(), r.AllocatedBytes)
}

func TestObservationsDegradedRequiresIndependentSelection(t *testing.T) {
	s, root, guard := observationFixture(t)
	canonical := s.policy
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Remove("observations.json"); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("interrupted untrusted snapshot")
	if err := writeNew(root, "observations.json", corrupt); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("preserve unknown file")
	if err := writeNew(root, "foreign", foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, guard); err == nil {
		t.Fatal("corruption silently opened")
	}
	for _, bad := range []Selection{{}, {Version: 2}, func() Selection { p := canonical; p.ID = strings.Repeat("0", 32); return p }(), func() Selection { p := canonical; p.Area.Inode++; return p }()} {
		if _, err := OpenDegraded(root, bad, guard); err == nil {
			t.Fatal("invalid independent selection admitted")
		}
	}
	if _, err := OpenDegraded(root, canonical, nil); err == nil {
		t.Fatal("nil guard")
	}
	guard.unsupported.Store(true)
	if _, err := OpenDegraded(root, canonical, guard); err == nil {
		t.Fatal("unsupported selection")
	}
	guard.unsupported.Store(false)
	guard.pressure.Store(true)
	d, err := OpenDegraded(root, canonical, guard)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Admitted(); err != nil {
		t.Fatal(err)
	}
	d.Record(netip.MustParseAddr("198.18.0.1"))
	r := d.Report()
	if !r.MemoryOnly || !r.Degraded || !r.UnknownGap || r.AllocatedKnown || !r.PersistedThrough.IsZero() || reportTotal(r) != 1 {
		t.Fatal("degraded report invented durable history or allocation")
	}
	if d.done != nil || d.lock != nil {
		t.Fatal("degraded mode started writer")
	}
	if d.Flush(context.Background()) == nil || d.Close() == nil {
		t.Fatal("memory-only publication claimed success")
	}
	for name, want := range map[string][]byte{"observations.json": corrupt, "foreign": foreign} {
		got, err := root.ReadFile(name)
		if err != nil || string(got) != string(want) {
			t.Fatal("degraded mode altered files")
		}
	}
}
