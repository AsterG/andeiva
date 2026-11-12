//go:build linux

package configpoc

import (
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func closingFixtureV2(t *testing.T) (*v2Store, time.Time, string, string, v2Operation) {
	t.Helper()
	s, _, now, subject := v2Fixture(t, 64)
	s.mu.Lock()
	err := s.enableClosingCreditsLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	origin, err := s.admit(subject, ns.ID, s.state.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.begin(subject, origin.ID, now); err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(90 * time.Second)
	origin, err = s.finish(subject, origin.ID, v2Outcome{Code: "applied_pending_confirmation", Generation: s.state.Generation, RunningRevision: strings.Repeat("a", 64), ConfirmationLease: "exact-fixture-lease", ConfirmationDeadline: &deadline}, []byte("catalogue-only fixture; no applied engine"), now, true)
	if err != nil {
		t.Fatal(err)
	}
	return s, now, subject, ns.ID, origin
}

func closingRequestV2(origin v2Operation) v2Request {
	return v2Request{Kind: OpConfirm, Origin: origin.ID, Target: origin.Outcome.RunningRevision}
}

func TestV2ClosingConfirmUsesReservedCapacity(t *testing.T) {
	s, now, subject, ns, origin := closingFixtureV2(t)
	for range 7 {
		if _, err := s.admit(subject, ns, s.state.Generation, v2Request{Kind: OpValidate}, now); err != nil {
			t.Fatal(err)
		}
	}
	otherNS, err := s.namespace(subject, "local_services", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for range 55 {
		v2Cycle(t, s, subject, otherNS.ID, now)
	}
	if len(s.state.Namespaces[s.namespaceIndex(subject, ns)].Open) != 8 || s.state.OccupiedOrdinary != 63 || closingEntriesReservedV2(s.state) != 1 {
		t.Fatal("saturation fixture is incomplete")
	}
	s.budget = v2Budget{Bytes: s.used.Bytes + s.state.ReservedBytes + 1024, Inodes: s.used.Inodes + s.state.ReservedInodes + 1}
	before := clone(s.state)
	if _, err = s.admit(subject, otherNS.ID, s.state.Generation, v2Request{Kind: OpValidate}, now); !errors.Is(err, errV2Limited) {
		t.Fatalf("ordinary admission stole closing capacity: %v", err)
	}
	child, err := s.admit(subject, ns, s.state.Generation, closingRequestV2(origin), now)
	if err != nil {
		t.Fatal("reserved Confirm refused", err)
	}
	after := s.state
	if child.Sequence != before.HighWater+1 || child.ID == origin.ID || child.ClosingCredit == "" || after.ReservedBytes != before.ReservedBytes || after.ReservedInodes != before.ReservedInodes || after.OccupiedClosing != 1 || closingEntriesReservedV2(after) != 0 || len(after.Namespaces[s.namespaceIndex(subject, ns)].Open) != 8 || len(after.Namespaces[s.namespaceIndex(subject, ns)].ClosingOpen) != 1 {
		t.Fatal("closing reservation was not transferred exactly")
	}
	if _, err = s.begin(subject, child.ID, now); err != nil {
		t.Fatal(err)
	}
	child, err = s.finish(subject, child.ID, v2Outcome{Code: "applied", Generation: s.state.Generation}, []byte("fixture terminal; no engine"), now, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.state.ReservedBytes != before.ReservedBytes || len(s.state.ClosingCredits) != 1 {
		t.Fatal("child completion released archival credit")
	}
	if err = s.releasePin(subject, origin.ID, child.ID, now); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	err = s.releaseClosingCreditLocked(origin.ID, child.ClosingCredit, child.ID, now)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.state.ClosingCredits) != 0 || s.state.ReservedBytes != 7*v2OperationReserveBytes {
		t.Fatal("closing credit not released exactly once")
	}
	queried, err := s.lookup(subject, child.ID)
	if err != nil || !reflect.DeepEqual(queried, child) {
		t.Fatalf("retained closing receipt lost: %v", err)
	}
	page, cursor, err := s.list(subject, ns, 0, 100)
	if err != nil || cursor != s.state.HighWater || len(page) != 9 {
		t.Fatalf("mixed catalogue list: len=%d cursor=%d err=%v", len(page), cursor, err)
	}
}

func TestV2ClosingRejectsForeignOrInvalidTransfers(t *testing.T) {
	s, now, subject, ns, origin := closingFixtureV2(t)
	for _, tc := range []struct {
		name     string
		request  v2Request
		expected uint64
	}{
		{"origin", v2Request{Kind: OpConfirm, Origin: "v2.op.99.foreign", Target: origin.Outcome.RunningRevision}, s.state.Generation},
		{"target", v2Request{Kind: OpConfirm, Origin: origin.ID, Target: strings.Repeat("b", 64)}, s.state.Generation},
		{"generation", closingRequestV2(origin), s.state.Generation + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := clone(s.state)
			if _, err := s.admit(subject, ns, tc.expected, tc.request, now); err == nil {
				t.Fatal("invalid closing admission accepted")
			}
			if !reflect.DeepEqual(before, s.state) {
				t.Fatal("rejected request consumed credit")
			}
		})
	}
	foreign, err := s.changeSubject("", "other", strings.Repeat("c", 64), false, now)
	if err != nil {
		t.Fatal(err)
	}
	foreignNS, err := s.namespace(foreign.ID, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before := clone(s.state)
	if _, err = s.admit(foreign.ID, foreignNS.ID, s.state.Generation, closingRequestV2(origin), now); err == nil {
		t.Fatal("foreign subject spent credit")
	}
	if !reflect.DeepEqual(before, s.state) {
		t.Fatal("foreign request changed state")
	}
}

func TestV2ClosingNamespaceUsesReservedRegistryEntry(t *testing.T) {
	s, now, subject, ns, origin := closingFixtureV2(t)
	s.mu.Lock()
	st := clone(s.state)
	st.NamespaceSlots = uint64(len(st.Namespaces)) + closingRegistryReservedV2(st)
	err := s.publish(st)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.closeNamespace(subject, ns, now); err != nil {
		t.Fatal(err)
	}
	s.budget = v2Budget{Bytes: s.used.Bytes + s.state.ReservedBytes + 1024, Inodes: s.used.Inodes + s.state.ReservedInodes + 1}
	fallback, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal("reserved namespace refused", err)
	}
	if fallback.ID == ns || fallback.ClosingOrigin != origin.ID || uint64(len(s.state.Namespaces)) != s.state.NamespaceSlots || closingRegistryReservedV2(s.state) != 0 {
		t.Fatal("registry reserve not transferred")
	}
	if _, err = s.admit(subject, fallback.ID, s.state.Generation, v2Request{Kind: OpValidate}, now); err == nil {
		t.Fatal("closing-only namespace allowed ordinary mutation")
	}
	if _, err = s.admit(subject, fallback.ID, s.state.Generation, closingRequestV2(origin), now); err != nil {
		t.Fatal(err)
	}
}

func TestV2ClosingProfileRefusesInsufficientBudget(t *testing.T) {
	s, _, _, _ := v2Fixture(t, 64)
	s.budget = v2Budget{Bytes: 64 << 20, Inodes: 1000}
	before := clone(s.state)
	s.mu.Lock()
	err := s.enableClosingCreditsLocked()
	s.mu.Unlock()
	if !errors.Is(err, errV2Limited) || !reflect.DeepEqual(before, s.state) || s.state.RecoveryReserveVersion != 0 {
		t.Fatalf("insufficient profile enabled or mutated: %v", err)
	}
}

func TestV2ClosingPublicationFailurePreservesSelectedOwnership(t *testing.T) {
	s, now, subject, ns, origin := closingFixtureV2(t)
	area := s.root
	before := clone(s.state)
	s.hook = func(point string) error {
		if point == "before_select" {
			return errV2Unavailable
		}
		return nil
	}
	if _, err := s.admit(subject, ns, s.state.Generation, closingRequestV2(origin), now); err == nil || !s.blocked {
		t.Fatal("ambiguous publication did not fence")
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if !reflect.DeepEqual(before, reopened.state) || reopened.state.ClosingCredits[0].Child != "" {
		t.Fatal("unselected closing child consumed ownership")
	}
}

func TestV2ClosingConcurrentAdmissionAndReopen(t *testing.T) {
	s, now, subject, ns, origin := closingFixtureV2(t)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	var childID string
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			child, err := s.admit(subject, ns, 1, closingRequestV2(origin), now)
			if err == nil {
				accepted.Add(1)
				childID = child.ID
			} else if !errors.Is(err, errV2Invalid) {
				t.Errorf("unexpected concurrent outcome: %v", err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("closing credit spent %d times", accepted.Load())
	}
	before := clone(s.state)
	area := s.root
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	child, err := reopened.lookup(subject, childID)
	if err != nil || child.State != "accepted" || !reflect.DeepEqual(before, reopened.state) {
		t.Fatalf("accepted closing work not preserved: %v", err)
	}
}

func TestV2ClosingIndexRefusesWrongSemanticPrefix(t *testing.T) {
	s, now, subject, ns, origin := closingFixtureV2(t)
	if _, err := s.admit(subject, ns, 1, closingRequestV2(origin), now); err != nil {
		t.Fatal(err)
	}
	var root v2ClosingIndexNode
	if err := s.readObject(s.state.ClosingIndexRoot, &root); err != nil {
		t.Fatal(err)
	}
	root.Children[1], root.Children[0] = root.Children[0], ""
	hash, err := s.object(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.closingIndexVisit(hash, 0, func(v2Operation) error { return nil }); !errors.Is(err, errV2Unavailable) {
		t.Fatalf("wrong-prefix leaf accepted: %v", err)
	}
}

func TestV2ClosingActualPriorReaderRefusal(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("supply the actual prior-source binary with -reclaim-old-reader; skip is not compatibility evidence")
	}
	for _, enabled := range []bool{false, true} {
		s, area, _, _ := v2Fixture(t, 64)
		if enabled {
			s.mu.Lock()
			err := s.enableClosingCreditsLocked()
			s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
		}
		for range 130 {
			if err := s.publish(clone(s.state)); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.close(); err != nil {
			t.Fatal(err)
		}
		before := journalFiles(t, area.Name())
		command := exec.Command(*reclaimOldReader, "-test.run=^TestReclaimPriorReader$", "-prior-reclaim-area="+area.Name())
		output, err := command.CombinedOutput()
		want := "OLD_READER_ACCEPTED"
		if enabled {
			want = "OLD_READER_REJECTED"
		}
		if err != nil || !strings.Contains(string(output), want) || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
			t.Fatalf("old-reader test enabled=%t: %v %s", enabled, err, output)
		}
	}
}

func TestV2ClosingAcceptedCleanupKeepsOwnAllowance(t *testing.T) {
	for _, closeNamespace := range []bool{false, true} {
		t.Run(map[bool]string{false: "expire", true: "close"}[closeNamespace], func(t *testing.T) {
			s, now, subject, ns, origin := closingFixtureV2(t)
			child, err := s.admit(subject, ns, 1, closingRequestV2(origin), now)
			if err != nil {
				t.Fatal(err)
			}
			s.budget = v2Budget{Bytes: s.used.Bytes + s.state.ReservedBytes + 1, Inodes: s.used.Inodes + s.state.ReservedInodes + 1}
			if closeNamespace {
				err = s.closeNamespace(subject, ns, now)
			} else {
				err = s.expire(*origin.Outcome.ConfirmationDeadline)
			}
			if err != nil {
				t.Fatal("closing cleanup refused its reserved publication capacity", err)
			}
			queried, err := s.lookup(subject, child.ID)
			if err != nil || queried.State != "final" || queried.Pinned || len(s.state.ClosingCredits) != 1 || s.state.ReservedBytes != v2OperationReserveBytes+v2ClosingReserveBytes || s.allowance != (v2Budget{}) {
				t.Fatalf("cleanup lost ownership or leaked allowance: %v", err)
			}
		})
	}
}
