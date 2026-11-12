//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func reclaimOrphanV2(t *testing.T, s *v2Store, label string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, err := s.indexPut("", 0, 1, checkpointDigest([]byte(label)))
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestV2ReclaimLiveCataloguePreservesReplay(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var first, last v2Operation
	for i := 0; i < 40; i++ {
		op := v2Cycle(t, s, subject, ns.ID, now)
		if i == 0 {
			first = op
		}
		last = op
	}
	before := clone(s.state)
	usage := v2ActualUsage(t, area)
	report, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || !report.Complete || report.Removed == 0 || report.Retained == 0 {
		t.Fatal(report, err)
	}
	if !reflect.DeepEqual(before, s.state) {
		t.Fatal("selected state changed")
	}
	after := v2ActualUsage(t, area)
	if usage.Bytes-after.Bytes != report.RemovedBytes || usage.Inodes-after.Inodes != report.Removed || after != s.used {
		t.Fatal("named accounting mismatch", usage, after, report, s.used)
	}
	for _, op := range []v2Operation{first, last} {
		got, e := s.lookup(subject, op.ID)
		if e != nil || !reflect.DeepEqual(got, op) {
			t.Fatal("replay changed", e)
		}
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if reopened.reclaim != nil || reopened.state.ReclamationVersion != 1 {
		t.Fatal("reopen reconstructed authority")
	}
	if err = reopened.enableIndexReclamation(); err != nil || len(reopened.reclaim.pages) != 0 {
		t.Fatal("reopen adopted files", err)
	}
	for _, op := range []v2Operation{first, last} {
		got, e := reopened.lookup(subject, op.ID)
		if e != nil || !reflect.DeepEqual(got, op) {
			t.Fatal(e)
		}
	}
	t.Logf("named pages removed=%d bytes=%d retained=%d lock=%s (not freed blocks)", report.Removed, report.RemovedBytes, report.Retained, report.LockDuration)
}

func TestV2ReclaimRequiresNewExclusiveProvenance(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	old := reclaimOrphanV2(t, s, "historical")
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	if again := reclaimOrphanV2(t, s, "historical"); again != old || len(s.reclaim.pages) != 0 {
		t.Fatal("dedup adopted historical file")
	}
	protected := reclaimOrphanV2(t, s, "protected")
	name, _ := v2ObjectName(protected)
	data, err := checkpointRead(area, name, v2ObjectLimit)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, err = s.object(json.RawMessage(data))
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.reclaim.pages[protected]; ok {
		t.Fatal("generic protected use retained deletion authority")
	}
	dedup := reclaimOrphanV2(t, s, "dedup-held")
	if again := reclaimOrphanV2(t, s, "dedup-held"); again != dedup || s.reclaim.pages[dedup] != nil {
		t.Fatal("dedup preserved deletion authority")
	}
	good := reclaimOrphanV2(t, s, "eligible")
	report, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || report.Removed != 0 || !report.AuthorityRevoked {
		t.Fatal(report, err)
	}
	for _, h := range []string{old, protected, dedup, good} {
		n, _ := v2ObjectName(h)
		if _, e := area.Stat(n); e != nil {
			t.Fatal("held file deleted", e)
		}
	}
}

func TestV2ReclaimRejectsReplacementAndForeignFiles(t *testing.T) {
	for _, kind := range []string{"same-bytes", "symlink", "hardlink", "mode", "missing", "lock", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			s, area, _, _ := v2Fixture(t, 64)
			if err := s.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
			hash := reclaimOrphanV2(t, s, "candidate")
			name, _ := v2ObjectName(hash)
			data, err := checkpointRead(area, name, v2ObjectLimit)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "same-bytes", "symlink", "missing":
				// Retain the old inode so a filesystem cannot reuse its identity.
				old, e := area.Open(name)
				if e != nil {
					t.Fatal(e)
				}
				defer old.Close()
				if e = area.Remove(name); e != nil {
					t.Fatal(e)
				}
				if kind == "same-bytes" {
					f, e := area.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if e != nil {
						t.Fatal(e)
					}
					if _, e = f.Write(data); e != nil {
						t.Fatal(e)
					}
					if e = f.Close(); e != nil {
						t.Fatal(e)
					}
				}
				if kind == "symlink" {
					if e = area.Symlink("selected.json", name); e != nil {
						t.Fatal(e)
					}
				}
			case "hardlink":
				if e := area.Link(name, "selection.pending"); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := area.Chmod(name, 0640); e != nil {
					t.Fatal(e)
				}
			case "lock":
				if e := area.Remove("checkpoint.lock"); e != nil {
					t.Fatal(e)
				}
				f, e := area.OpenFile("checkpoint.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
			case "unknown":
				f, e := area.OpenFile("foreign", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					t.Fatal(e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
			}
			before := journalFiles(t, area.Name())
			r, e := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
			if e == nil || r.Complete || r.Removed != 0 || !s.blocked || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("foreign scope was modified", r, e)
			}
		})
	}
}

func TestV2ReclaimMarkerSurvivesBoot(t *testing.T) {
	c, area, _, _ := bootFixtureV2(t)
	if err := c.store.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	before := clone(c.store.state.Configuration.Candidate)
	id := v2BootID(testBootIDV2)
	c.options.BootID = &id
	c.store.mu.Lock()
	err := c.bootStartupLocked(context.Background(), id)
	c.store.mu.Unlock()
	if err != nil || c.store.state.ReclamationVersion != 1 {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, c.store.state.Configuration.Candidate) {
		t.Fatal("boot changed candidate")
	}
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	r, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !r.Complete {
		t.Fatal(r, err)
	}
	opened, err := openV2(area, c.store.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	if opened.state.ReclamationVersion != 1 || opened.reclaim != nil {
		t.Fatal("boot reopen changed marker/authority")
	}
}

func TestV2ReclaimDeletedOpenAccounting(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	hash := reclaimOrphanV2(t, s, "open")
	name, _ := v2ObjectName(hash)
	f, err := area.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || r.Removed != 1 {
		t.Fatal(r, err)
	}
	after, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st, ok := after.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 0 || after.Size() != before.Size() {
		t.Fatal("open inode not retained")
	}
	allocatedBefore, _ := v2Allocated(before)
	allocatedAfter, _ := v2Allocated(after)
	if allocatedBefore != allocatedAfter {
		t.Fatal("unlink unexpectedly claimed inode allocation")
	}
	if got := v2ActualUsage(t, area); got != s.used {
		t.Fatal("named usage wrong", got, s.used)
	}
}

func TestV2ReclaimBudgetCancellationAndCapacityDoNotBlockWriter(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	reclaimOrphanV2(t, s, "eligible")
	before := journalFiles(t, area.Name())
	b := reachabilityBudgetV2()
	b.Objects = 1
	if _, err := s.reclaimIndexPages(context.Background(), b); !errors.Is(err, errV2InspectionBudget) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.reclaimIndexPages(ctx, reachabilityBudgetV2()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.blocked || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
		t.Fatal("pre-sweep refusal changed store")
	}
	for i := len(s.reclaim.pages); i < v2ReclaimPageLimit; i++ {
		reclaimOrphanV2(t, s, fmt.Sprint(i))
	}
	held := reclaimOrphanV2(t, s, "over-cap")
	if len(s.reclaim.pages) != v2ReclaimPageLimit || s.reclaim.pages[held] != nil {
		t.Fatal("ledger cap bypass")
	}
	if _, err := s.namespace(subject, "firewall", now, time.Hour); err != nil {
		t.Fatal("full ledger blocked operation", err)
	}
}

func TestV2ReclaimMarkerStickyAndDefaultBytes(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	legacy, _ := json.Marshal(s.state)
	if strings.Contains(string(legacy), "reclamation_version") {
		t.Fatal("default wire changed")
	}
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	withMarker, _ := json.Marshal(s.state)
	var old map[string]json.RawMessage
	if json.Unmarshal(withMarker, &old) != nil || string(old["reclamation_version"]) != "1" {
		t.Fatal("marker absent")
	}
	for _, v := range []uint8{0, 2, 255} {
		st := clone(s.state)
		st.ReclamationVersion = v
		before := journalFiles(t, area.Name())
		s.mu.Lock()
		err := s.publish(st)
		s.mu.Unlock()
		if err == nil || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
			t.Fatal("invalid marker publication", v, err)
		}
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	r, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if r.state.ReclamationVersion != 1 || r.reclaim != nil {
		t.Fatal("marker/provenance mismatch")
	}
}

func TestV2ReclaimFailureAfterUnlinkReopensConservatively(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	reclaimOrphanV2(t, s, "one")
	reclaimOrphanV2(t, s, "two")
	before := clone(s.state)
	s.hook = func(p string) error {
		if p == "after_reclaim_unlink" {
			return errors.New("interrupted")
		}
		return nil
	}
	report, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if !errors.Is(err, errV2Uncertain) || report.Complete || !s.blocked || !reflect.DeepEqual(before, s.state) {
		t.Fatal(report, err)
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	r, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	files := journalFiles(t, area.Name())
	if err = r.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	report, err = r.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || !report.Complete || report.Removed != 0 || !reflect.DeepEqual(files, journalFiles(t, area.Name())) {
		t.Fatal("restart resumed or adopted", report, err)
	}
}

func TestV2ReclaimSerializesWriter(t *testing.T) {
	s, _, now, subject := v2Fixture(t, 64)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	reclaimOrphanV2(t, s, "one")
	entered, release := make(chan struct{}), make(chan struct{})
	s.hook = func(p string) error {
		if p == "before_reclaim_unlink" {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { _, e := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2()); done <- e }()
	<-entered
	var wg sync.WaitGroup
	wg.Add(1)
	write := make(chan error, 1)
	go func() { defer wg.Done(); _, e := s.namespace(subject, "firewall", now, time.Hour); write <- e }()
	select {
	case e := <-write:
		t.Fatal("writer crossed locked sweep", e)
	default:
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	wg.Wait()
	if e := <-write; e != nil {
		t.Fatal(e)
	}
}

func TestV2ReclaimOptInPressureAndLogicalBudget(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	before := journalFiles(t, area.Name())
	s.spaceProbe = func(*os.File) (storageSpace, error) { return storageSpace{BlockSize: 4096}, nil }
	if err := s.enableIndexReclamation(); !errors.Is(err, errV2Limited) || s.blocked || s.reclaim != nil || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
		t.Fatal("pressure admitted marker or blocked writer", err)
	}
	s.spaceProbe = nil
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	reclaimOrphanV2(t, s, "budget")
	s.budget = s.used
	r, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || r.Removed != 1 || !r.Complete {
		t.Fatal("logical exhaustion prevented allocation-free sweep", r, err)
	}
}

func TestV2ReclaimMigrationPreservesOriginals(t *testing.T) {
	fw, _ := v2LegacyFixture(t, "firewall", 9)
	ls, _ := v2LegacyFixture(t, "local_services", 27)
	fwBefore, lsBefore := journalFiles(t, fw.Name()), journalFiles(t, ls.Name())
	fwi, err := inspectLegacyV2(fw, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	lsi, err := inspectLegacyV2(ls, "local_services", nil)
	if err != nil {
		t.Fatal(err)
	}
	subject := v2Subject{ID: "explicit-incarnation", Login: "alice", CredentialRevision: checkpointDigest([]byte("credential revision"))}
	bindings := []v2LegacyBinding{{Source: fwi.Source, Actor: "alice", Subject: subject.ID, ReceiptIndex: fwi.ReceiptIndex}, {Source: lsi.Source, Actor: "alice", Subject: subject.ID, ReceiptIndex: lsi.ReceiptIndex}}
	area, _ := checkpointFixtureArea(t)
	s, err := prepareMigrationV2(area, fw, ls, []v2Subject{subject}, bindings, v2Budget{Bytes: 2 << 30, Inodes: 300000}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if s.state.ReclamationVersion != 0 {
		t.Fatal("migration implicitly opted in")
	}
	if err = s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	reclaimOrphanV2(t, s, "migrated-orphan")
	r, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || r.Removed != 1 {
		t.Fatal(r, err)
	}
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	opened, err := openV2(area, s.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.close()
	for _, domain := range []string{"firewall", "local_services"} {
		_, original, e := opened.legacyReplay(subject.ID, domain, "alice", "retained-key", checkpointDigest([]byte("request")))
		if e != nil || original != 3 {
			t.Fatal("legacy receipt changed", domain, e)
		}
	}
	if !reflect.DeepEqual(fwBefore, journalFiles(t, fw.Name())) || !reflect.DeepEqual(lsBefore, journalFiles(t, ls.Name())) {
		t.Fatal("legacy sources modified")
	}
}

func TestV2ReclaimCombinedLocalCandidateBootAndReplay(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, pending := range []bool{false, true} {
			t.Run(fmt.Sprintf("enabled-%t/pending-%t", enabled, pending), func(t *testing.T) {
				c, area, engines, p := bootFixtureV2(t)
				c.options.LocalPolicy = localFaultPolicyV2{}
				if enabled {
					if err := c.store.enableIndexReclamation(); err != nil {
						t.Fatal(err)
					}
				}
				config := localSample(t, 18443)
				op, staged, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
				if err != nil {
					t.Fatal(err)
				}
				candidate := clone(c.store.state.Configuration.LocalServices.Candidate)
				reclaimOrphanV2(t, c.store, "combined-held-or-eligible")
				id := v2BootID(testBootIDV2)
				c.options.BootID = &id
				if pending {
					c.options.Hook = func(point string) error {
						if point == "after_boot_intent" {
							return ErrInterrupted
						}
						return nil
					}
				}
				c.store.mu.Lock()
				err = c.bootStartupLocked(context.Background(), id)
				c.store.mu.Unlock()
				if pending && !errors.Is(err, ErrInterrupted) || !pending && err != nil {
					t.Fatal(err)
				}
				wantMarker := uint8(0)
				if enabled {
					wantMarker = 1
				}
				if c.store.state.ReclamationVersion != wantMarker || !hasFeatureV2(c.store.state, v2BootFeature) || !hasFeatureV2(c.store.state, v2LocalFeature) || !reflect.DeepEqual(candidate, c.store.state.Configuration.LocalServices.Candidate) {
					t.Fatal("combined marker/features/candidate changed")
				}
				before := clone(c.store.state)
				report, err := c.store.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
				if enabled && !pending {
					if err != nil || !report.Complete || report.Removed == 0 {
						t.Fatal(report, err)
					}
				} else if err == nil || report.Removed != 0 {
					t.Fatal("disabled/pending maintenance admitted", report, err)
				}
				if !reflect.DeepEqual(before, c.store.state) {
					t.Fatal("maintenance changed state")
				}
				retained, err := c.store.lookup(p.Subject, op.ID)
				if err != nil || !reflect.DeepEqual(retained, staged.Operation) {
					t.Fatal("local replay changed", err)
				}
				c.close()
				if err = c.store.close(); err != nil {
					t.Fatal(err)
				}
				files := journalFiles(t, area.Name())
				for _, engine := range engines {
					engine.reset()
				}
				closure, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
				if err != nil || !closure.Complete || !reflect.DeepEqual(files, journalFiles(t, area.Name())) {
					t.Fatal("combined closure failed", closure, err)
				}
				for _, engine := range engines {
					if engine.applies.Load() != 0 {
						t.Fatal("inspection applied engine")
					}
				}
				reopened, err := openV2(area, c.store.budget)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.close()
				if reopened.state.ReclamationVersion != wantMarker || reopened.reclaim != nil || !reflect.DeepEqual(before, reopened.state) {
					t.Fatal("combined reopen changed state/authority")
				}
				retained, err = reopened.lookup(p.Subject, op.ID)
				if err != nil || !reflect.DeepEqual(retained, staged.Operation) {
					t.Fatal("cold local replay changed", err)
				}
			})
		}
	}
}

func TestV2ReclaimPromotedPagePreservesUnselectedDescendants(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	root, err := s.indexPut("", 2, 1, checkpointDigest([]byte("unselected operation")))
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var page v2Page
	if err = s.readObject(root, &page); err != nil {
		t.Fatal(err)
	}
	identities := make(map[string]os.FileInfo)
	for hash, info := range s.reclaim.pages {
		identities[hash] = info
	}
	if len(identities) != 3 {
		t.Fatal("fixture requires parent and two child pages")
	}
	before := clone(s.state)
	s.mu.Lock()
	_, err = s.object(page)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// A successful generic/protected use is sufficient; no publication follows.
	report, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || report.Removed != 0 || !reflect.DeepEqual(before, s.state) {
		t.Fatal("promoted parent lost descendants", report, err)
	}
	for hash, expected := range identities {
		name, _ := v2ObjectName(hash)
		actual, e := area.Lstat(name)
		if e != nil || !sameRecordFile(expected, actual) {
			t.Fatal("held closure changed", hash, e)
		}
	}
}

func TestV2ReclaimUnknownAndDeduplicatedParentsRevokeSession(t *testing.T) {
	type pageAlias v2Page
	for _, mode := range []string{"raw", "alias", "unknown", "invalid-raw", "dedup", "cap-raw", "cap-dedup", "missing-child"} {
		t.Run(mode, func(t *testing.T) {
			s, area, _, _ := v2Fixture(t, 64)
			if err := s.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "cap-") {
				for i := 0; i < v2ReclaimPageLimit-2; i++ {
					reclaimOrphanV2(t, s, fmt.Sprintf("filler-%d", i))
				}
			}
			s.mu.Lock()
			root, err := s.indexPut("", 2, 1, checkpointDigest([]byte("unselected operation")))
			s.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "cap-") && s.reclaim.pages[root] != nil {
				t.Fatal("root should lack provenance at cap")
			}
			var page v2Page
			if err = s.readObject(root, &page); err != nil {
				t.Fatal(err)
			}
			name, _ := v2ObjectName(root)
			data, err := checkpointRead(area, name, v2ObjectLimit)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing-child" {
				child, _ := v2ObjectName(page.Refs[0])
				if err = area.Remove(child); err != nil {
					t.Fatal(err)
				}
			}
			before := journalFiles(t, area.Name())
			s.mu.Lock()
			switch mode {
			case "raw", "cap-raw":
				_, err = s.object(json.RawMessage(data))
			case "alias":
				_, err = s.object(pageAlias(page))
			case "unknown":
				_, err = s.object(map[string]string{"protected_parent": root})
			case "invalid-raw":
				_, err = s.object(json.RawMessage(`{"unfinished":`))
			case "dedup", "cap-dedup":
				_, err = s.objectClass(page, true)
			case "missing-child":
				_, err = s.object(page)
			}
			s.mu.Unlock()
			if mode == "invalid-raw" {
				if err == nil {
					t.Fatal("invalid raw accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if len(s.reclaim.pages) != 0 {
				t.Fatal("partial parent-only revocation")
			}
			// Unknown successful writes may add a held object; record that result
			// before sweeping so the assertion concerns deletion authority only.
			if mode == "unknown" {
				before = journalFiles(t, area.Name())
			}
			r, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
			if err != nil || r.Removed != 0 || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("held closure modified", r, err)
			}
		})
	}
}

func TestV2ReclaimKnownPublicationFailureFencesAndLosesAuthority(t *testing.T) {
	for _, point := range []string{"objects_durable", "after_select"} {
		t.Run(point, func(t *testing.T) {
			s, area, now, subject := v2Fixture(t, 64)
			if err := s.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
			ns, err := s.namespace(subject, "firewall", now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			s.hook = func(p string) error {
				if p == point {
					return ErrInterrupted
				}
				return nil
			}
			if _, err = s.admit(subject, ns.ID, s.state.Generation, v2Request{Kind: OpValidate}, now); err == nil || !s.blocked || len(s.reclaim.pages) == 0 {
				t.Fatal("fixture did not fence newly indexed work", err)
			}
			before := journalFiles(t, area.Name())
			r, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
			if err == nil || r.Removed != 0 || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("failed publication permitted sweep", r, err)
			}
			if err = s.close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := openV2(area, s.budget)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.close()
			if reopened.reclaim != nil {
				t.Fatal("reopen restored uncertain authority")
			}
			if err = reopened.enableIndexReclamation(); err != nil {
				t.Fatal(err)
			}
			r, err = reopened.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
			if err != nil || r.Removed != 0 || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("reopen swept previously held pages", r, err)
			}
		})
	}
}

func TestV2ReclaimRevocationCannotAcquireLaterChild(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	if err := s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	child := v2Page{Format: v2Format, Level: 0}
	child.Refs[0] = checkpointDigest([]byte("later-child-operation"))
	_, childHash, err := v2Canonical(child)
	if err != nil {
		t.Fatal(err)
	}
	parent := v2Page{Format: v2Format, Level: 1}
	parent.Refs[0] = childHash
	// No tracked pages exist yet. Unknown-parent use still revokes future
	// tracking, so an unselected held reference cannot acquire a deletable child.
	s.mu.Lock()
	_, err = s.object(parent)
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !s.reclaim.revoked {
		t.Fatal("empty ledger did not revoke future authority")
	}
	if err = s.enableIndexReclamation(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	created, err := s.objectClass(child, true)
	s.mu.Unlock()
	if err != nil || created != childHash || len(s.reclaim.pages) != 0 {
		t.Fatal("authority reacquired after promotion", err)
	}
	if _, err = s.namespace(subject, "firewall", now, time.Hour); err != nil {
		t.Fatal("revocation blocked normal writer", err)
	}
	before := journalFiles(t, area.Name())
	r, err := s.reclaimIndexPages(context.Background(), reachabilityBudgetV2())
	if err != nil || !r.AuthorityRevoked || r.Removed != 0 || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
		t.Fatal(r, err)
	}
}
