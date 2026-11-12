//go:build linux

package configpoc

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

func v2Fixture(t *testing.T, slots uint64) (*v2Store, *os.Root, time.Time, string) {
	t.Helper()
	area, _ := checkpointFixtureArea(t)
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	subject, err := v2ID("subject", 1)
	if err != nil {
		t.Fatal(err)
	}
	lineage, err := v2ID("lineage", 1)
	if err != nil {
		t.Fatal(err)
	}
	state := v2State{Format: v2Format, Lineage: lineage, Generation: 1, LiveSlots: slots, Clock: now, Subjects: []v2Subject{{ID: subject, Login: "admin", CredentialRevision: checkpointDigest([]byte("credential revision"))}}, Namespaces: []v2Namespace{}}
	store, err := createV2(area, v2Budget{Bytes: 2 << 30, Inodes: 300000}, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	return store, area, now, subject
}

func v2Cycle(t *testing.T, s *v2Store, subject, ns string, now time.Time) v2Operation {
	t.Helper()
	op, err := s.admit(subject, ns, s.state.Generation, v2Request{Kind: OpValidate}, now)
	if err != nil {
		t.Fatal("admit", err)
	}
	if op.State != "accepted" {
		t.Fatal("admission effect")
	}
	if _, err = s.begin(subject, op.ID, now); err != nil {
		t.Fatal("begin", err)
	}
	final, err := s.finish(subject, op.ID, v2Outcome{Code: "applied", Generation: s.state.Generation}, []byte("verified internal catalogue fixture; no engine effects"), now, false)
	if err != nil {
		t.Fatal("finish", err)
	}
	return final
}

func TestV2DurableCatalogue5000Lifecycles(t *testing.T) {
	if os.Getenv("ANDEIVA_CONFIG_V2_ENDURANCE") != "1" {
		t.Skip("set ANDEIVA_CONFIG_V2_ENDURANCE=1 for the dedicated durable 5000-operation qualification")
	}
	s, area, now, subject := v2Fixture(t, v2MaximumOperations)
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var first, last v2Operation
	for i := 0; i < 5000; i++ {
		op := v2Cycle(t, s, subject, ns.ID, now)
		if i == 0 {
			first = op
		}
		last = op
		if i%1000 == 999 {
			if err = s.close(); err != nil {
				t.Fatal(err)
			}
			s, err = openV2(area, s.budget)
			if err != nil {
				t.Fatal("cold reopen", i, err)
			}
			defer s.close()
			got, e := s.lookup(subject, first.ID)
			if e != nil || !reflect.DeepEqual(got, first) {
				t.Fatal("cold exact lookup", i, e)
			}
		}
	}
	got, err := s.lookup(subject, last.ID)
	if err != nil || !reflect.DeepEqual(got, last) {
		t.Fatal(err)
	}
	if s.state.ReservedBytes != 0 || s.state.ReservedInodes != 0 || s.state.HighWater != 5000 || s.state.Generation != 1 {
		t.Fatal("lifecycle/state accounting")
	}
	t.Logf("5000 catalogue lifecycles, immutable files=%d bytes=%d; no engines or coordinator cycles", s.used.Inodes, s.used.Bytes)
}

func TestV2LiveSlotReuseBeyondCapacity(t *testing.T) {
	s, _, now, subject := v2Fixture(t, 64)
	var first v2Operation
	for batch := 0; batch < 5; batch++ {
		ns, err := s.namespace(subject, "firewall", now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ops := make([]v2Operation, 64)
		for i := range ops {
			ops[i] = v2Cycle(t, s, subject, ns.ID, now)
			if batch == 0 && i == 0 {
				first = ops[i]
			}
		}
		if _, err = s.admit(subject, ns.ID, 1, v2Request{Kind: OpSave}, now); !errors.Is(err, errV2Limited) {
			t.Fatal("overwrote retained slot", err)
		}
		now = now.Add(31 * 24 * time.Hour)
		for _, op := range ops {
			if err = s.retire(subject, op.ID, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	if s.state.HighWater != 320 {
		t.Fatal("monotonic issuance")
	}
	if _, err := s.lookup(subject, first.ID); !errors.Is(err, errV2NotFound) {
		t.Fatal("old overwritten handle classified as owned", err)
	}
	if _, err := s.begin(subject, first.ID, now); !errors.Is(err, errV2NotFound) {
		t.Fatal("retired handle executed", err)
	}
}

func TestV2OwnershipExpiryPinsAndSubjects(t *testing.T) {
	s, _, now, subject := v2Fixture(t, 64)
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil || again.ID != ns.ID {
		t.Fatal("lost namespace response duplicated")
	}
	op, err := s.admit(subject, ns.ID, 1, v2Request{Kind: OpSave}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.lookup("foreign", op.ID); !errors.Is(err, errV2NotFound) {
		t.Fatal(err)
	}
	if _, err = s.begin(subject, op.ID+"x", now); !errors.Is(err, errV2NotFound) {
		t.Fatal(err)
	}
	if _, err = s.begin(subject, op.ID, now); err != nil {
		t.Fatal(err)
	}
	final, err := s.finish(subject, op.ID, v2Outcome{Code: "applied_pending_confirmation", Generation: 1}, []byte("confirmation origin"), now, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.closeNamespace(subject, ns.ID, now); err != nil {
		t.Fatal(err)
	}
	if s.state.ReservedBytes != v2OperationReserveBytes {
		t.Fatal("close stole rollback reserve")
	}
	if err = s.retire(subject, op.ID, now.Add(31*24*time.Hour)); !errors.Is(err, errV2Invalid) {
		t.Fatal("retired pin", err)
	}
	got, err := s.lookup(subject, op.ID)
	if err != nil || !reflect.DeepEqual(final, got) {
		t.Fatal("lookup modified outcome", err)
	}
	changed, err := s.changeSubject(subject, "renamed", checkpointDigest([]byte("rotated")), false, now)
	if err != nil || changed.ID != subject {
		t.Fatal(err)
	}
	if _, err = s.changeSubject(subject, "renamed", changed.CredentialRevision, true, now); err != nil {
		t.Fatal(err)
	}
	newSubject, err := s.changeSubject("", "renamed", changed.CredentialRevision, false, now)
	if err != nil || newSubject.ID == subject {
		t.Fatal(err)
	}
	if _, err = s.lookup(newSubject.ID, op.ID); !errors.Is(err, errV2NotFound) {
		t.Fatal("recreated account inherited receipt", err)
	}
}

func TestV2ConcurrencyAndAdmissionReservation(t *testing.T) {
	s, _, now, subject := v2Fixture(t, 64)
	ns, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.admit(subject, ns.ID, 1, v2Request{Kind: OpSave}, now)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				accepted++
			} else if !errors.Is(err, errV2Limited) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted != 8 || s.state.ReservedBytes != 8*v2OperationReserveBytes {
		t.Fatal("open-operation reservation", accepted)
	}
	if err = s.expire(now.Add(-time.Second)); !errors.Is(err, errV2Unavailable) {
		t.Fatal("clock rollback", err)
	}
	if err = s.expire(now.Add(901 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if s.state.ReservedBytes != 0 {
		t.Fatal("expiry did not release accepted work")
	}
	for _, ns := range s.state.Namespaces {
		if len(ns.Open) != 0 {
			t.Fatal("expired operation pinned")
		}
	}
}

func TestV2RegistryLiveLimitsAreNotLifetimeLimits(t *testing.T) {
	s, _, now, subject := v2Fixture(t, 64)
	st := clone(s.state)
	st.NamespaceSlots = 4
	st.SubjectSlots = 2
	if err := s.publish(st); err != nil {
		t.Fatal(err)
	}
	var firstNamespace, firstSubject string
	for i := 0; i < 20; i++ {
		ns, err := s.namespace(subject, "firewall", now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		op := v2Cycle(t, s, subject, ns.ID, now)
		if i == 0 {
			firstNamespace = ns.ID
		}
		if err = s.closeNamespace(subject, ns.ID, now); err != nil {
			t.Fatal(err)
		}
		if err = s.retireNamespace(subject, ns.ID, now); !errors.Is(err, errV2Invalid) {
			t.Fatal("early namespace retirement", err)
		}
		now = now.Add(31 * 24 * time.Hour)
		if err = s.retireNamespace(subject, ns.ID, now); !errors.Is(err, errV2Limited) {
			t.Fatal("retained operation lost ownership", err)
		}
		if err = s.retire(subject, op.ID, now); err != nil {
			t.Fatal(err)
		}
		if err = s.retireNamespace(subject, ns.ID, now); err != nil {
			t.Fatal(err)
		}
		if _, err = s.admit(subject, ns.ID, 1, v2Request{Kind: OpSave}, now); !errors.Is(err, errV2NotFound) {
			t.Fatal("retired namespace recreated on miss", err)
		}
		created, err := s.changeSubject("", "ephemeral", checkpointDigest([]byte("revision")), false, now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstSubject = created.ID
		}
		if _, err = s.changeSubject(created.ID, "ephemeral", created.CredentialRevision, true, now); err != nil {
			t.Fatal(err)
		}
		if err = s.retireSubjectRecord(created.ID, now); err != nil {
			t.Fatal(err)
		}
	}
	if s.state.NamespaceSequence != 20 || s.state.SubjectSequence != 21 || len(s.state.Namespaces) != 0 || len(s.state.Subjects) != 1 {
		t.Fatal("registry issuance did not survive retirement")
	}
	if _, err := s.namespace(firstSubject, "firewall", now, time.Hour); err == nil {
		t.Fatal("retired subject revived")
	}
	if _, err := s.admit(subject, firstNamespace, 1, v2Request{Kind: OpSave}, now); !errors.Is(err, errV2NotFound) {
		t.Fatal("old namespace revived", err)
	}
}

func TestV2SubjectRetirementClosesNamespacesWithoutLosingPending(t *testing.T) {
	s, _, now, subject := v2Fixture(t, 64)
	firewall, err := s.namespace(subject, "firewall", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	local, err := s.namespace(subject, "local_services", now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := s.admit(subject, firewall.ID, 1, v2Request{Kind: OpValidate}, now)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := s.admit(subject, local.ID, 1, v2Request{Kind: OpValidate}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.begin(subject, pending.ID, now); err != nil {
		t.Fatal(err)
	}
	before := s.state.ReservedBytes
	if _, err = s.changeSubject(subject, "admin", s.state.Subjects[0].CredentialRevision, true, now); err != nil {
		t.Fatal(err)
	}
	for _, ns := range s.state.Namespaces {
		if !ns.Closed {
			t.Fatal("retired subject left an uncloseable namespace")
		}
	}
	if s.state.ReservedBytes != before {
		t.Fatal("retirement stole accepted/pending reserve")
	}
	got, err := s.lookupRetained(subject, accepted.ID)
	if err != nil || got.State != "accepted" || got.Outcome != nil {
		t.Fatal("retirement manufactured terminal outcome", err)
	}
	got, err = s.lookupRetained(subject, pending.ID)
	if err != nil || got.State != "pending" || !got.Pinned {
		t.Fatal("pending recovery lost", err)
	}
	if err = s.expire(now.Add(901 * time.Second)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * 24 * time.Hour)
	if err = s.retire(subject, accepted.ID, now); err != nil {
		t.Fatal("retired subject prevented eligible operation retirement", err)
	}
	if err = s.retireNamespace(subject, firewall.ID, now); err != nil {
		t.Fatal("eligible old namespace cannot retire", err)
	}
	if err = s.retireNamespace(subject, local.ID, now); err == nil {
		t.Fatal("pending namespace retired")
	}
	if err = s.retireSubjectRecord(subject, now); err == nil {
		t.Fatal("pending subject registry tombstone lost")
	}
	if s.state.ReservedBytes != v2OperationReserveBytes {
		t.Fatal("pending rollback reserve changed")
	}
}

func BenchmarkV2CatalogueLifecycle(b *testing.B) {
	areaPath := b.TempDir()
	if err := os.Chmod(areaPath, 0700); err != nil {
		b.Fatal(err)
	}
	area, err := os.OpenRoot(areaPath)
	if err != nil {
		b.Fatal(err)
	}
	defer area.Close()
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	state := v2State{Format: v2Format, Lineage: "benchmark-lineage", Generation: 1, LiveSlots: v2MaximumOperations, Clock: now, Subjects: []v2Subject{{ID: "benchmark-subject", Login: "admin", CredentialRevision: checkpointDigest([]byte("revision"))}}, Namespaces: []v2Namespace{}}
	s, err := createV2(area, v2Budget{Bytes: 2 << 30, Inodes: 300000}, state)
	if err != nil {
		b.Fatal(err)
	}
	defer s.close()
	ns, err := s.namespace("benchmark-subject", "firewall", now, time.Hour)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		op, e := s.admit("benchmark-subject", ns.ID, 1, v2Request{Kind: OpSave}, now)
		if e != nil {
			b.Fatal(e)
		}
		if _, e = s.begin("benchmark-subject", op.ID, now); e != nil {
			b.Fatal(e)
		}
		if _, e = s.finish("benchmark-subject", op.ID, v2Outcome{Code: "applied", Generation: 1}, []byte(fmt.Sprint(i)), now, false); e != nil {
			b.Fatal(e)
		}
	}
}
