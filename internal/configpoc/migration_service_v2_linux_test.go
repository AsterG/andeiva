//go:build linux

package configpoc

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestMigrationServiceV2FingerprintsBindingsAndSourcePreservation(t *testing.T) {
	fw, _ := v2LegacyFixture(t, "firewall", 9)
	ls, _ := v2LegacyFixture(t, "local_services", 27)
	fBefore, lBefore := journalFiles(t, fw.Name()), journalFiles(t, ls.Name())
	f, err := InspectLegacyV2(fw, "firewall")
	if err != nil {
		t.Fatal(err)
	}
	l, err := InspectLegacyV2(ls, "local_services")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fBefore, journalFiles(t, fw.Name())) || !reflect.DeepEqual(lBefore, journalFiles(t, ls.Name())) {
		t.Fatal("inspection wrote source")
	}
	id, err := NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewSubjectIDV2()
	if err != nil || id == other {
		t.Fatal("subject IDs not independent")
	}
	subjects := []SubjectV2{{ID: id, Login: "alice", CredentialRevision: checkpointDigest([]byte("explicit credential revision"))}}
	bindings := []LegacyBindingV2{{Source: f.Source, Actor: "alice", Subject: id, ReceiptIndex: f.ReceiptIndex}, {Source: l.Source, Actor: "alice", Subject: id, ReceiptIndex: l.ReceiptIndex}}
	for _, problem := range []string{"stale_tip", "stale_sequence", "stale_receipts", "wrong_domain", "missing_binding", "wrong_owner"} {
		t.Run(problem, func(t *testing.T) {
			destination, _ := checkpointFixtureArea(t)
			expected := [2]LegacyFingerprintV2{f, l}
			mapping := clone(bindings)
			switch problem {
			case "stale_tip":
				expected[0].Tip = checkpointDigest([]byte("another tip"))
			case "stale_sequence":
				expected[1].Sequence++
			case "stale_receipts":
				expected[0].ReceiptIndex = checkpointDigest([]byte("another receipt index"))
			case "wrong_domain":
				expected[1].Domain = "firewall"
			case "missing_binding":
				mapping = nil
			case "wrong_owner":
				mapping[0].Subject = "not-issued"
			}
			err := PrepareMigrationV2(destination, fw, ls, expected, subjects, mapping, BudgetV2{Bytes: 2 << 30, Inodes: 300000}, time.Now().UTC())
			if err == nil {
				t.Fatal("invalid migration published")
			}
			if problem == "stale_tip" || problem == "stale_sequence" || problem == "stale_receipts" {
				if !errors.Is(err, ErrConflict) {
					t.Fatal("fingerprint mismatch not explicit", err)
				}
			}
			if len(journalFiles(t, destination.Name())) != 0 {
				t.Fatal("rejected migration mutated destination")
			}
		})
	}
	destination, _ := checkpointFixtureArea(t)
	if err := PrepareMigrationV2(destination, fw, ls, [2]LegacyFingerprintV2{f, l}, subjects, bindings, BudgetV2{Bytes: 2 << 30, Inodes: 300000}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	store, err := openV2(destination, v2Budget{Bytes: 2 << 30, Inodes: 300000})
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if store.state.Operational || store.state.Configuration != nil {
		t.Fatal("storage preparation claimed runtime activation")
	}
	if !reflect.DeepEqual(fBefore, journalFiles(t, fw.Name())) || !reflect.DeepEqual(lBefore, journalFiles(t, ls.Name())) {
		t.Fatal("migration wrote source")
	}
}
