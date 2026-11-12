//go:build linux

package configpoc

import (
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

func v2LegacyFixture(t *testing.T, domain string, generation uint64) (*os.Root, durableState) {
	t.Helper()
	area, path := checkpointFixtureArea(t)
	store, err := openStore(path, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{}}
	if domain == "local_services" {
		config = localSample(t, 9443)
	}
	running, err := Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	startup := running
	if domain == "local_services" {
		startup, err = Canonical(localSample(t, 8443))
		if err != nil {
			t.Fatal(err)
		}
	}
	state := durableState{Snapshot: Snapshot{Generation: generation, Running: running, Startup: startup, LastGood: running, Revoked: []string{}}, Receipts: map[string]receipt{"alice:retained-key": {Fingerprint: checkpointDigest([]byte("request")), Generation: 3}}}
	if err = store.append(state, Audit{Sequence: 1, Actor: "alice", At: time.Now().UTC(), Operation: OpSave, Surface: API, Result: "success", RunningHash: running.Hash}, true, nil); err != nil {
		t.Fatal(err)
	}
	if err = store.lock.Close(); err != nil {
		t.Fatal(err)
	}
	return area, state
}

func TestV2MigrationPreservesSourcesSchemasHashesAndReplay(t *testing.T) {
	fw, fwState := v2LegacyFixture(t, "firewall", 9)
	ls, lsState := v2LegacyFixture(t, "local_services", 27)
	fwBefore := journalFiles(t, fw.Name())
	lsBefore := journalFiles(t, ls.Name())
	fwImage, err := inspectLegacyV2(fw, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	lsImage, err := inspectLegacyV2(ls, "local_services", nil)
	if err != nil {
		t.Fatal(err)
	}
	subject := v2Subject{ID: "explicitly-verified-incarnation", Login: "alice", CredentialRevision: checkpointDigest([]byte("credential revision"))}
	bindings := []v2LegacyBinding{{Source: fwImage.Source, Actor: "alice", Subject: subject.ID, ReceiptIndex: fwImage.ReceiptIndex}, {Source: lsImage.Source, Actor: "alice", Subject: subject.ID, ReceiptIndex: lsImage.ReceiptIndex}}
	destination, _ := checkpointFixtureArea(t)
	store, err := prepareMigrationV2(destination, fw, ls, []v2Subject{subject}, bindings, v2Budget{Bytes: 2 << 30, Inodes: 300000}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if store.state.Generation != 1 || store.selection.Sequence != 1 || store.selection.Previous != "" || store.selection.Lineage == fwImage.Source || store.state.Operational {
		t.Fatal("migration claimed operational Running")
	}
	var migration v2Migration
	if err = store.readObject(store.state.Migration, &migration); err != nil {
		t.Fatal(err)
	}
	if migration.Firewall.Projection != 9 || migration.LocalServices.Projection != 27 || migration.Firewall.Snapshot.Running.Hash != fwState.Snapshot.Running.Hash || migration.LocalServices.Snapshot.Startup.Hash != lsState.Snapshot.Startup.Hash {
		t.Fatal("component lineage relabelled")
	}
	if migration.Startup.LocalServices.Revision == migration.Running.LocalServices.Revision {
		t.Fatal("Running copied over Startup")
	}
	for _, domain := range []string{"firewall", "local_services"} {
		current, original, e := store.legacyReplay(subject.ID, domain, "alice", "retained-key", checkpointDigest([]byte("request")))
		want := uint64(9)
		if domain == "local_services" {
			want = 27
		}
		if e != nil || original != 3 || current.Generation != want {
			t.Fatal("legacy replay mapping", domain, e)
		}
	}
	if _, _, err = store.legacyReplay("recreated-subject", "firewall", "alice", "retained-key", checkpointDigest([]byte("request"))); !errors.Is(err, errV2NotFound) {
		t.Fatal("guessed owner accepted", err)
	}
	if !reflect.DeepEqual(fwBefore, journalFiles(t, fw.Name())) || !reflect.DeepEqual(lsBefore, journalFiles(t, ls.Name())) {
		t.Fatal("source modified")
	}
	for _, source := range []*os.Root{fw, ls} {
		legacy, e := openStore(source.Name(), 2048)
		if e != nil {
			t.Fatal("old layout unreadable", e)
		}
		_ = legacy.lock.Close()
	}
}

func TestV2MigrationInterruptedBeforeInitialSelection(t *testing.T) {
	fw, _ := v2LegacyFixture(t, "firewall", 9)
	ls, _ := v2LegacyFixture(t, "local_services", 27)
	fwImage, err := inspectLegacyV2(fw, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	lsImage, err := inspectLegacyV2(ls, "local_services", nil)
	if err != nil {
		t.Fatal(err)
	}
	subject := v2Subject{ID: "verified-subject", Login: "alice", CredentialRevision: checkpointDigest([]byte("revision"))}
	bindings := []v2LegacyBinding{{Source: fwImage.Source, Actor: "alice", Subject: subject.ID, ReceiptIndex: fwImage.ReceiptIndex}, {Source: lsImage.Source, Actor: "alice", Subject: subject.ID, ReceiptIndex: lsImage.ReceiptIndex}}
	destination, _ := checkpointFixtureArea(t)
	budget := v2Budget{Bytes: 2 << 30, Inodes: 300000}
	store, err := prepareMigrationV2WithHook(destination, fw, ls, []v2Subject{subject}, bindings, budget, time.Now().UTC(), func(point string) error {
		if point == "before_select" {
			return ErrInterrupted
		}
		return nil
	})
	if err == nil {
		_ = store.close()
		t.Fatal("interruption ignored")
	}
	if _, err = destination.Stat("selected.json"); !os.IsNotExist(err) {
		t.Fatal("partial migration was selected", err)
	}
	if reopened, e := openV2(destination, budget); e == nil {
		_ = reopened.close()
		t.Fatal("unselected migration treated as usable")
	}
	for _, source := range []*os.Root{fw, ls} {
		legacy, e := openStore(source.Name(), 2048)
		if e != nil {
			t.Fatal("legacy recovery layout not reusable", e)
		}
		_ = legacy.lock.Close()
	}
	// A fresh preparation can select exactly sequence1 after the caller retains
	// the interrupted workspace for investigation; no cleanup is guessed.
	fresh, _ := checkpointFixtureArea(t)
	store, err = prepareMigrationV2(fresh, fw, ls, []v2Subject{subject}, bindings, budget, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if store.selection.Sequence != 1 {
		t.Fatal("initial storage sequence changed")
	}
	_ = store.close()
	reopened, err := openV2(fresh, budget)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if reopened.selection.Sequence != 1 || reopened.state.Generation != 1 || reopened.state.Operational {
		t.Fatal("cold prepared migration semantics")
	}
}

func TestV2MigrationRejectsClonedSourceIdentity(t *testing.T) {
	fw, _ := v2LegacyFixture(t, "firewall", 9)
	ls, _ := v2LegacyFixture(t, "local_services", 27)
	for _, name := range []string{stagingRegistration, stagingDirectory + "/" + stagingMarker} {
		data, err := fw.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = ls.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fwImage, err := inspectLegacyV2(fw, "firewall", nil)
	if err != nil {
		t.Fatal(err)
	}
	lsImage, err := inspectLegacyV2(ls, "local_services", nil)
	if err != nil {
		t.Fatal(err)
	}
	if fwImage.Source != lsImage.Source {
		t.Fatal("fixture identity not cloned")
	}
	subject := v2Subject{ID: "verified-subject", Login: "alice", CredentialRevision: checkpointDigest([]byte("revision"))}
	bindings := []v2LegacyBinding{{Source: fwImage.Source, Actor: "alice", Subject: subject.ID, ReceiptIndex: fwImage.ReceiptIndex}}
	destination, _ := checkpointFixtureArea(t)
	store, err := prepareMigrationV2(destination, fw, ls, []v2Subject{subject}, bindings, v2Budget{Bytes: 2 << 30, Inodes: 300000}, time.Now().UTC())
	if err == nil {
		_ = store.close()
		t.Fatal("duplicate source identity admitted")
	}
	dir, err := destination.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil || len(entries) != 0 {
		t.Fatal("refusal mutated destination", err)
	}
}

func TestV2MigrationRejectsUnresolvedAndAmbiguousWithoutWrites(t *testing.T) {
	fw, _ := v2LegacyFixture(t, "firewall", 9)
	ls, _ := v2LegacyFixture(t, "local_services", 27)
	destination, _ := checkpointFixtureArea(t)
	before := journalFiles(t, fw.Name())
	if store, err := prepareMigrationV2(destination, fw, ls, nil, nil, v2Budget{Bytes: 2 << 30, Inodes: 300000}, time.Now().UTC()); err == nil {
		_ = store.close()
		t.Fatal("ambiguous historical owner inferred")
	}
	entries, err := destination.ReadFile("selected.json")
	if err == nil {
		t.Fatal("selected before binding validation", entries)
	}
	if !reflect.DeepEqual(before, journalFiles(t, fw.Name())) {
		t.Fatal("refusal mutated source")
	}
	// Inspection rejects an interrupted staging record without recovering it.
	if err = fw.WriteFile(stagingDirectory+"/"+stagingPayload, []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = inspectLegacyV2(fw, "firewall", nil); err == nil {
		t.Fatal("unresolved owned staging accepted")
	}
	data, err := fw.ReadFile(stagingDirectory + "/" + stagingPayload)
	if err != nil || string(data) != "incomplete" {
		t.Fatal("inspection performed cleanup", err)
	}
}
