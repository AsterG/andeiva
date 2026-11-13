//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func migrationProvenanceFixtureV3(t *testing.T, localOperation ...string) (*RoutedSelectionReaderV2, *os.Root, [2]LegacyFingerprintV2, Revision, time.Time) {
	t.Helper()
	area, _ := checkpointFixtureArea(t)
	var roots [3]*os.Root
	var pools [3]*recoveryreserve.PoolV2
	var profiles [3]recoveryreserve.ProfileV2
	for i, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
	}{{recoveryreserve.AdmissionV2, 4096}, {recoveryreserve.PlanV2, 16384}, {recoveryreserve.EmergencyV2, 8192}} {
		roots[i], _ = checkpointFixtureArea(t)
		var err error
		pools[i], err = recoveryreserve.PrepareV2(roots[i], 18, item.capacity, item.role)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pools[i].Close() })
		profiles[i], err = pools[i].Profile()
		if err != nil {
			t.Fatal(err)
		}
	}
	local, err := Canonical(Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{}, Services: []localpolicy.Service{}}})
	if err != nil {
		t.Fatal(err)
	}
	fw, err := Canonical(Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	var sources [2]*os.Root
	var expected [2]LegacyFingerprintV2
	at := time.Now().UTC()
	for i, domain := range []string{"firewall", "local_services"} {
		var path string
		sources[i], path = checkpointFixtureArea(t)
		store, e := openStore(path, 2048)
		if e != nil {
			t.Fatal(e)
		}
		rev := fw
		if i == 1 {
			rev = local
		}
		state := durableState{Snapshot: Snapshot{Generation: 1, Running: rev, Startup: rev, LastGood: rev, Revoked: []string{}}, Receipts: map[string]receipt{}}
		operation := "initialize"
		if i == 1 && len(localOperation) > 0 {
			operation = localOperation[0]
		}
		if e = store.append(state, Audit{Sequence: 1, At: at, Actor: "system", Surface: API, Operation: operation, Result: "ok", RunningHash: rev.Hash}, true, nil); e != nil {
			t.Fatal(e)
		}
		if e = store.lock.Close(); e != nil {
			t.Fatal(e)
		}
		expected[i], e = InspectLegacyV2(sources[i], domain)
		if e != nil {
			t.Fatal(e)
		}
	}
	subject, err := NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	budget := BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}
	if err = PrepareMigrationV2(area, sources[0], sources[1], expected, []SubjectV2{{ID: subject, Login: "fixture-admin", CredentialRevision: checkpointDigest([]byte("test-only-revision"))}}, nil, budget, at); err != nil {
		t.Fatal(err)
	}
	// This callback models source verification; these tests claim filesystem/G1
	// integrity only, never actual kernel, listener or installer qualification.
	if err = PrepareOfflineMigratedRoutedStoreV3(context.Background(), area, sources, budget, RuntimePoolsV2{Admission: pools[0], Plan: pools[1], Emergency: pools[2]}, expected, &offlineMigrationReadbackTestV3{}, at); err != nil {
		t.Fatal(err)
	}
	access := sharedTestAreaV2(t, area, "checkpoint.lock")
	readers := make([]*recoveryreserve.ReadOnlyPoolV2, 3)
	for i, pool := range pools {
		if err = pool.Close(); err != nil {
			t.Fatal(err)
		}
		a := sharedTestAreaV2(t, roots[i], "")
		readers[i], err = recoveryreserve.OpenReadOnlyV2(roots[i], a, profiles[i])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = readers[i].Close() })
	}
	identity := networkexecutor.OwnedNamespaceIdentity{UID: access.OwnerUID + 1, GID: access.ReaderGID, Host: 11, Namespace: 22, BootID: "12345678-1234-1234-1234-123456789abc", RunID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	reader, err := NewRoutedSelectionReaderV2(area, SelectionReaderOptionsV2{Access: access, Identity: identity, Admission: readers[0], Plan: readers[1], Emergency: readers[2], Budget: reachabilityBudgetV2()})
	if err != nil {
		t.Fatal(err)
	}
	return reader, area, expected, local, at
}

func TestMigrationProvenanceV3SelectedDetachedAndBounded(t *testing.T) {
	r, area, expected, local, at := migrationProvenanceFixtureV3(t)
	selected, err := os.ReadFile(filepath.Join(area.Name(), "selected.json"))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := r.MigrationProvenanceV3(context.Background())
	if err != nil || proof.Sources != expected || proof.LocalRevision.Hash != local.Hash || !proof.LocalInitializedAt.Equal(at) || proof.Selection.Sequence == 0 {
		t.Fatal(proof, err)
	}
	proof.LocalRevision.Config.LocalServices.Services = append(proof.LocalRevision.Config.LocalServices.Services, localpolicy.Service{ID: "caller-mutation"})
	repeated, err := r.MigrationProvenanceV3(context.Background())
	if err != nil || len(repeated.LocalRevision.Config.LocalServices.Services) != 0 {
		t.Fatal("returned alias changed selected configuration", err)
	}
	after, err := os.ReadFile(filepath.Join(area.Name(), "selected.json"))
	if err != nil || string(after) != string(selected) {
		t.Fatal("getter changed selected state", err)
	}
	r.options.Policy = SelectionActionAuthorityV2
	if _, err = r.MigrationProvenanceV3(context.Background()); err == nil {
		t.Fatal("action-only reader returned historical provenance")
	}
	r.options.Policy = SelectionFullHistoryV2
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.MigrationProvenanceV3(ctx); err == nil {
		t.Fatal("cancelled read succeeded")
	}
}

func TestMigrationProvenanceV3RejectsMissingAndCorruptSelection(t *testing.T) {
	r, _, _ := selectedReaderFixtureV2(t)
	if _, err := r.MigrationProvenanceV3(context.Background()); err == nil {
		t.Fatal("missing migration accepted")
	}
	r, area, _, _, _ := migrationProvenanceFixtureV3(t)
	view, err := r.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hash := view.store.state.Migration
	if err = view.graph.closeSelectedV2(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(area.Name(), "object-"+hash+".json"), []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err = r.MigrationProvenanceV3(context.Background()); err == nil {
		t.Fatal("corrupt selected migration accepted")
	}
}

func TestMigrationProvenanceV3DoesNotInventAnInitializationEvent(t *testing.T) {
	r, _, _, _, _ := migrationProvenanceFixtureV3(t, OpSave)
	if _, err := r.MigrationProvenanceV3(context.Background()); err == nil {
		t.Fatal("historical save event mislabeled as new domain creation")
	}
}

func TestWithLegacyFingerprintV3RetainsAndRechecksOriginalLock(t *testing.T) {
	area, path := checkpointFixtureArea(t)
	initial := Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []Rule{}}
	// Simulated engine only initializes this filesystem fixture; no kernel claim.
	core, err := Open(path, []Engine{NewSimEngine("fixture-only")}, Options{Initial: &initial})
	if err != nil {
		t.Fatal(err)
	}
	if err = core.Close(); err != nil {
		t.Fatal(err)
	}
	expected, err := InspectLegacyV2(area, "firewall")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err = WithLegacyFingerprintV3(context.Background(), area, "firewall", func(ctx context.Context, actual LegacyFingerprintV2) error {
		called = true
		if actual != expected {
			return errors.New("wrong source fingerprint")
		}
		if nested, e := lockLegacyV2(area); e == nil {
			nested.Close()
			return errors.New("source lock released during visitor")
		}
		return nil
	}); err != nil || !called {
		t.Fatal(err, called)
	}
	if _, err = InspectLegacyV2(area, "firewall"); err != nil {
		t.Fatal("lock not closed", err)
	}
	sentinel := errors.New("visitor refused")
	if err = WithLegacyFingerprintV3(context.Background(), area, "firewall", func(context.Context, LegacyFingerprintV2) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("visitor error lost", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err = WithLegacyFingerprintV3(ctx, area, "firewall", func(context.Context, LegacyFingerprintV2) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	// A noncooperating writer can ignore flock. Reinspection must detect its
	// corruption and preserve it, rather than repairing evidence silently.
	record := filepath.Join(path, "00000001.json")
	if err = WithLegacyFingerprintV3(context.Background(), area, "firewall", func(context.Context, LegacyFingerprintV2) error { return os.WriteFile(record, []byte("{}"), 0600) }); err == nil {
		t.Fatal("source mutation during visitor accepted")
	}
	if data, e := os.ReadFile(record); e != nil || string(data) != "{}" {
		t.Fatal("source evidence was replaced", e)
	}
	if WithLegacyFingerprintV3(nil, area, "firewall", nil) == nil {
		t.Fatal("nil invocation accepted")
	}
}
