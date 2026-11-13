//go:build linux

package configpoc

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func actionGraphFixtureV2(t *testing.T) (*v2ReachabilityReader, *v2Coordinator, string) {
	t.Helper()
	r, c, name := selectedCacheFixtureV2(t)
	r.action = &actionReadDependenciesV2{entries: map[string]actionReadDependencyV2{}}
	t.Cleanup(func() {
		if err := r.closeSelectedV2(); err != nil {
			t.Error(err)
		}
	})
	return r, c, name
}
func TestActionReaderV2DefaultAndPrepare(t *testing.T) {
	r, c, _ := selectedReaderFixtureV2(t)
	if r.options.Policy != SelectionFullHistoryV2 {
		t.Fatal("default policy changed")
	}
	opts := r.options
	opts.Policy = "unknown"
	if _, err := NewRoutedSelectionReaderV2(r.area, opts); err == nil {
		t.Fatal("unknown policy accepted")
	}
	r.options.Policy = SelectionActionAuthorityV2
	ref, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ref.Mode != "prepare" || ref.Selection != c.store.selector.Current {
		t.Fatal("wrong selection")
	}
	if _, err := r.PrepareView(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
}
func TestActionReaderV2UncachedDependenciesRevalidated(t *testing.T) {
	for _, kind := range []string{"unchanged", "contents", "replacement", "permissions", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			r, _, name := actionGraphFixtureV2(t)
			r.cache.files = 0
			data, release, err := r.read(name, v2ObjectLimit)
			if err != nil {
				t.Fatal(err)
			}
			release()
			if len(r.cache.entries) != 0 || len(r.action.entries) != 1 || r.active != uint64(len(data))+actionDependencyMetadataBytesV2 {
				t.Fatal("overflow dependency not retained")
			}
			switch kind {
			case "contents":
				f, e := r.area.OpenFile(name, os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.WriteAt([]byte(" "), 0)
				if e != nil {
					t.Fatal(e)
				}
				_ = f.Close()
			case "replacement":
				if err := r.area.Rename(name, name+".held"); err != nil {
					t.Fatal(err)
				}
				if err := r.area.WriteFile(name, data, 0640); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := r.area.Chmod(name, 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				r.ctx = ctx
			}
			err = r.revalidateSelectedV2()
			if (kind == "unchanged") != (err == nil) {
				t.Fatalf("validation %s: %v", kind, err)
			}
			if err := r.closeSelectedV2(); err != nil && kind != "cancel" {
				t.Fatal(err)
			}
			if r.active != 0 || len(r.action.entries) != 0 {
				t.Fatal("dependency leak")
			}
		})
	}
}
func TestActionReaderV2DependencyBudgetIsFailClosed(t *testing.T) {
	r, _, name := actionGraphFixtureV2(t)
	r.cache.files = 0
	r.budget.ActiveBytes = 2
	if _, _, err := r.read(name, v2ObjectLimit); err == nil {
		t.Fatal("byte bound ignored")
	}
	if len(r.action.entries) != 0 || r.active != 0 {
		t.Fatal("failed read retained charge")
	}
}
func TestActionReaderV2AuditDoesNotEnumeratePredecessor(t *testing.T) {
	r, c, _ := actionGraphFixtureV2(t)
	audit := v2CoordinatorAudit{Format: v2Format, Sequence: 2, Generation: c.store.state.Generation, Previous: strings.Repeat("a", 64), Operation: "protected-operation", At: time.Now().UTC(), Running: c.store.state.Configuration.Running.Hash, Startup: c.store.state.Configuration.Startup.Hash}
	hash, err := c.store.object(audit)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.actionAuditLeafV2(hash, 2, c.store.state.Generation, 2); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.action.entries["object-"+audit.Previous+".json"]; ok {
		t.Fatal("unconsumed predecessor was read")
	}
	// Missing predecessor is an explicit rejecting loader: full G1 must still
	// refuse it, while the action leaf does not use that history as authority.
	heldDependencies := r.action
	r.action = nil
	defer func() { r.action = heldDependencies }()
	if err := r.auditChain(hash, 2, c.store.state.Generation, 2); err == nil {
		t.Fatal("default full history weakened")
	}
}
func TestActionReaderV2RejectsOpaqueOperationAuthority(t *testing.T) {
	r, c, _ := actionGraphFixtureV2(t)
	op := v2Operation{ID: "opaque-operation"}
	hash, err := c.store.object(struct {
		Format    string `json:"format"`
		Operation string `json:"operation"`
		Data      []byte `json:"data"`
	}{v2Format, op.ID, []byte("not a typed audit")})
	if err != nil {
		t.Fatal(err)
	}
	op.Outcome = &v2Outcome{AuditHash: hash}
	if err := r.operationAudit(op, c.store.state, 2); err == nil {
		t.Fatal("opaque audit authorized typed action")
	}
	if r.report.OpaqueAuditObjects != 0 {
		t.Fatal("opaque authority recorded")
	}
}
func TestActionReaderV2SelectedIntentAuthority(t *testing.T) {
	r, _, ref := selectedIntentFixtureV2(t)
	r.options.Policy = SelectionActionAuthorityV2
	actual, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal("observe intent", err)
	}
	if actual != ref {
		t.Fatal("authority policy changed selection")
	}
	plan, err := r.Resolve(context.Background(), actual, SelectionArmV2)
	if err != nil {
		t.Fatal("resolve intent", err)
	}
	if plan.Reference().Work != ref.WorkHash {
		t.Fatal("wrong work")
	}
	if _, err := r.Resolve(context.Background(), actual, SelectionBootstrapV2); err == nil {
		t.Fatal("wrong purpose authorized")
	}
}
func TestActionReaderV2RequiredAuditShape(t *testing.T) {
	cases := map[string]func(*v2CoordinatorAudit){"format": func(a *v2CoordinatorAudit) { a.Format = "foreign" }, "sequence": func(a *v2CoordinatorAudit) { a.Sequence = 0 }, "generation": func(a *v2CoordinatorAudit) { a.Generation = 0 }, "running": func(a *v2CoordinatorAudit) { a.Running = "bad" }, "startup": func(a *v2CoordinatorAudit) { a.Startup = "bad" }, "operation": func(a *v2CoordinatorAudit) { a.Operation = "" }, "time": func(a *v2CoordinatorAudit) { a.At = time.Time{} }, "predecessor": func(a *v2CoordinatorAudit) { a.Previous = "bad" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, c, _ := actionGraphFixtureV2(t)
			a := v2CoordinatorAudit{Format: v2Format, Sequence: 2, Generation: c.store.state.Generation, Previous: strings.Repeat("a", 64), Operation: "protected", At: time.Now().UTC(), Running: c.store.state.Configuration.Running.Hash, Startup: c.store.state.Configuration.Startup.Hash}
			mutate(&a)
			hash, err := c.store.object(a)
			if err != nil {
				t.Fatal(err)
			}
			var out v2CoordinatorAudit
			if err := r.object(hash, &out); err == nil {
				t.Fatal("invalid consumed typed audit accepted")
			}
		})
	}
}
func TestActionReaderV2DoesNotEnumerateUnrelatedHistory(t *testing.T) {
	r, _, _ := selectedIntentFixtureV2(t)
	full, err := r.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	historical := map[string]bool{}
	for hash := range full.graph.objects {
		historical[hash] = true
	}
	if err := full.graph.closeSelectedV2(); err != nil {
		t.Fatal(err)
	}
	r.options.Policy = SelectionActionAuthorityV2
	action, err := r.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for hash := range action.graph.objects {
		delete(historical, hash)
	}
	if err := action.graph.closeSelectedV2(); err != nil {
		t.Fatal(err)
	}
	if len(historical) == 0 {
		t.Fatal("fixture did not contain unrelated history")
	}
	var removed string
	for hash := range historical {
		removed = "object-" + hash + ".json"
		break
	}
	if err := r.area.Rename(removed, removed+".retained-test"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.area.Rename(removed+".retained-test", removed); err != nil {
			t.Error(err)
		}
	}()
	// The physical loader now rejects this historical reference. No skip or
	// injected success is used: action authority must never request the object.
	if _, err := r.Observe(context.Background()); err != nil {
		t.Fatal("unrelated history enumerated", err)
	}
	r.options.Policy = SelectionFullHistoryV2
	if _, err := r.Observe(context.Background()); err == nil {
		t.Fatal("full G1 missed missing retained history")
	}
}
func TestActionReaderV2PinnedRetentionFailureCleanup(t *testing.T) {
	r, _, name := actionGraphFixtureV2(t)
	info, err := r.area.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	r.budget.ActiveBytes = uint64(info.Size()) * 2
	if _, _, err := r.read(name, v2ObjectLimit); err == nil {
		t.Fatal("metadata retention budget ignored")
	}
	if len(r.cache.entries) != 1 {
		t.Fatal("test failed before FD cache insertion")
	}
	if err := r.closeSelectedV2(); err != nil {
		t.Fatal(err)
	}
	if r.active != 0 || r.action.metadataBytes != 0 || len(r.cache.entries) != 0 {
		t.Fatal("retention failure leaked resources")
	}
}
func TestActionReaderV2ConsumedArchiveRequiresTypedFinality(t *testing.T) {
	for _, kind := range []string{"valid", "missing-audit", "foreign-audit", "substituted-claim"} {
		t.Run(kind, func(t *testing.T) {
			c, area, _, p, _ := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			first := coordinatorV2Stage(t, c, p, "first")
			second := coordinatorV2Stage(t, c, p, "second")
			expected := v2ReserveArchiveEntry{Claim: first.Operation.Reserve.Claims.Admission}
			archive, found, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, expected, "claim")
			if err != nil || !found {
				t.Fatal("archive fixture", found, err)
			}
			rootInfo, err := area.Stat(".")
			if err != nil {
				t.Fatal(err)
			}
			graph := &v2ReachabilityReader{ctx: context.Background(), area: area, root: rootInfo, budget: reachabilityBudgetV2(), objects: map[string]bool{}, edges: map[string]uint8{}, action: &actionReadDependenciesV2{entries: map[string]actionReadDependencyV2{}}}
			if kind == "missing-audit" {
				name, err := v2ObjectName(archive.Audit)
				if err != nil {
					t.Fatal(err)
				}
				if err := area.Remove(name); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "foreign-audit" {
				var facts v2ReserveFinality
				if err := c.store.readObject(archive.FinalWork, &facts); err != nil {
					t.Fatal(err)
				}
				var origin v2Operation
				if err := c.store.readObject(facts.Origin.Object, &origin); err != nil {
					t.Fatal(err)
				}
				origin.Outcome.AuditHash = second.Operation.Outcome.AuditHash
				archive.Audit = origin.Outcome.AuditHash
				facts.Origin.Object, err = c.store.object(origin)
				if err != nil {
					t.Fatal(err)
				}
				archive.FinalWork, err = c.store.object(facts)
				if err != nil {
					t.Fatal(err)
				}
			}
			hash, err := c.store.object(archive)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := reserveArchiveBundleRefV2(archive.Lineage, first.Operation.Reserve.Scope.Bundle, hash)
			if err != nil {
				t.Fatal(err)
			}
			root, err := c.store.reserveArchiveInsertV2("", 0, "", ref)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			c.store.archiveObserver = func(actual v2ReserveArchiveRef) error {
				calls++
				if actual != ref {
					t.Fatal("unbound archive observer")
				}
				return graph.reserveArchiveObject(actual, "current", c.store.state, 0)
			}
			if kind == "substituted-claim" {
				expected.Claim.Epoch++
			}
			_, found, err = c.store.reserveArchiveBundleLookupV2(root, expected, "claim")
			if kind == "valid" {
				if err != nil || !found || calls != 1 {
					t.Fatal("typed archive refused", found, err, calls)
				}
			} else {
				if err == nil || found {
					t.Fatal("invalid consumed archive accepted")
				}
				if kind == "substituted-claim" && calls != 0 {
					t.Fatal("foreign claim reached authority observer")
				}
			}
		})
	}
}
