//go:build linux

package configpoc

import (
	"context"
	"os"
	"reflect"
	"testing"
)

func selectedCacheFixtureV2(t *testing.T) (*v2ReachabilityReader, *v2Coordinator, string) {
	t.Helper()
	reader, c, _ := selectedReaderFixtureV2(t)
	graph := &v2ReachabilityReader{ctx: context.Background(), area: reader.area, budget: reader.options.Budget, objects: map[string]bool{}, edges: map[string]uint8{}, shared: &reader.options.Access, cache: newSelectedReadCacheV2()}
	t.Cleanup(func() {
		if err := graph.cache.close(graph); err != nil {
			t.Error(err)
		}
	})
	return graph, c, "object-" + c.store.selection.State + ".json"
}
func TestSelectedCacheV2BytesAndTypedChecks(t *testing.T) {
	r, c, name := selectedCacheFixtureV2(t)
	first, release, err := r.read(name, v2ObjectLimit)
	if err != nil {
		t.Fatal(err)
	}
	release()
	bytes := r.report.BytesRead
	second, release, err := r.read(name, v2ObjectLimit)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if string(first) != string(second) || r.cache.hits != 1 || r.report.BytesRead != bytes {
		t.Fatal("raw object not reused")
	}
	var selection v2Selection
	if err := r.object(c.store.selection.State, &selection); err == nil {
		t.Fatal("cached bytes bypassed typed decoding")
	}
	if _, _, err := r.read(name, 1); err == nil {
		t.Fatal("cached payload bypassed caller limit")
	}
	if err := r.cache.revalidate(r); err != nil {
		t.Fatal(err)
	}
	if err := r.cache.close(r); err != nil || r.active != 0 || len(r.cache.entries) != 0 {
		t.Fatal("cache retained resources", err, r.active)
	}
}
func TestSelectedCacheV2RejectsChangedFiles(t *testing.T) {
	for _, kind := range []string{"contents", "contents_same_metadata", "replacement", "mode", "link", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			r, _, name := selectedCacheFixtureV2(t)
			data, release, err := r.read(name, v2ObjectLimit)
			if err != nil {
				t.Fatal(err)
			}
			release()
			before := r.cache.entries[name].info
			switch kind {
			case "contents", "contents_same_metadata":
				f, e := r.area.OpenFile(name, os.O_WRONLY, 0)
				if e != nil {
					t.Fatal(e)
				}
				changed := append([]byte(nil), data...)
				changed[0] = ' '
				if _, e = f.WriteAt(changed, 0); e != nil {
					t.Fatal(e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
				if e = r.area.Chtimes(name, before.ModTime(), before.ModTime()); e != nil {
					t.Fatal(e)
				}
				if kind == "contents_same_metadata" {
					// Emulate a filesystem whose timestamps do not distinguish the write:
					// the final byte comparison must independently reject changed data.
					entry := r.cache.entries[name]
					entry.info, err = entry.file.Stat()
					if err != nil {
						t.Fatal(err)
					}
					r.cache.entries[name] = entry
				}
			case "replacement":
				if e := r.area.Rename(name, name+".held"); e != nil {
					t.Fatal(e)
				}
				f, e := r.area.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.Write(data); e != nil {
					t.Fatal(e)
				}
				if e = f.Chmod(0640); e != nil {
					t.Fatal(e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
			case "mode":
				if e := r.area.Chmod(name, 0600); e != nil {
					t.Fatal(e)
				}
			case "link":
				if e := r.area.Link(name, name+".held"); e != nil {
					t.Fatal(e)
				}
			case "cancel":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				r.ctx = ctx
			}
			if err := r.cache.revalidate(r); err == nil {
				t.Fatal("changed pinned record accepted")
			}
		})
	}
}
func TestSelectedCacheV2BudgetAndSelector(t *testing.T) {
	r, _, name := selectedCacheFixtureV2(t)
	data, release, err := r.read(name, v2ObjectLimit)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if r.active != uint64(len(data)) {
		t.Fatal("retained bytes not charged")
	}
	if _, release, err := r.read("selected.json", 4096); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	if _, ok := r.cache.entries["selected.json"]; ok {
		t.Fatal("mutable selector cached")
	}
	r.budget.IOCalls = r.report.IOCalls
	if err := r.cache.revalidate(r); err == nil {
		t.Fatal("revalidation exceeded budget")
	}
	r.budget.IOCalls += 1024
}
func TestSelectedCacheV2PureConfigurationDoesNotReuseChangedInput(t *testing.T) {
	r, c, _ := selectedCacheFixtureV2(t)
	cfg := clone(*c.store.state.Configuration)
	if !r.selectedConfigurationValidV2(&cfg) {
		t.Fatal("valid fixture")
	}
	cfg.Running.Hash = "invalid"
	if r.selectedConfigurationValidV2(&cfg) {
		t.Fatal("changed configuration accepted")
	}
}
func TestSelectedReaderV2CurrentViewAndWorkExpectations(t *testing.T) {
	r, _, _ := selectedReaderFixtureV2(t)
	ref, err := r.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected, err := r.PrepareView(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := r.PrepareCurrentView(context.Background())
	if err != nil || !reserveJSONEqualV2(expected, actual) {
		t.Fatal("atomic view differs", err)
	}
	ref.Generation++
	if _, err = r.PrepareView(context.Background(), ref); err == nil {
		t.Fatal("legacy reference check weakened")
	}
	for _, work := range []RoutedWorkReferenceV1{{}, {Work: ref.Selection, Lineage: ref.Lineage, Generation: ref.Generation}} {
		if _, err = r.ResolveCurrent(context.Background(), work, SelectionArmV2); err == nil {
			t.Fatal("expectation became authority")
		}
	}
}

func TestSelectedCacheV2SnapshotContextCannotCrossGeneration(t *testing.T) {
	r, c, _ := selectedCacheFixtureV2(t)
	hash, err := c.store.object(*c.store.state.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	state := clone(c.store.state)
	if err = r.snapshot(hash, "first-path", state, 1); err != nil {
		t.Fatal(err)
	}
	edges := len(r.edges)
	if err = r.snapshot(hash, "another-path", state, 1); err != nil || len(r.edges) != edges {
		t.Fatal("identical context was not memoized", err)
	}
	state.Generation = 0
	if err = r.snapshot(hash, "first-path", state, 1); err == nil {
		t.Fatal("different context bypassed generation validation")
	}
}

func TestSelectedCacheV2WorkClosureAndLineage(t *testing.T) {
	reader, _, ref := selectedIntentFixtureV2(t)
	v, err := reader.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := v.graph.cache.close(v.graph); err != nil {
			t.Error(err)
		}
	}()
	r := v.graph
	plan, err := r.selectedRoutedWorkV2(ref.WorkHash, ref.Lineage)
	if err != nil || !plan.Valid() {
		t.Fatal(err)
	}
	if len(r.cache.plans) == 0 || r.cache.planBytes == 0 {
		t.Fatal("complete pinned work was not memoized")
	}
	if err = r.routedWork(ref.WorkHash, "original", v.store.state, 1); err != nil {
		t.Fatal(err)
	}
	foreign := clone(v.store.state)
	foreign.Lineage += "other"
	if err = r.routedWork(ref.WorkHash, "original", foreign, 1); err == nil {
		t.Fatal("work closure memo bypassed lineage context")
	}
	reads := r.report.BytesRead
	again, err := r.selectedRoutedWorkV2(ref.WorkHash, ref.Lineage)
	if err != nil || again.Reference() != plan.Reference() || r.report.BytesRead != reads {
		t.Fatal("work memo", err)
	}
	if _, err = r.selectedRoutedWorkV2(ref.WorkHash, ref.Lineage+"other"); err == nil {
		t.Fatal("foreign lineage reused memo")
	}
	// Keep the complete represented-payload accounting in sync with private
	// fields; adding a field requires an explicit accounting review.
	if reflect.TypeFor[RoutedSelectedPlanV1]().NumField() != 7 {
		t.Fatal("plan representation changed; review memo payload accounting")
	}
	if _, err = reader.ResolveCurrent(context.Background(), plan.Reference(), SelectionArmV2); err != nil {
		t.Fatal(err)
	}
	wrong := plan.Reference()
	wrong.Generation++
	if _, err = reader.ResolveCurrent(context.Background(), wrong, SelectionArmV2); err == nil {
		t.Fatal("wrong work generation accepted")
	}
}
