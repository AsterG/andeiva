//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFullHistoryRetentionMatchesUncachedView(t *testing.T) {
	for _, change := range []string{"valid", "missing", "modified", "symlink", "mode", "selector"} {
		t.Run(change, func(t *testing.T) {
			reader, store, _ := selectedReaderFixtureV2(t)
			name, err := v2ObjectName(store.store.state.Migration)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(reader.area.Name(), name)
			switch change {
			case "missing":
				err = os.Remove(path)
			case "modified":
				err = os.WriteFile(path, []byte("{}"), 0640)
			case "symlink":
				if err = os.Rename(path, path+".original"); err == nil {
					err = os.Symlink(name+".original", path)
				}
			case "mode":
				err = os.Chmod(path, 0660)
			case "selector":
				err = os.WriteFile(filepath.Join(reader.area.Name(), "selected.json"), []byte("{}"), 0640)
			}
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			current, currentErr := reader.PrepareCurrentView(ctx)
			old, oldErr := prepareWithoutHistoryRetention(t, ctx, reader)
			if (oldErr == nil) != (currentErr == nil) || !reflect.DeepEqual(old, current) {
				t.Fatalf("decision or view changed: previous %v, current %v", oldErr, currentErr)
			}
			if (oldErr == nil) != (change == "valid") {
				t.Fatalf("unexpected outcome: %v", oldErr)
			}
		})
	}
}

func prepareWithoutHistoryRetention(t *testing.T, ctx context.Context, reader *RoutedSelectionReaderV2) (RoutedPrepareViewV2, error) {
	t.Helper()
	view, err := reader.readWithGateV2(ctx, func(v *selectedViewV2) error {
		v.graph.active -= v.graph.history.bytes
		v.graph.history = nil
		return nil
	})
	if err != nil {
		return RoutedPrepareViewV2{}, err
	}
	defer func() {
		if err := view.graph.closeSelectedV2(); err != nil {
			t.Error(err)
		}
	}()
	out, err := routedPrepareViewFromStoreV2(view.store)
	if err != nil {
		return RoutedPrepareViewV2{}, err
	}
	if err = addServiceRestartViewV3(view.store, reader.options.Identity, &out); err != nil {
		return RoutedPrepareViewV2{}, err
	}
	if err = reader.revalidate(ctx, view); err != nil {
		return RoutedPrepareViewV2{}, err
	}
	return out, nil
}

func TestFullHistoryRetentionFallsBackAndRevalidates(t *testing.T) {
	for _, mutation := range []string{"none", "mode", "bytes", "identity"} {
		reader, store, _ := selectedReaderFixtureV2(t)
		name, err := v2ObjectName(store.store.state.Migration)
		if err != nil {
			t.Fatal(err)
		}
		file, err := reader.area.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		size := uint64(file.Size())
		graph := &v2ReachabilityReader{
			ctx: context.Background(), area: reader.area, shared: &reader.options.Access, budget: reader.options.Budget,
			cache: &selectedReadCacheV2{}, history: &historyReadCacheV2{entries: map[string]historyReadEntryV2{}},
		}
		t.Cleanup(func() {
			if err := graph.closeSelectedV2(); err != nil || graph.active != 0 {
				t.Errorf("unbalanced accounting: %d, %v", graph.active, err)
			}
		})
		graph.budget.ActiveBytes = size * 2
		read := func(name string) {
			t.Helper()
			_, release, err := graph.readSharedRecordV2(name, v2ObjectLimit)
			if err != nil {
				t.Fatal(err)
			}
			release()
		}
		read(name)
		read(name)
		if graph.active != size || graph.report.BytesRead != size || graph.report.IOCalls != 65 {
			t.Fatal("retention failed to charge bytes or service a repeat")
		}
		other, err := v2ObjectName(store.store.selector.Current)
		if err != nil {
			t.Fatal(err)
		}
		otherInfo, err := reader.area.Stat(other)
		if err != nil {
			t.Fatal(err)
		}
		read(other)
		read(other)
		if graph.active != size || graph.report.IOCalls != 193 || graph.report.BytesRead != size+2*uint64(otherInfo.Size()) {
			t.Fatal("a full cache must read an unretained object at the ordinary charge")
		}
		if !graph.selectedActiveFitsV2(size+1) || graph.history.bytes != 0 || graph.active != 0 {
			t.Fatal("optional payload prevented a normal load")
		}
		read(name)
		if graph.report.IOCalls != 257 || graph.report.BytesRead != 2*(size+uint64(otherInfo.Size())) || graph.active != 0 {
			t.Fatal("fallback did not use the ordinary load and release")
		}
		path := filepath.Join(reader.area.Name(), name)
		switch mutation {
		case "mode":
			err = os.Chmod(path, 0660)
		case "bytes":
			err = os.WriteFile(path, []byte("{}"), 0640)
		case "identity":
			var original []byte
			original, err = os.ReadFile(path)
			if err == nil {
				err = os.Rename(path, path+".original")
			}
			if err == nil {
				err = os.WriteFile(path, original, file.Mode().Perm())
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		err = graph.revalidateSelectedV2()
		if (mutation == "none" && err != nil) || (mutation != "none" && !errors.Is(err, errV2Unavailable)) {
			t.Fatalf("revalidation after release, mutation=%s: %v", mutation, err)
		}
	}
}
