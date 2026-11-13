//go:build linux

package configpoc

import (
	"context"
	"testing"
)

func TestSelectedCacheV2ArchiveFinalityPreservesContext(t *testing.T) {
	c, a, principal, target := boundaryCoordinatorFixtureV2(t)
	reader := sharedBoundaryReaderV2(t, c, a)
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &target}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	op, result, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: op.ID, Target: result.Current.Running.Hash}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpSave}); err != nil {
		t.Fatal(err)
	}
	archive, found, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: op.Reserve.Claims.Admission}, "claim")
	if err != nil || !found {
		t.Fatal("real routed archive", found, err)
	}
	view, err := reader.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := view.graph.cache.close(view.graph); err != nil {
			t.Error(err)
		}
	}()
	for _, kind := range []string{"valid", "lineage", "feature", "high_water", "finality"} {
		state := clone(c.store.state)
		candidate := clone(archive)
		switch kind {
		case "lineage":
			state.Lineage += "foreign"
		case "feature":
			var features []string
			for _, feature := range state.RequiredFeatures {
				if feature != v2RoutedFeature {
					features = append(features, feature)
				}
			}
			state.RequiredFeatures = features
		case "high_water":
			state.HighWater = 0
		case "finality":
			candidate.FinalWork = c.store.selection.State
		}
		original := validateArchiveFinalityV2(candidate, state, c.store.readObject)
		reused := view.graph.selectedArchiveFinalityV2(candidate, state)
		if (original == nil) != (reused == nil) {
			t.Fatalf("%s wrapper/hook mismatch: %v / %v", kind, original, reused)
		}
		if (kind == "valid") != (reused == nil) {
			t.Fatalf("%s contextual finality: %v", kind, reused)
		}
	}
	if err = view.graph.cache.revalidate(view.graph); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedCacheV2WorkPredicateEquivalent(t *testing.T) {
	reader, _, ref := selectedIntentFixtureV2(t)
	view, err := reader.read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := view.graph.cache.close(view.graph); err != nil {
			t.Error(err)
		}
	}()
	for _, kind := range []string{"valid", "configuration", "lineage"} {
		lineage := ref.Lineage
		if kind == "lineage" {
			lineage += "foreign"
		}
		load := func(hash string, target any) error {
			if err := view.graph.object(hash, target); err != nil {
				return err
			}
			if cfg, ok := target.(*v2Configuration); ok && kind == "configuration" {
				cfg.Running.Hash = "invalid"
			}
			return nil
		}
		original, originalErr := loadRoutedWorkV2(ref.WorkHash, lineage, load)
		reused, reusedErr := loadRoutedWorkWithValidationV2(ref.WorkHash, lineage, load, view.graph.selectedConfigurationValidV2)
		if (originalErr == nil) != (reusedErr == nil) || (kind == "valid") != (reusedErr == nil) {
			t.Fatalf("%s: wrapper/hook %v / %v", kind, originalErr, reusedErr)
		}
		if reusedErr == nil && (!reserveJSONEqualV2(original.work, reused.work) || original.Reference() != reused.Reference()) {
			t.Fatal("work changed")
		}
	}
	if _, err := loadRoutedWorkWithValidationV2(ref.WorkHash, ref.Lineage, view.graph.object, nil); err == nil {
		t.Fatal("nil validation accepted")
	}
}
