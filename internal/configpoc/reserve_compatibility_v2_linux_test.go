//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"testing"
)

func TestV2ReserveMarkerCannotBeRemovedAcrossCheckpoints(t *testing.T) {
	s, area, _, _ := v2Fixture(t, v2MaximumOperations)
	if err := s.enableClosingCreditsLocked(); err != nil {
		t.Fatal(err)
	}
	stripped := clone(s.state)
	stripped.RecoveryReserveVersion = 0
	if err := s.publish(stripped); err == nil {
		t.Fatal("recovery marker downgrade was published")
	}
	for range 130 {
		if err := s.publish(s.state); err != nil {
			t.Fatal(err)
		}
	}
	// Construct a hash-consistent but semantically invalid predecessor edge.
	// This bypasses publication exclusively to test reopening and inspection.
	stripped = clone(s.state)
	stripped.RecoveryReserveVersion = 0
	stateHash, err := s.object(stripped)
	if err != nil {
		t.Fatal(err)
	}
	next := v2Selection{Format: v2Format, Lineage: s.state.Lineage, Sequence: s.selection.Sequence + 1, State: stateHash, Previous: s.selector.Current, Segment: s.selection.Segment + 1}
	if next.Segment > 64 {
		next.Segment = 1
		next.Checkpoint = true
	}
	selectionHash, err := s.object(next)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(v2Selector{Format: v2Format, Current: selectionHash, Previous: s.selector.Current})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointWrite(area, "selection.pending", data, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := area.Rename("selection.pending", "selected.json"); err != nil {
		t.Fatal(err)
	}
	if err := checkpointSync(area, nil, ""); err != nil {
		t.Fatal(err)
	}
	budget := s.budget
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := openV2(area, budget); err == nil {
		opened.close()
		t.Fatal("reopen accepted stripped recovery marker")
	}
	if report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2()); err == nil || report.Complete {
		t.Fatal("inspection accepted stripped recovery marker")
	}
}
