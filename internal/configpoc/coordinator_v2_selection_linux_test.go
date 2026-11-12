//go:build linux

package configpoc

import (
	"encoding/json"
	"testing"
)

func TestCoordinatorV2SelectionRejectsForgedBoundaryAndPriorLineage(t *testing.T) {
	for _, kind := range []string{"checkpoint-segment", "missing-checkpoint", "prior-segment", "prior-lineage"} {
		t.Run(kind, func(t *testing.T) {
			s, area, _, _ := v2Fixture(t, 64)
			for i := 0; i < 64; i++ {
				if err := s.publish(clone(s.state)); err != nil {
					t.Fatal(err)
				}
			}
			if s.selection.Sequence != 65 || s.selection.Segment != 1 || !s.selection.Checkpoint {
				t.Fatal("fixture did not cross boundary")
			}
			current := s.selection
			switch kind {
			case "checkpoint-segment":
				current.Segment = 17
			case "missing-checkpoint":
				current.Checkpoint = false
			case "prior-segment", "prior-lineage":
				var prior v2Selection
				if s.readObject(current.Previous, &prior) != nil {
					t.Fatal("prior")
				}
				if kind == "prior-segment" {
					prior.Segment = 65
				} else {
					var state v2State
					if s.readObject(prior.State, &state) != nil {
						t.Fatal("prior state")
					}
					state.Lineage = "foreign-lineage"
					hash, err := s.object(state)
					if err != nil {
						t.Fatal(err)
					}
					prior.State = hash
				}
				hash, err := s.object(prior)
				if err != nil {
					t.Fatal(err)
				}
				current.Previous = hash
			}
			hash, err := s.object(current)
			if err != nil {
				t.Fatal(err)
			}
			selector := v2Selector{Format: v2Format, Current: hash, Previous: current.Previous}
			data, err := json.Marshal(selector)
			if err != nil {
				t.Fatal(err)
			}
			if err = area.WriteFile("selected.json", data, 0600); err != nil {
				t.Fatal(err)
			}
			_ = s.close()
			if reopened, err := openV2(area, s.budget); err == nil {
				_ = reopened.close()
				t.Fatal("forged boundary/lineage accepted")
			}
		})
	}
}
