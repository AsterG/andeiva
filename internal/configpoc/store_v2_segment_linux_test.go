//go:build linux

package configpoc

import (
	"encoding/json"
	"testing"
	"time"
)

func TestV2RejectsForgedCheckpointSegment(t *testing.T) {
	for _, kind := range []string{"checkpoint-noninitial-segment", "reset-without-checkpoint", "missing-predecessor", "prior-checkpoint-noninitial-segment"} {
		t.Run(kind, func(t *testing.T) {
			s, area, now, subject := v2Fixture(t, 64)
			if _, err := s.namespace(subject, "firewall", now, time.Hour); err != nil {
				t.Fatal(err)
			}
			if _, err := s.namespace(subject, "firewall", now, time.Hour); err != nil {
				t.Fatal(err)
			}
			selection := s.selection
			switch kind {
			case "checkpoint-noninitial-segment":
				selection.Checkpoint = true
			case "reset-without-checkpoint":
				selection.Segment = 1
				selection.Checkpoint = false
			case "missing-predecessor":
				selection.Previous = ""
			case "prior-checkpoint-noninitial-segment":
				var prior v2Selection
				if err := s.readObject(selection.Previous, &prior); err != nil {
					t.Fatal(err)
				}
				prior.Checkpoint = true
				hash, err := s.object(prior)
				if err != nil {
					t.Fatal(err)
				}
				selection.Previous = hash
			}
			hash, err := s.object(selection)
			if err != nil {
				t.Fatal(err)
			}
			selector := v2Selector{Format: v2Format, Current: hash, Previous: selection.Previous}
			data, err := json.Marshal(selector)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.close(); err != nil {
				t.Fatal(err)
			}
			if err = area.WriteFile("selected.json", data, 0600); err != nil {
				t.Fatal(err)
			}
			reopened, err := openV2(area, s.budget)
			if err == nil {
				_ = reopened.close()
				t.Fatal("forged segment accepted")
			}
		})
	}
}
func TestV2SelectionSegmentBoundaries(t *testing.T) {
	valid := []v2Selection{{Format: v2Format, Sequence: 1, Segment: 1}, {Format: v2Format, Sequence: 65, Segment: 1, Checkpoint: true, Previous: "prior"}, {Format: v2Format, Sequence: 64, Segment: 64, Previous: "prior"}}
	for _, s := range valid {
		if !v2ValidSelection(s) {
			t.Fatalf("valid selection rejected: %+v", s)
		}
	}
}
