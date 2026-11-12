//go:build linux

package configpoc

import (
	"context"
	"testing"
)

func TestV2ClosingReachabilityIncludesReservedOperations(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "missing-closing-operation"}[missing], func(t *testing.T) {
			s, now, subject, namespace, origin := closingFixtureV2(t)
			child, err := s.admit(subject, namespace, s.state.Generation, closingRequestV2(origin), now)
			if err != nil {
				t.Fatal(err)
			}
			hash, err := s.catalogueHashV2(child.Sequence)
			if err != nil {
				t.Fatal(err)
			}
			area := s.root
			if err := s.close(); err != nil {
				t.Fatal(err)
			}
			if missing {
				name, err := v2ObjectName(hash)
				if err != nil {
					t.Fatal(err)
				}
				if err := area.Remove(name); err != nil {
					t.Fatal(err)
				}
			}
			report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
			if missing {
				if err == nil || report.Complete {
					t.Fatal("inspection ignored missing reserved operation")
				}
			} else if err != nil || !report.Complete {
				t.Fatalf("complete catalogue rejected: %v", err)
			}
		})
	}
}
