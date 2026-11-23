//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestPreparedActivationInspectsBoundHistoryAndRejectsMismatches(t *testing.T) {
	r, c, _ := selectedReaderFixtureV2(t)
	before := c.store.selector
	var imported v2Migration
	if err := c.store.readObject(c.store.state.Migration, &imported); err != nil {
		t.Fatal(err)
	}
	approved := PreparedActivationExpectationV1{
		Firewall: fingerprintLegacyV2(imported.Firewall), LocalServices: fingerprintLegacyV2(imported.LocalServices),
		Subjects: c.store.state.Subjects, Bindings: imported.Bindings,
	}
	report, err := InspectPreparedActivationV1(context.Background(), r.area, r.options, approved)
	if err != nil || report.Selection.Selection != before.Current || report.Startup != c.store.state.Configuration.Startup.Hash ||
		report.Used.Entries == 0 || report.Used.Objects == 0 || report.Used.Depth == 0 {
		t.Fatalf("prepared history inspection failed: %+v, %v", report, err)
	}
	wrong := approved
	wrong.Firewall.Sequence++
	if _, err = InspectPreparedActivationV1(context.Background(), r.area, r.options, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale origin accepted: %v", err)
	}
	wrong = approved
	wrong.Bindings = []LegacyBindingV2{{Actor: "unknown"}}
	if _, err = InspectPreparedActivationV1(context.Background(), r.area, r.options, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("different binding accepted: %v", err)
	}
	options := r.options
	options.Policy = SelectionActionAuthorityV2
	if _, err = InspectPreparedActivationV1(context.Background(), r.area, options, approved); !errors.Is(err, ErrInvalid) {
		t.Fatalf("action-only reader accepted: %v", err)
	}
	options = r.options
	options.Budget.Objects = 1
	if proof, err := InspectPreparedActivationV1(context.Background(), r.area, options, approved); err == nil || proof != (PreparedActivationInspectionV1{}) {
		t.Fatalf("budget overrun yielded inspection evidence: %+v, %v", proof, err)
	}
	if c.store.selector != before {
		t.Fatal("inspection changed the selector")
	}
}

func TestPreparedActivationEntryBudget(t *testing.T) {
	r, _, _ := selectedReaderFixtureV2(t)
	entries, err := os.ReadDir(r.area.Name())
	if err != nil || len(entries) < 2 {
		t.Fatal("fixture has no entries", err)
	}
	for _, tc := range []struct {
		name  string
		limit uint64
		want  error
	}{{"exact", uint64(len(entries)), nil}, {"short", uint64(len(entries) - 1), errV2InspectionBudget}} {
		t.Run(tc.name, func(t *testing.T) {
			graph := &v2ReachabilityReader{ctx: context.Background(), area: r.area, shared: &r.options.Access, budget: r.options.Budget}
			graph.budget.Entries = tc.limit
			if err := graph.countActivationEntriesV1(); !errors.Is(err, tc.want) {
				t.Fatalf("count: %v", err)
			}
			if tc.want == nil && graph.report.Entries != tc.limit {
				t.Fatalf("counted %d entries, want %d", graph.report.Entries, tc.limit)
			}
		})
	}
}
