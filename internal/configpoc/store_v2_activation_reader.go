package configpoc

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
)

type PreparedActivationExpectationV1 struct {
	Firewall, LocalServices LegacyFingerprintV2
	Subjects                []SubjectV2
	Bindings                []LegacyBindingV2
}

type PreparedActivationInspectionV1 struct {
	Selection SelectionReferenceV2
	Startup   string
	Used      SelectionReadBudgetV2
}

// InspectPreparedActivationV1 runs the full G1 reader before there is a new
// namespace. It returns observations only and borrows the root and read-only
// pools. The installer must exclude both writers until publication.
func InspectPreparedActivationV1(ctx context.Context, area *os.Root, options SelectionReaderOptionsV2, expected PreparedActivationExpectationV1) (PreparedActivationInspectionV1, error) {
	if ctx == nil || options.Policy != SelectionFullHistoryV2 || !validSelectionReaderResourcesV2(area, options) {
		return PreparedActivationInspectionV1{}, ErrInvalid
	}
	reader := &RoutedSelectionReaderV2{area: area, options: options}
	view, err := reader.readWithGateV2(ctx, func(v *selectedViewV2) error {
		s := v.store.state
		c := s.Configuration
		if !inspectionQuiescentV1(s) || c.Candidate != nil || c.CandidateGroup != nil ||
			c.Firewall.Candidate != nil || c.LocalServices.Candidate != nil || c.LastCompletedBoot != "" ||
			s.Operational || !validHash(s.Migration) || s.RoutedActive != nil || s.RoutedBootBoundary != nil || s.RoutedDHCP != nil {
			return ErrRecovery
		}
		var imported v2Migration
		if v.store.readObject(s.Migration, &imported) != nil ||
			fingerprintLegacyV2(imported.Firewall) != expected.Firewall ||
			fingerprintLegacyV2(imported.LocalServices) != expected.LocalServices ||
			!slices.Equal(s.Subjects, expected.Subjects) || !slices.Equal(imported.Bindings, expected.Bindings) {
			return ErrConflict
		}
		return v.graph.countActivationEntriesV1()
	})
	if err != nil {
		return PreparedActivationInspectionV1{}, err
	}
	if err = errors.Join(view.graph.closeSelectedV2(), ctx.Err()); err != nil {
		return PreparedActivationInspectionV1{}, err
	}
	report := view.graph.report
	if report.IOCalls > options.Budget.IOCalls {
		return PreparedActivationInspectionV1{}, errV2InspectionBudget
	}
	return PreparedActivationInspectionV1{
		Selection: view.ref,
		Startup:   view.store.state.Configuration.Startup.Hash,
		Used: SelectionReadBudgetV2{
			Entries: report.Entries, Objects: report.Objects, Edges: report.Edges,
			IOCalls: report.IOCalls, Bytes: report.BytesRead, ActiveBytes: report.PeakActiveBytes,
			Depth: report.MaximumDepth,
		},
	}, nil
}

func (r *v2ReachabilityReader) countActivationEntriesV1() (result error) {
	dir, _, err := r.sharedDirectoryV2()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, r.closeFile(dir)) }()
	for {
		if err := r.step(); err != nil {
			return err
		}
		entries, err := dir.ReadDir(64)
		if uint64(len(entries)) > r.budget.Entries-r.report.Entries {
			return errV2InspectionBudget
		}
		r.report.Entries += uint64(len(entries))
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errV2Unavailable
		}
	}
}
