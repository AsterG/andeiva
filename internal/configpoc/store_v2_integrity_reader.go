package configpoc

import (
	"context"
	"errors"
)

var errInspectionHeaderV1 = errors.New("inspection header complete")

// InspectionReference is a bounded selection/quiescence observation, not full
// history qualification. The caller still owns the publication barrier and the
// helper must independently prove that its physical guardian is idle/bootstrap.
func (r *RoutedSelectionReaderV2) InspectionReference(ctx context.Context) (SelectionReferenceV2, error) {
	if r == nil || ctx == nil {
		return SelectionReferenceV2{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inspectionReferenceLockedV1(ctx, true)
}

// CaptureReferenceV1 observes a fresh tuple even during existing recovery. It
// authorizes neither continuation nor readiness and does not perform full G1.
func (r *RoutedSelectionReaderV2) CaptureReferenceV1(ctx context.Context) (SelectionReferenceV2, error) {
	if r == nil || ctx == nil {
		return SelectionReferenceV2{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inspectionReferenceLockedV1(ctx, false)
}

func (r *RoutedSelectionReaderV2) inspectionReferenceLockedV1(ctx context.Context, quiescent bool) (SelectionReferenceV2, error) {
	if err := ctx.Err(); err != nil {
		return SelectionReferenceV2{}, err
	}
	var ref SelectionReferenceV2
	_, err := r.readWithGateV2(ctx, func(v *selectedViewV2) error {
		if quiescent && !inspectionQuiescentV1(v.store.state) {
			return ErrConflict
		}
		actual, err := selectedReferenceV2(v.store)
		if err != nil {
			return err
		}
		if err = r.revalidate(ctx, v); err != nil {
			return err
		}
		if err = v.graph.closeSelectedV2(); err != nil {
			return err
		}
		ref = actual
		return errInspectionHeaderV1
	})
	if ctx.Err() != nil {
		return SelectionReferenceV2{}, ctx.Err()
	}
	if errors.Is(err, errInspectionHeaderV1) {
		return ref, nil
	}
	return SelectionReferenceV2{}, err
}

// InspectQuiescentV1 runs full G1, never the action-only policy. It neither
// acquires a writer flock nor publishes/clears a fence. Every non-complete result
// is a denial; only helper-owned gate code decides durable fence handling.
func (r *RoutedSelectionReaderV2) InspectQuiescentV1(ctx context.Context, expected SelectionReferenceV2) (IntegrityResultV1, error) {
	result := IntegrityResultV1{State: IntegrityUnavailableV1}
	if r == nil || ctx == nil {
		return result, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.options.Policy != SelectionFullHistoryV2 {
		return result, ErrDenied
	}
	if err := ctx.Err(); err != nil {
		result.State = IntegrityCancelledV1
		return result, err
	}
	var matched *selectedViewV2
	view, err := r.readWithGateV2(ctx, func(v *selectedViewV2) error {
		if !inspectionQuiescentV1(v.store.state) {
			return ErrConflict
		}
		actual, e := selectedReferenceV2(v.store)
		if e != nil {
			return e
		}
		result.Selection = actual
		if actual != expected {
			result.State = IntegrityStaleV1
			return ErrConflict
		}
		matched = v
		return nil
	})
	if err == nil {
		if view.ref != expected {
			result.State = IntegrityStaleV1
			err = ErrConflict
		}
		if closeErr := view.graph.closeSelectedV2(); closeErr != nil {
			result.State = IntegrityUnavailableV1
			err = closeErr
		}
		if err == nil {
			result.State = IntegrityCompleteV1
			result.Selection = view.ref
		}
		return result, err
	}
	if ctx.Err() != nil {
		result.State = IntegrityCancelledV1
		return result, ctx.Err()
	}
	if result.State == IntegrityStaleV1 || matched == nil {
		return result, err
	}
	// The failed read has closed its cached descriptors. Recheck the selector
	// and pools using the SAME graph budget, not a fresh inspection allowance.
	// A changing or unreadable dependency cannot become confirmed corruption.
	defer func() { _ = matched.graph.closeSelectedV2() }()
	data, checkErr := matched.store.readRecordV2("selected.json", 4096)
	var selector v2Selector
	if ctx.Err() != nil {
		result.State = IntegrityCancelledV1
		return result, ctx.Err()
	}
	if checkErr != nil || checkpointDecode(data, &selector) != nil {
		return result, err
	}
	if selector != matched.store.selector {
		result.State = IntegrityStaleV1
		return result, ErrConflict
	}
	checkErr = r.revalidate(ctx, matched)
	closeErr := matched.graph.closeSelectedV2()
	if ctx.Err() != nil {
		result.State = IntegrityCancelledV1
		return result, ctx.Err()
	}
	if checkErr != nil || closeErr != nil {
		return result, err
	}
	if matched.graph.integrityCorruption {
		result.State = IntegrityFencedV1
	}
	return result, err
}
