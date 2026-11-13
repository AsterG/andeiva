package configpoc

import (
	"context"
	"reflect"
)

// ResolveFencedContinuationV1 preserves only previously selected recovery and
// closing obligations. An integrity fence cannot authorize a new bootstrap or
// a newly admitted confirmation of a previously pending target.
func (r *RoutedSelectionReaderV2) ResolveFencedContinuationV1(ctx context.Context, anchor RoutedColdAnchorV1, expected RoutedWorkReferenceV1, purpose RoutedSelectionPurposeV2) (RoutedSelectedPlanV1, error) {
	return r.resolveColdContinuationV1(ctx, anchor, expected, purpose, true)
}

func fencedContinuationAllowedV1(anchor RoutedColdAnchorV1, current *v2Configuration, purpose RoutedSelectionPurposeV2) bool {
	switch purpose {
	case SelectionMatchBeforeV2, SelectionMatchTargetV2:
		return true // Readback conveys no permission to publish or apply.
	case SelectionRecoverV2:
		return anchor.configuration.Intent != nil || anchor.configuration.Pending != nil
	case SelectionConfirmV2:
		in := anchor.configuration.Intent
		return in != nil && current != nil && (in.Kind == OpConfirm || in.Kind == v2BootKind) && reflect.DeepEqual(in, current.Intent)
	}
	return false
}
