package configpoc

import (
	"context"
	"time"
)

// RuntimeIntegrityV1 is a trusted controller dependency, never a user request.
// Inspection returns only after its helper dispatch has completed or the
// controller has been irrevocably fenced against further publication.
type RuntimeIntegrityV1 interface {
	Attach(context.Context, SelectionReferenceV2) error
	Inspect(context.Context, SelectionReferenceV2) (IntegrityResultV1, error)
}

type IntegrityStateV1 string

const (
	IntegrityCompleteV1    IntegrityStateV1 = "complete"
	IntegrityCancelledV1   IntegrityStateV1 = "cancelled"
	IntegrityStaleV1       IntegrityStateV1 = "stale"
	IntegrityUnavailableV1 IntegrityStateV1 = "unavailable"
	IntegrityFencedV1      IntegrityStateV1 = "fenced"

	IntegrityInspectionDeadlineV1 = 30 * time.Second
	IntegrityInspectionIntervalV1 = time.Minute
	IntegrityPublicationLimitV1   = 64
)

type IntegrityResultV1 struct {
	Selection SelectionReferenceV2 `json:"selection"`
	State     IntegrityStateV1     `json:"state"`
}

// Accepted catalogue work and reserved closing potential are not physical
// leases. The sole writer must retain store.mu; the helper separately verifies
// idle/bootstrap before inspecting. Inspection never retires any reservation.
func inspectionQuiescentV1(state v2State) bool {
	c := state.Configuration
	return c != nil && c.Intent == nil && c.Pending == nil && !c.RecoveryRequired
}

func selectedReferenceV2(s *v2Store) (SelectionReferenceV2, error) {
	if s == nil || s.state.Configuration == nil || !validHash(s.selector.Current) || !validHash(s.selection.State) || s.state.Generation == 0 {
		return SelectionReferenceV2{}, ErrRecovery
	}
	ref := SelectionReferenceV2{Selection: s.selector.Current, Previous: s.selector.Previous, State: s.selection.State, Lineage: s.state.Lineage, Sequence: s.selection.Sequence, Generation: s.state.Generation, Mode: "prepare"}
	if intent := s.state.Configuration.Intent; intent != nil {
		if intent.Domain != "routed" || !validHash(intent.RoutedWork) {
			return SelectionReferenceV2{}, ErrRecovery
		}
		ref.WorkHash, ref.Mode = intent.RoutedWork, "intent"
	} else if s.state.Configuration.Pending != nil {
		_, work, err := selectedPendingReadbackV2(s)
		if err != nil {
			return SelectionReferenceV2{}, err
		}
		ref.WorkHash, ref.Mode = work, "pending"
	} else if active := s.state.RoutedActive; active != nil {
		ref.WorkHash, ref.Mode = active.Work, "active"
	}
	return ref, nil
}
