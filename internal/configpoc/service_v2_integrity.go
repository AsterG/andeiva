package configpoc

import (
	"context"
	"sync/atomic"
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

type runtimeIntegrityStateV1 struct {
	inspecting atomic.Bool
	ready      bool // All remaining fields are protected by store.mu.
	fenced     bool
	checked    time.Time
	sequence   uint64
}

// InspectRuntimeV1 is called only by trusted runtime assembly. Holding the
// existing writer lock prevents catalogue, timer and execution publication
// throughout the independently authenticated helper inspection.
func (s *ServiceV2) InspectRuntimeV1(ctx context.Context) error {
	if s == nil || s.coordinator == nil || ctx == nil {
		return ErrInvalid
	}
	c := s.coordinator
	if c.options.Integrity == nil {
		return ErrInvalid
	}
	if !c.integrity.inspecting.CompareAndSwap(false, true) {
		return ErrConflict
	}
	defer c.integrity.inspecting.Store(false)
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked || c.integrity.fenced || !inspectionQuiescentV1(c.store.state) {
		return ErrRecovery
	}
	c.integrity.ready = false
	expected, err := selectedReferenceV2(c.store)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, IntegrityInspectionDeadlineV1)
	defer cancel()
	result, err := c.options.Integrity.Inspect(bounded, expected)
	if result.State == IntegrityFencedV1 {
		c.integrity.fenced = true
	}
	current, currentErr := selectedReferenceV2(c.store)
	if err != nil || bounded.Err() != nil || currentErr != nil || current != expected || result.Selection != expected || result.State != IntegrityCompleteV1 || c.integrity.fenced {
		return ErrRecovery
	}
	c.integrity.ready = true
	c.integrity.checked = c.now()
	c.integrity.sequence = expected.Sequence
	return nil
}

// Caller holds store.mu. Due inspections stop new work, never the independent
// guardian. An already admitted closing operation can retain its original
// recovery path while its selected lease prevents quiescent inspection.
func (c *v2Coordinator) integrityAllowsV1(closing bool) bool {
	if c.options.Integrity == nil {
		return true
	}
	i := &c.integrity
	if i.inspecting.Load() || !i.ready || i.fenced {
		return false
	}
	if closing && c.store.state.Configuration.Pending != nil {
		return true
	}
	now := c.now()
	sequence := c.store.selection.Sequence
	return !now.Before(i.checked) && now.Sub(i.checked) < IntegrityInspectionIntervalV1 && sequence >= i.sequence && sequence-i.sequence < IntegrityPublicationLimitV1
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
