package previewruntime

import (
	"context"
	"errors"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type routedIntegrityReaderV3 interface {
	CaptureReferenceV1(context.Context) (configpoc.SelectionReferenceV2, error)
	InspectQuiescentV1(context.Context, configpoc.SelectionReferenceV2) (configpoc.IntegrityResultV1, error)
}
type routedIntegrityFenceOpsV3 interface {
	Check() error
	MarkBlocked() error
}

// Implemented only by a selected-store reader with typed durable continuation
// validation. A shared work hash alone never grants the cold exception.
type routedColdContinuationV3 interface {
	ResolveColdContinuationV1(context.Context, firewallipc.RoutedReferenceV3, string) (configpoc.RoutedSelectedPlanV1, error)
}
type routedFencedContinuationV3 interface {
	ResolveFencedContinuationV1(context.Context, firewallipc.RoutedReferenceV3, string) (configpoc.RoutedSelectedPlanV1, error)
}

type routedIntegrityPhaseV3 string

const (
	routedIntegrityColdV3        routedIntegrityPhaseV3 = "cold"
	routedIntegrityReconcilingV3 routedIntegrityPhaseV3 = "reconciling"
	routedIntegrityCheckingV3    routedIntegrityPhaseV3 = "checking"
	routedIntegrityReadyV3       routedIntegrityPhaseV3 = "ready"
	routedIntegrityFencedV3      routedIntegrityPhaseV3 = "fenced"
)

type routedIntegrityGateV3 struct {
	mu                   sync.Mutex
	reader               routedIntegrityReaderV3
	source               RoutedSelectionSourceV3
	fence                routedIntegrityFenceOpsV3
	phase                routedIntegrityPhaseV3
	anchor, lastComplete configpoc.SelectionReferenceV2
}

func NewRoutedIntegritySessionV3(authority configpoc.RoutedAuthorityV1, source RoutedSelectionSourceV3, reader routedIntegrityReaderV3, fence routedIntegrityFenceOpsV3) (*RoutedSessionV3, error) {
	if reader == nil || fence == nil {
		return nil, ErrIdentity
	}
	s, err := NewRoutedSessionV3(authority, source)
	if err != nil {
		return nil, err
	}
	s.integrity = &routedIntegrityGateV3{reader: reader, source: source, fence: fence, phase: routedIntegrityColdV3}
	return s, nil
}
func (g *routedIntegrityGateV3) blockedLocked() bool {
	if g.fence.Check() != nil {
		g.phase = routedIntegrityFencedV3
	}
	return g.phase == routedIntegrityFencedV3
}
func (g *routedIntegrityGateV3) attach(ctx context.Context, expected configpoc.SelectionReferenceV2) (configpoc.IntegrityResultV1, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.blockedLocked()
	if g.phase == routedIntegrityCheckingV3 {
		return configpoc.IntegrityResultV1{State: configpoc.IntegrityUnavailableV1}, nil
	}
	current, err := g.reader.CaptureReferenceV1(ctx)
	if err != nil {
		return integrityIncompleteV3(ctx, current, err), nil
	}
	if current != expected {
		return configpoc.IntegrityResultV1{Selection: current, State: configpoc.IntegrityStaleV1}, nil
	}
	if capture, ok := g.source.(interface {
		CaptureColdAnchorV1(context.Context, configpoc.SelectionReferenceV2) error
	}); ok {
		if err := capture.CaptureColdAnchorV1(ctx, current); err != nil {
			return integrityIncompleteV3(ctx, current, err), nil
		}
	}
	g.anchor = current
	if g.phase == routedIntegrityColdV3 {
		g.phase = routedIntegrityReconcilingV3
	}
	// Attach is not a full scan or a supplied readiness flag. A surviving helper
	// retains its prior qualification; reconnect cannot reset its fence/anchor.
	// Complete here acknowledges capture only, bound to mode=attach on wire.
	// Neither the API adapter nor this method marks integrity ready.
	return configpoc.IntegrityResultV1{Selection: current, State: configpoc.IntegrityCompleteV1}, nil
}
func integrityIncompleteV3(ctx context.Context, selection configpoc.SelectionReferenceV2, err error) configpoc.IntegrityResultV1 {
	state := configpoc.IntegrityUnavailableV1
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		state = configpoc.IntegrityCancelledV1
	}
	return configpoc.IntegrityResultV1{Selection: selection, State: state}
}
func (g *routedIntegrityGateV3) inspect(ctx context.Context, expected configpoc.SelectionReferenceV2, authority configpoc.RoutedAuthorityV1) (configpoc.IntegrityResultV1, error) {
	g.mu.Lock()
	if g.blockedLocked() {
		g.mu.Unlock()
		return configpoc.IntegrityResultV1{State: configpoc.IntegrityFencedV1}, nil
	}
	if g.phase == routedIntegrityCheckingV3 || g.anchor == (configpoc.SelectionReferenceV2{}) {
		g.mu.Unlock()
		return configpoc.IntegrityResultV1{State: configpoc.IntegrityUnavailableV1}, nil
	}
	g.phase = routedIntegrityCheckingV3
	g.mu.Unlock()
	// Do not hold the gate mutex or any guardian lock during the full graph walk.
	// The sole API writer holds its publication barrier; helper dispatch ownership
	// independently prevents a replacement controller until this call drains.
	receipt, revision, err := authority.Observe(ctx)
	result := integrityIncompleteV3(ctx, configpoc.SelectionReferenceV2{}, err)
	if err == nil && integrityPhysicalIdleV3(receipt, revision) {
		result, err = g.reader.InspectQuiescentV1(ctx, expected)
		if !firewallipc.ValidRoutedIntegrityResultV3(result) {
			result = configpoc.IntegrityResultV1{State: configpoc.IntegrityUnavailableV1}
		}
		if err != nil && result.State != configpoc.IntegrityFencedV1 {
			result = integrityIncompleteV3(ctx, result.Selection, err)
		}
		if result.State == configpoc.IntegrityCompleteV1 {
			after, afterRevision, observeErr := authority.Observe(ctx)
			if observeErr != nil || !integrityPhysicalIdleV3(after, afterRevision) || after != receipt || afterRevision != revision || result.Selection != expected || ctx.Err() != nil {
				result = integrityIncompleteV3(ctx, result.Selection, observeErr)
			}
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.blockedLocked() {
		return configpoc.IntegrityResultV1{Selection: result.Selection, State: configpoc.IntegrityFencedV1}, nil
	}
	switch result.State {
	case configpoc.IntegrityCompleteV1:
		g.phase = routedIntegrityReadyV3
		g.lastComplete = result.Selection
	case configpoc.IntegrityFencedV1:
		g.phase = routedIntegrityFencedV3
		_ = g.fence.MarkBlocked()
	default:
		g.phase = routedIntegrityReconcilingV3
	}
	return result, nil
}
func (g *routedIntegrityGateV3) resolve(ctx context.Context, source RoutedSelectionSourceV3, ref firewallipc.RoutedReferenceV3, purpose string) (configpoc.RoutedSelectedPlanV1, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	blocked := g.blockedLocked()
	if g.phase == routedIntegrityCheckingV3 {
		return configpoc.RoutedSelectedPlanV1{}, ErrUnavailable
	}
	if !blocked && g.phase == routedIntegrityReadyV3 {
		plan, err := source.Resolve(ctx, ref, purpose)
		if err != nil {
			return plan, err
		}
		if g.blockedLocked() {
			return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrRecovery
		}
		return plan, nil
	}
	if blocked {
		fenced, ok := source.(routedFencedContinuationV3)
		if !ok || g.anchor == (configpoc.SelectionReferenceV2{}) {
			return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrRecovery
		}
		return fenced.ResolveFencedContinuationV1(ctx, ref, purpose)
	}
	continuation, ok := source.(routedColdContinuationV3)
	if !ok || g.anchor == (configpoc.SelectionReferenceV2{}) {
		return configpoc.RoutedSelectedPlanV1{}, configpoc.ErrRecovery
	}
	// The source must retain its own opaque, reader-issued cold anchor. The gate's
	// tuple above is correlation only and is deliberately not passed as authority.
	return continuation.ResolveColdContinuationV1(ctx, ref, purpose)
}

func integrityPhysicalIdleV3(receipt configpoc.RoutedReceiptV1, _ string) bool {
	// Observe independently validates actual owned state. Idle may retain the
	// original idempotent receipt; its historical deadline is not an active lease.
	// The full scan additionally requires this exact receipt/hash before and after.
	return receipt.Phase == "idle" || receipt.Phase == "bootstrap"
}
