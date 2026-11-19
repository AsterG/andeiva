package routedactivation

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedflow"
	"github.com/AsterG/andeiva/internal/routedmodel"
	"github.com/AsterG/andeiva/internal/routednft"
)

var errMarkedClosureUnverified = errors.New("marked forwarding closure could not be verified")

type markedRoutedTransition struct {
	plan                          configpoc.RoutedBootMarkPlanV1
	scope                         networkexecutor.OwnedNamespaceIdentity
	before, target                routedmodel.Revision
	forward, undo                 routednft.Artifact
	closeForForward, closeForUndo bool
	applied                       bool
	applyCleanup, undoCleanup     *configpoc.RoutedConntrackCleanupV1
}

func equalAdmissionMarks(a, b routedmodel.AdmissionMarks) bool {
	return a.Boot == b.Boot && a.Revision == b.Revision && a.Issued == b.Issued && slices.Equal(a.Bindings, b.Bindings)
}

func sameOptionalAdmissionMarks(a, b *routedmodel.AdmissionMarks) bool {
	if a == nil || b == nil {
		return a == b
	}
	return equalAdmissionMarks(*a, *b)
}

func (e *Engine) resolveMarkedRoutedTransition(ctx context.Context, transition configpoc.RoutedTransitionV1, deadline time.Time, prepared PreparationV1) (*markedRoutedTransition, error) {
	if e.options.ResolveAdmissionMarks == nil {
		return nil, nil
	}
	marks, scope, err := e.options.ResolveAdmissionMarks(ctx, transition, deadline)
	if err != nil {
		return nil, ErrState
	}
	if marks == nil {
		if e.admission != nil {
			return nil, ErrState
		}
		return nil, nil
	}
	before, target := prepared.Before, prepared.Target
	if !sameOptionalAdmissionMarks(e.admission, marks.Prior) || scope.Namespace == 0 || scope.Host == 0 ||
		scope.Namespace == scope.Host || before.NetworkState != Configured || target.NetworkState != Configured ||
		!sameArtifact(before.LegacyFirewall, target.LegacyFirewall) || !sameArtifact(before.LocalServices, target.LocalServices) ||
		before.RoutedFirewall.Revision == nil || before.RoutedFirewall.Revision.Config.Routed == nil ||
		target.RoutedFirewall.Revision == nil || target.RoutedFirewall.Revision.Config.Routed == nil {
		return nil, ErrState
	}
	prior, err := routedmodel.Canonical(*before.RoutedFirewall.Revision.Config.Routed)
	if err != nil {
		return nil, ErrState
	}
	next, err := routedmodel.Canonical(*target.RoutedFirewall.Revision.Config.Routed)
	if err != nil || prior.Hash == next.Hash || prior.Policy.Network.Hash != next.Policy.Network.Hash || !slices.Equal(prior.Policy.NAT, next.Policy.NAT) ||
		!sameArtifact(prior.Policy.DHCPServer, next.Policy.DHCPServer) {
		return nil, ErrState
	}
	assigned, closeForForward, err := routedmodel.ReserveAdmissionMarks(scope.BootID, marks.BaseIssued, marks.Prior, prior, next)
	if err != nil || !equalAdmissionMarks(assigned, marks.Applied) {
		return nil, ErrState
	}
	restored, closeForUndo, err := routedmodel.ReserveAdmissionMarks(scope.BootID, assigned.Issued, &assigned, next, prior)
	if err != nil || !equalAdmissionMarks(restored, marks.Restored) {
		return nil, ErrState
	}
	forward, err := routednft.CompileMarkedPolicy(next, assigned)
	if err != nil {
		return nil, ErrState
	}
	undo, err := routednft.CompileMarkedPolicy(prior, restored)
	if err != nil {
		return nil, ErrState
	}
	return &markedRoutedTransition{plan: *marks, scope: scope, before: prior, target: next, forward: forward, undo: undo,
		closeForForward: marks.Prior == nil || closeForForward, closeForUndo: closeForUndo}, nil
}

func (e *Engine) applyMarkedRoutedLocked(ctx context.Context, restore bool) error {
	m := e.marked
	if restore && !m.applied {
		if e.matches(ctx, e.prepared.Before, e.prepared.Dependencies) {
			return nil
		}
		return e.closeMarkedRoutedLocked(m)
	}
	before, target := m.before, m.target
	previous, assigned := m.plan.Prior, m.plan.Applied
	batch, origin, destination := m.forward.Batch, e.prepared.Before, e.prepared.Target
	watermark := m.plan.BaseIssued
	needsClosure := m.closeForForward
	if restore {
		before, target = target, before
		previous, assigned = &m.plan.Applied, m.plan.Restored
		batch, origin, destination = m.undo.Batch, destination, origin
		watermark = previous.Issued
		needsClosure = m.closeForUndo
	}
	if !sameOptionalAdmissionMarks(e.admission, previous) ||
		!e.matches(ctx, origin, e.prepared.Dependencies) {
		if restore {
			return e.closeMarkedRoutedLocked(m)
		}
		return ErrState
	}
	var retirement *routedflow.Retirement
	var err error
	if previous != nil {
		retirement, err = routedflow.NewRetirement(e.plan.Operation, m.scope.Namespace, m.scope.Host, before, target, *previous, assigned, watermark)
	}
	if err != nil || e.kernel.Check(ctx, batch) != nil || ctx.Err() != nil {
		if restore {
			return e.closeMarkedRoutedLocked(m)
		}
		return ErrState
	}
	if needsClosure && e.denyMarkedRoutedLocked(ctx, m) != nil {
		return e.closeMarkedRoutedLocked(m)
	}
	if e.kernel.Apply(ctx, batch) != nil {
		return e.closeMarkedRoutedLocked(m)
	}
	e.admission = &assigned
	// Deletion assumes that the new policy already rejects the retired marks.
	// Confirm that prerequisite before touching any tracked connection.
	loaded, exists, err := e.kernel.Observe(ctx, RoutedTable)
	if err != nil || !exists {
		return e.closeMarkedRoutedLocked(m)
	}
	if _, err = routednft.VerifyRetainedWANObservation(loaded, target, assigned); err != nil {
		return e.closeMarkedRoutedLocked(m)
	}
	summary := &configpoc.RoutedConntrackCleanupV1{Operation: e.plan.Operation, Partial: true}
	if retirement != nil {
		result, err := e.retireMarked(retirement, ctx)
		if err != nil || result.Operation != e.plan.Operation || result.Retired < 0 || result.Retired > routedflow.MaxRetirements {
			return e.closeMarkedRoutedLocked(m)
		}
		summary.Retired, summary.Partial = uint16(result.Retired), result.Limited
	}
	if !e.matches(ctx, destination, e.prepared.Dependencies) {
		return e.closeMarkedRoutedLocked(m)
	}
	m.applied = !restore
	if restore {
		m.undoCleanup = summary
	} else {
		m.applyCleanup = summary
	}
	return nil
}

// The closure is a separate safety effect for an uncertain kernel mutation.
// Its policy retains the WAN acquisition, local ingress and original timer.
func (e *Engine) closeMarkedRoutedLocked(m *markedRoutedTransition) error {
	e.fenced = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := e.denyMarkedRoutedLocked(ctx, m); err != nil {
		return errors.Join(ErrState, errMarkedClosureUnverified, err)
	}
	return ErrState
}

func (e *Engine) denyMarkedRoutedLocked(ctx context.Context, m *markedRoutedTransition) error {
	deny := m.target.Policy
	deny.Rules = nil
	revision, err := routedmodel.Canonical(deny)
	if err != nil {
		return err
	}
	marks := routedmodel.AdmissionMarks{Boot: m.scope.BootID, Revision: revision.Hash, Issued: m.plan.Restored.Issued}
	artifact, err := routednft.CompileMarkedPolicy(revision, marks)
	if err != nil || e.kernel.Check(ctx, artifact.Batch) != nil || e.kernel.Apply(ctx, artifact.Batch) != nil {
		return ErrState
	}
	raw, exists, err := e.kernel.Observe(ctx, RoutedTable)
	if err != nil || !exists {
		return ErrState
	}
	if _, err = routednft.VerifyRetainedWANObservation(raw, revision, marks); err != nil {
		return err
	}
	return ctx.Err()
}
