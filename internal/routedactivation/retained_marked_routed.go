package routedactivation

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
	"github.com/AsterG/andeiva/internal/routednft"
)

var errMarkedClosureUnverified = errors.New("marked forwarding closure could not be verified")

type markedRoutedTransition struct {
	plan           configpoc.RoutedBootMarkPlanV1
	scope          networkexecutor.OwnedNamespaceIdentity
	before, target routedmodel.Revision
	forward, undo  routednft.Artifact
	applied        bool
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

// SelectBaselineAdmission expects the managed lease gate to remain closed
// through the first DHCP Open. No established WAN connection is re-marked.
func (e *Engine) SelectBaselineAdmission(ctx context.Context, running string, marks routedmodel.AdmissionMarks) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fenced || !e.selected || ctx.Err() != nil {
		return ErrState
	}
	owned, bundle, err := e.currentOwned(ctx)
	if err != nil || bundle == nil || bundle.Composite.Hash != running || owned.NetworkState != Configured ||
		bundle.Firewall.Config.Routed == nil {
		return ErrState
	}
	if e.admission != nil {
		if !equalAdmissionMarks(*e.admission, marks) {
			return ErrState
		}
		return nil
	}
	policy, err := routedmodel.Canonical(*bundle.Firewall.Config.Routed)
	if err != nil {
		return ErrState
	}
	compiled, err := routednft.CompileMarkedPolicy(policy, marks)
	if err != nil || e.kernel.Check(ctx, compiled.Batch) != nil {
		return ErrState
	}
	if e.kernel.Apply(ctx, compiled.Batch) != nil {
		e.fenced = true
		return ErrState
	}
	e.admission = &marks
	if !e.matches(ctx, owned, e.prepared.Dependencies) {
		e.fenced = true
		return ErrState
	}
	return nil
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
	assigned, _, err := routedmodel.ReserveAdmissionMarks(scope.BootID, marks.BaseIssued, marks.Prior, prior, next)
	if err != nil || !equalAdmissionMarks(assigned, marks.Applied) {
		return nil, ErrState
	}
	restored, _, err := routedmodel.ReserveAdmissionMarks(scope.BootID, assigned.Issued, &assigned, next, prior)
	if err != nil || !equalAdmissionMarks(restored, marks.Restored) {
		return nil, ErrState
	}
	forward, err := routednft.CompileHeldMarkedPolicy(next, assigned)
	if err != nil {
		return nil, ErrState
	}
	undo, err := routednft.CompileHeldMarkedPolicy(prior, restored)
	if err != nil {
		return nil, ErrState
	}
	return &markedRoutedTransition{plan: *marks, scope: scope, before: prior, target: next, forward: forward, undo: undo}, nil
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
	if restore {
		before, target = target, before
		previous, assigned = &m.plan.Applied, m.plan.Restored
		batch, origin, destination = m.undo.Batch, destination, origin
	}
	if !sameOptionalAdmissionMarks(e.admission, previous) ||
		!e.matches(ctx, origin, e.prepared.Dependencies) {
		if restore {
			return e.closeMarkedRoutedLocked(m)
		}
		return ErrState
	}
	hold := routednft.ForwardHold(true)
	if e.kernel.Check(ctx, hold) != nil || e.kernel.Check(ctx, batch) != nil || ctx.Err() != nil {
		if restore {
			return e.closeMarkedRoutedLocked(m)
		}
		return ErrState
	}
	if e.applyRuleHoldBatch(ctx, "rule_hold_close", hold) != nil || !e.markedForwardHeld(ctx, before, previous) {
		return e.closeMarkedRoutedLocked(m)
	}
	if e.applyRuleHoldBatch(ctx, "rule_hold_replace", batch) != nil || !e.markedForwardHeld(ctx, target, &assigned) {
		return e.closeMarkedRoutedLocked(m)
	}
	// Keep the independent DHCP gate intact. If its owner is renewing or
	// expires during this transaction it continues to deny forwarding after
	// the configuration barrier is removed.
	if e.network.Verify(ctx) != nil {
		return e.closeMarkedRoutedLocked(m)
	}
	release := routednft.ForwardHold(false)
	if e.kernel.Check(ctx, release) != nil || e.applyRuleHoldBatch(ctx, "rule_hold_release", release) != nil {
		return e.closeMarkedRoutedLocked(m)
	}
	e.admission = &assigned
	if !e.matches(ctx, destination, e.prepared.Dependencies) {
		return e.closeMarkedRoutedLocked(m)
	}
	m.applied = !restore
	return nil
}

func (e *Engine) applyRuleHoldBatch(ctx context.Context, phase string, batch []byte) error {
	if done := networkexecutor.StartNativeLeaseSpanV4(phase); done != nil {
		defer done()
	}
	return e.kernel.Apply(ctx, batch)
}

func (e *Engine) markedForwardHeld(ctx context.Context, revision routedmodel.Revision, marks *routedmodel.AdmissionMarks) bool {
	raw, present, err := e.kernel.Observe(ctx, RoutedTable)
	if err != nil || !present {
		return false
	}
	_, err = routednft.VerifyHeldObservation(raw, revision, marks)
	return err == nil && ctx.Err() == nil
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
