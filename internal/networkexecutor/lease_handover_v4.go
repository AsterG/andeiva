package networkexecutor

import (
	"context"
	"reflect"
)

// ValidateSameEffectiveLeaseV4 checks a renewal's immutable effective delta.
// It grants no authority: callers must independently authenticate both selected
// works, current owner evidence, gate closure and the new absolute deadline.
// Only sequence, deadline and their digest may change. A shorter fresh lease is
// legal; this function never manufactures a minimum or extends either deadline.
func ValidateSameEffectiveLeaseV4(previous, next LeaseSelectedSnapshotV3) error {
	p, err := CanonicalLeaseSelectedSnapshotV3(previous)
	if err != nil {
		return ErrScope
	}
	n, err := CanonicalLeaseSelectedSnapshotV3(next)
	if err != nil || n.Sequence <= p.Sequence {
		return ErrScope
	}
	p.Sequence, n.Sequence = 0, 0
	p.DeadlineBootNS, n.DeadlineBootNS = 0, 0
	p.Hash, n.Hash = "", ""
	if !reflect.DeepEqual(p, n) {
		return ErrScope
	}
	return nil
}

// RefreshSameEffectiveSelectedV4 replaces only retained owner evidence. The
// caller authenticates selected cleanup authority and closes its lease gate
// and forwarding first. This method independently requires exact existing
// L3, the original baseline and a fresh owner grant; it never adds or removes
// an address/route and never changes the selected work or its R2 plan.
// On any error the caller must keep the gate closed and reconcile withdrawal.
func (l *LeaseExecutor) RefreshSameEffectiveSelectedV4(ctx context.Context, previous, next LeaseSelectedSnapshotV3) error {
	if l == nil || l.base == nil || ctx == nil || ctx.Err() != nil || ValidateSameEffectiveLeaseV4(previous, next) != nil {
		return ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.base.identity == nil || l.base.active == nil || previous.Identity != *l.base.identity || previous.Desired.Hash != l.desired.Hash || previous.Fact() != l.fact || previous.Sequence != l.seen || !reflect.DeepEqual(observation{Links: previous.Links, Routes: previous.Routes}, l.baseline) {
		return ErrScope
	}
	if err := l.base.ready(ctx); err != nil {
		return err
	}
	if err := l.guard(ctx); err != nil {
		return err
	}
	if err := l.sameFact(ctx, next.Fact()); err != nil {
		return err
	}
	if err := l.observeExpected(ctx); err != nil {
		return err
	}
	if err := l.guard(ctx); err != nil {
		return err
	}
	if err := l.sameFact(ctx, next.Fact()); err != nil {
		return err
	}
	if err := l.observeExpected(ctx); err != nil {
		return err
	}
	if err := l.sameFact(ctx, next.Fact()); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	l.fact, l.seen = next.Fact(), next.Sequence
	return nil
}
