package networkexecutor

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Reproduces the current strict generic observation contract. The kernel is an
// explicit double; LANBootstrapV3, LeaseExecutor and their Verify methods are
// real. A new same-effective grant is not interchangeable with retained proof.
func TestLeaseRenewalObservationV4LegacyVerifyRejectsUnrefreshedGrant(t *testing.T) {
	ctx := context.Background()
	bootstrap, k, options, _ := bootstrapFixtureV3(t)
	current, err := options.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	options.Current = func(context.Context) (LeaseFact, error) { return current, nil }
	prepared, err := bootstrap.Prepare(ctx, options.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if err = bootstrap.ApplyPrepared(ctx, options.Desired, prepared); err != nil {
		t.Fatal(err)
	}
	lease, err := bootstrap.OpenLease(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, e := lease.Refresh(ctx); e != nil || outcome != LeaseApplied {
		t.Fatal("initial lease", outcome, e)
	}
	previous, err := lease.PrepareSelectedSnapshotV3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Verify(ctx) != nil || bootstrap.Verify(ctx) != nil {
		t.Fatal("initial grant did not verify")
	}
	physical := cloneObservationTestV3(k.state)
	mutations, retained := k.mutations, lease.fact
	current.Sequence++
	current.DeadlineBootNS += int64(10 * time.Second)
	if current.Owner != retained.Owner || current.Address != retained.Address || current.Gateway != retained.Gateway {
		t.Fatal("fixture changed effective network or owner")
	}
	for name, verify := range map[string]func(context.Context) error{"lease": lease.Verify, "LAN bootstrap": bootstrap.Verify} {
		if err = verify(ctx); !errors.Is(err, ErrScope) {
			t.Fatalf("%s accepted stale retained authority or returned another class: %v", name, err)
		}
	}
	if k.mutations != mutations || !reflect.DeepEqual(k.state, physical) || lease.fact != retained || lease.seen != retained.Sequence {
		t.Fatal("read-only rejection changed physical state or refreshed authority")
	}
	next, err := lease.PrepareSelectedSnapshotV3(ctx)
	if err != nil || ValidateSameEffectiveLeaseV4(previous, next) != nil {
		t.Fatal("fresh grant not same effective lease", err)
	}
	if err = lease.RefreshSameEffectiveSelectedV4(ctx, previous, next); err != nil {
		t.Fatal("explicit evidence refresh", err)
	}
	if lease.fact != current || lease.seen != current.Sequence || lease.Verify(ctx) != nil || bootstrap.Verify(ctx) != nil {
		t.Fatal("refreshed retained evidence did not verify")
	}
	if k.mutations != mutations || !reflect.DeepEqual(k.state, physical) {
		t.Fatal("evidence-only refresh mutated L3")
	}
	t.Log("Legacy generic Verify rejects an unrefreshed same-effective grant with ErrScope; explicit V4 evidence refresh restores verification without L3 writes. This is a reproducer, not end-to-end V4 qualification.")
}
