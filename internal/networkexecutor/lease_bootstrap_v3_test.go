package networkexecutor

import (
	"context"
	"reflect"
	"testing"
)

func bootstrapFixtureV3(t *testing.T) (*LANBootstrapV3, *fakeKernel, LeaseOptions, *bool) {
	t.Helper()
	base, k, opts, _, now := leaseInputs(t)
	if _, err := k.run(context.Background(), operation{kind: "address-delete", name: "lan0", address: "198.18.0.1/24"}); err != nil {
		t.Fatal(err)
	}
	k.mutations = 0
	closed := true
	guard := func() error {
		if !closed {
			return ErrScope
		}
		return nil
	}
	run := base.run
	base.run = func(ctx context.Context, op operation) ([]byte, error) {
		switch op.kind {
		case "links", "addresses", "routes", "rules":
		default:
			if err := guard(); err != nil {
				return nil, err
			}
		}
		return run(ctx, op)
	}
	b, err := newLANBootstrapV3(base, opts.Desired, func() (int64, error) { return *now, nil }, guard)
	if err != nil {
		t.Fatal(err)
	}
	return b, k, opts, &closed
}

func TestLANBootstrapV3OnlyLANThenLeaseThenOriginalEmptyBaseline(t *testing.T) {
	b, k, opts, closed := bootstrapFixtureV3(t)
	original := cloneObservationTestV3(k.state)
	s, err := b.Prepare(context.Background(), opts.Desired)
	if err != nil || k.mutations != 0 {
		t.Fatal("prepare", err)
	}
	if err = b.ApplyPrepared(context.Background(), opts.Desired, s); err != nil || k.mutations != 1 {
		t.Fatal("LAN apply", err)
	}
	if len(k.state.Links[1].Addresses) != 0 || b.Verify(context.Background()) != nil {
		t.Fatal("WAN changed at boot")
	}
	l, err := b.OpenLease(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	*closed = false
	if b.Verify(context.Background()) != nil {
		t.Fatal("read-only live verification requires forwarding disabled")
	}
	before := k.mutations
	if b.RestorePrepared(context.Background(), s) == nil || b.ReleaseLease(context.Background()) == nil || k.mutations != before {
		t.Fatal("live WAN/LAN removed")
	}
	*closed = true
	if _, err = l.WithdrawSelectedV3(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.ReleaseLease(context.Background()) != nil || b.RestorePrepared(context.Background(), s) != nil || !reflect.DeepEqual(k.state, original) {
		t.Fatal("baseline not restored")
	}
}

func cloneObservationTestV3(o observation) observation {
	copy := observation{Links: append([]link{}, o.Links...), Routes: append([]route{}, o.Routes...)}
	for i := range copy.Links {
		copy.Links[i].Flags = append([]string{}, o.Links[i].Flags...)
		copy.Links[i].Addresses = append([]address{}, o.Links[i].Addresses...)
	}
	return copy
}

func TestLANBootstrapV3ScopeDriftAndClosedForwarding(t *testing.T) {
	for _, mode := range []string{"wan-occupied", "lan-occupied", "link-replaced", "forward-open", "apply-error-after-effect"} {
		t.Run(mode, func(t *testing.T) {
			b, k, opts, closed := bootstrapFixtureV3(t)
			s, err := b.Prepare(context.Background(), opts.Desired)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "wan-occupied":
				_, err = k.run(context.Background(), operation{kind: "address-add", name: "wan0", address: "198.19.0.3/24"})
			case "lan-occupied":
				_, err = k.run(context.Background(), operation{kind: "address-add", name: "lan0", address: "198.18.0.3/24"})
			case "link-replaced":
				k.state.Links[0].Index++
			case "forward-open":
				*closed = false
			case "apply-error-after-effect":
				k.failAt = 1
				k.afterEffect = true
			}
			if err != nil {
				t.Fatal(err)
			}
			before := k.mutations
			if b.ApplyPrepared(context.Background(), opts.Desired, s) == nil {
				t.Fatal("invalid apply accepted")
			}
			if mode == "apply-error-after-effect" {
				if !k.state.empty() {
					t.Fatal("partial LAN survived compensation")
				}
			} else if k.mutations != before {
				t.Fatal("foreign mutation")
			}
		})
	}
}

func TestLANBootstrapV3RecoveryNeverAdoptsWAN(t *testing.T) {
	b, k, opts, _ := bootstrapFixtureV3(t)
	s, err := b.Prepare(context.Background(), opts.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.ApplyPrepared(context.Background(), opts.Desired, s); err != nil {
		t.Fatal(err)
	}
	base := &Executor{lifetime: b.base.lifetime, run: b.base.run, identity: b.base.identity}
	recovered, err := newLANBootstrapV3(base, opts.Desired, b.now, b.closedForwarding)
	if err != nil {
		t.Fatal(err)
	}
	before := k.mutations
	if recovered.RecoverPrepared(context.Background(), opts.Desired, s, *base.identity) != nil || k.mutations != before {
		t.Fatal("LAN recovery")
	}
	_, err = k.run(context.Background(), operation{kind: "address-add", name: "wan0", address: "198.19.0.3/24"})
	if err != nil {
		t.Fatal(err)
	}
	base = &Executor{lifetime: b.base.lifetime, run: b.base.run, identity: b.base.identity}
	other, err := newLANBootstrapV3(base, opts.Desired, b.now, b.closedForwarding)
	if err != nil {
		t.Fatal(err)
	}
	before = k.mutations
	if other.RecoverPrepared(context.Background(), opts.Desired, s, *base.identity) == nil || k.mutations != before {
		t.Fatal("WAN adopted")
	}
}

func TestLANBootstrapV3SelectedWANRecoveryDoesNotConferLANOwnership(t *testing.T) {
	b, k, opts, _ := bootstrapFixtureV3(t)
	ctx := context.Background()
	s, err := b.Prepare(ctx, opts.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.ApplyPrepared(ctx, opts.Desired, s); err != nil {
		t.Fatal(err)
	}
	l, err := b.OpenLease(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := l.PrepareSelectedSnapshotV3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	base := &Executor{lifetime: b.base.lifetime, run: b.base.run, identity: b.base.identity}
	recovered, err := newLANBootstrapV3(base, opts.Desired, b.now, b.closedForwarding)
	if err != nil {
		t.Fatal(err)
	}
	before := k.mutations
	wan, err := recovered.RecoverSelectedLeaseV3(ctx, opts, selected)
	if err != nil || k.mutations != before || base.active != nil {
		t.Fatal("read-only WAN reconstruction adopted LAN", err)
	}
	if _, err = wan.WithdrawSelectedV3(ctx); err != nil {
		t.Fatal(err)
	}
	if err = recovered.ReleaseLease(ctx); err != nil {
		t.Fatal(err)
	}
	before = k.mutations
	if recovered.RestorePrepared(ctx, s) == nil || k.mutations != before {
		t.Fatal("LAN removed without selected Boot ownership")
	}
	if err = recovered.RecoverPrepared(ctx, opts.Desired, s, *base.identity); err != nil {
		t.Fatal(err)
	}
	if err = recovered.RestorePrepared(ctx, s); err != nil || !k.state.empty() {
		t.Fatal("selected LAN not restored", err)
	}
}
