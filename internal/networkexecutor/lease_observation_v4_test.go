package networkexecutor

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type observationSourceFixtureV4 struct {
	observation        LeaseObservationV4
	effects            LeaseFact
	err, effectsErr    error
	calls, effectCalls int
	onRead             func(int)
}

func (s *observationSourceFixtureV4) read(context.Context) (LeaseObservationV4, error) {
	s.calls++
	if s.onRead != nil {
		s.onRead(s.calls)
	}
	return s.observation, s.err
}
func (s *observationSourceFixtureV4) current(context.Context) (LeaseFact, error) {
	s.effectCalls++
	return s.effects, s.effectsErr
}

func observationFixtureV4(t *testing.T, enabled bool) (*LANBootstrapV3, *LeaseExecutor, *fakeKernel, *observationSourceFixtureV4) {
	t.Helper()
	ctx := context.Background()
	b, k, options, _ := bootstrapFixtureV3(t)
	fact, err := options.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := &observationSourceFixtureV4{effects: fact, observation: LeaseObservationV4{Epoch: 10, Fact: fact}}
	options.Current = s.current
	if enabled {
		options.GetObservationV4 = s.read
	}
	prepared, err := b.Prepare(ctx, options.Desired)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.ApplyPrepared(ctx, options.Desired, prepared); err != nil {
		t.Fatal(err)
	}
	l, err := b.OpenLease(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	if out, e := l.Refresh(ctx); e != nil || out != LeaseApplied {
		t.Fatal(out, e)
	}
	return b, l, k, s
}

func TestLeaseObservationV4StableAndPendingAreReadOnlyAndSeparate(t *testing.T) {
	ctx := context.Background()
	b, l, k, s := observationFixtureV4(t, true)
	retained, seen, mutations, physical := l.fact, l.seen, k.mutations, cloneObservationTestV3(k.state)
	if err := b.VerifyObservationV4(ctx); err != nil {
		t.Fatal("unchanged valid fact", err)
	}
	s.observation.Epoch++
	s.observation.Fact.Sequence++
	s.observation.Fact.DeadlineBootNS += int64(10 * time.Second)
	// Effect Current is intentionally unavailable. Observation must use only
	// its separately provisioned read callback and must not refresh authority.
	s.effectsErr = ErrLeaseUnavailable
	effectCalls := s.effectCalls
	err := b.VerifyObservationV4(ctx)
	if err == nil || !IsLeaseObservationPendingV4(err) || !MatchesLeaseObservationPendingV4(err, retained) || s.effectCalls != effectCalls {
		t.Fatal("pending observation became authority or reused effect Current", err)
	}
	wrong := retained
	wrong.Sequence++
	if MatchesLeaseObservationPendingV4(err, wrong) || l.fact != retained || l.seen != seen || k.mutations != mutations || !reflect.DeepEqual(k.state, physical) || l.base.fenced {
		t.Fatal("pending witness binding or read-only invariant failed")
	}
	if IsLeaseObservationPendingV4(&leaseObservationPendingV4{}) {
		t.Fatal("zero witness accepted")
	}
}

type observationErrorAsFixtureV4 struct{ pending error }

func (observationErrorAsFixtureV4) Error() string { return "generic failure" }
func (e observationErrorAsFixtureV4) As(target any) bool {
	p, ok := target.(**leaseObservationPendingV4)
	if ok {
		*p = e.pending.(*leaseObservationPendingV4)
	}
	return ok
}

func TestLeaseObservationV4RawClassifierRejectsWrappedOrJoinedFailures(t *testing.T) {
	_, l, _, _ := observationFixtureV4(t, true)
	pending := NewLeaseObservationPendingV4(l.fact)
	if !IsLeaseObservationPendingV4(pending) || !MatchesLeaseObservationPendingV4(pending, l.fact) {
		t.Fatal("direct witness rejected")
	}
	var typedNil *leaseObservationPendingV4
	for _, err := range []error{nil, typedNil, ErrScope, errors.Join(ErrScope, pending), errors.Join(pending, ErrScope), errors.Join(pending), fmt.Errorf("generic: %w", pending), observationErrorAsFixtureV4{pending}} {
		if IsLeaseObservationPendingV4(err) || MatchesLeaseObservationPendingV4(err, l.fact) {
			t.Fatal("indirect source failure acquired raw pending classification", err)
		}
	}
}

func TestLeaseObservationV4DefaultOffKeepsLegacyRejection(t *testing.T) {
	ctx := context.Background()
	b, l, k, s := observationFixtureV4(t, false)
	s.effects.Sequence++
	s.effects.DeadlineBootNS += int64(time.Second)
	mutations := k.mutations
	for _, verify := range []func(context.Context) error{l.Verify, l.VerifyObservationV4, b.Verify, b.VerifyObservationV4} {
		if err := verify(ctx); !errors.Is(err, ErrScope) || IsLeaseObservationPendingV4(err) {
			t.Fatal("legacy behavior changed", err)
		}
	}
	if s.calls != 0 || k.mutations != mutations {
		t.Fatal("default-off introduced observation work or effects")
	}
}

func TestLeaseObservationV4RejectsNonPendingOrUnstableEvidence(t *testing.T) {
	for _, mode := range []string{"replay", "sequence-zero", "owner", "boot", "run", "desired", "wan", "address", "gateway", "revoked", "expired", "expired-during-read", "clock-regression", "deadline-zero", "deadline-large", "generic", "no-lease", "unstable-fact", "unstable-epoch", "drift", "drift-during-read", "cancel", "lifetime", "late-lifetime", "fenced", "retained-seen", "retained-identity", "callback-witness"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, l, k, s := observationFixtureV4(t, true)
			s.observation.Epoch++
			s.observation.Fact.Sequence++
			s.observation.Fact.DeadlineBootNS += int64(time.Second)
			switch mode {
			case "replay":
				s.observation.Fact.Sequence = l.fact.Sequence
			case "sequence-zero":
				s.observation.Fact.Sequence = 0
			case "owner":
				s.observation.Fact.Owner.Incarnation = strings.Repeat("c", 32)
			case "boot":
				s.observation.Fact.Owner.BootID = "00000000-0000-0000-0000-000000000000"
			case "run":
				s.observation.Fact.Owner.RunID = strings.Repeat("c", 32)
			case "desired":
				s.observation.Fact.DesiredHash = strings.Repeat("c", 64)
			case "wan":
				s.observation.Fact.WAN.HardwareAddress = "02:00:00:00:00:ff"
			case "address":
				s.observation.Fact.Address = "198.19.0.3/24"
			case "gateway":
				s.observation.Fact.Gateway = "198.19.0.3"
			case "revoked":
				s.observation.Fact.Revoked = true
			case "expired":
				s.observation.Fact.DeadlineBootNS = int64(time.Second)
			case "expired-during-read":
				s.onRead = func(call int) {
					if call == 2 {
						l.now = func() (int64, error) { return s.observation.Fact.DeadlineBootNS, nil }
					}
				}
			case "clock-regression":
				s.onRead = func(call int) {
					if call == 2 {
						l.now = func() (int64, error) { return 1, nil }
					}
				}
			case "deadline-zero":
				s.observation.Fact.DeadlineBootNS = 0
			case "deadline-large":
				s.observation.Fact.DeadlineBootNS = int64(8 * 24 * time.Hour)
			case "generic":
				s.err = errors.New("source unavailable")
			case "no-lease":
				s.err = ErrLeaseUnavailable
			case "unstable-fact":
				s.onRead = func(call int) {
					if call == 2 {
						s.observation.Fact.Sequence++
					}
				}
			case "unstable-epoch":
				s.onRead = func(call int) {
					if call == 2 {
						s.observation.Epoch++
					}
				}
			case "drift":
				k.state.Routes = nil
			case "drift-during-read":
				run := l.base.run
				reads := 0
				l.base.run = func(c context.Context, op operation) ([]byte, error) {
					raw, e := run(c, op)
					if op.kind == "routes" {
						reads++
						if reads == 1 {
							k.state.Links[0].MTU++
						}
					}
					return raw, e
				}
			case "cancel":
				s.onRead = func(call int) {
					if call == 2 {
						cancel()
					}
				}
			case "lifetime":
				l.base.lifetime = ctx
				cancel()
			case "late-lifetime":
				life, stop := context.WithCancel(context.Background())
				defer stop()
				l.base.lifetime = life
				s.onRead = func(call int) {
					if call == 2 {
						stop()
					}
				}
			case "fenced":
				l.base.fenced = true
			case "retained-seen":
				l.seen++
			case "retained-identity":
				copy := *l.base.identity
				copy.RunID = strings.Repeat("c", 32)
				l.base.identity = &copy
			case "callback-witness":
				s.err = errors.Join(ErrLeaseUnavailable, NewLeaseObservationPendingV4(l.fact))
			}
			mutations, retained, seen, fenced := k.mutations, l.fact, l.seen, l.base.fenced
			err := l.VerifyObservationV4(ctx)
			if err == nil || IsLeaseObservationPendingV4(err) || k.mutations != mutations || l.fact != retained || l.seen != seen || l.base.fenced != fenced {
				t.Fatal("unproven evidence acquired pending witness or caused effects", mode, err)
			}
		})
	}
}

func TestLeaseObservationV4PendingFactoryOnlyReturnsBoundClosureError(t *testing.T) {
	_, l, _, _ := observationFixtureV4(t, true)
	retained := l.fact
	for _, mode := range []string{"valid", "expired-retained", "zero", "revoked", "deadline", "owner", "sequence", "hash", "address", "gateway", "off-link", "name", "mac"} {
		fact := retained
		switch mode {
		case "expired-retained":
			fact.DeadlineBootNS = 1
		case "zero":
			fact = LeaseFact{}
		case "revoked":
			fact.Revoked = true
		case "deadline":
			fact.DeadlineBootNS = 0
		case "owner":
			fact.Owner.PID = 0
		case "sequence":
			fact.Sequence = 0
		case "hash":
			fact.DesiredHash = "bad"
		case "address":
			fact.Address = "198.19.0.0/24"
		case "gateway":
			fact.Gateway = "198.19.0.255"
		case "off-link":
			fact.Gateway = "198.18.0.1"
		case "name":
			fact.WAN.Name = "lo"
		case "mac":
			fact.WAN.HardwareAddress = "01:00:00:00:00:01"
		}
		err := NewLeaseObservationPendingV4(fact)
		valid := mode == "valid" || mode == "expired-retained"
		if err == nil || IsLeaseObservationPendingV4(err) != valid || valid && !MatchesLeaseObservationPendingV4(err, fact) || !valid && !errors.Is(err, ErrScope) {
			t.Fatal("factory produced authority or accepted malformed shape", mode, err)
		}
	}
}

func TestLeaseObservationV4FreshCurrentAfterOldDeadlineRemainsClosureOnly(t *testing.T) {
	_, l, k, s := observationFixtureV4(t, true)
	retained, seen, mutations := l.fact, l.seen, k.mutations
	l.now = func() (int64, error) { return retained.DeadlineBootNS + 1, nil }
	s.observation.Epoch++
	s.observation.Fact.Sequence++
	s.observation.Fact.DeadlineBootNS += int64(time.Minute)
	err := l.VerifyObservationV4(context.Background())
	if !MatchesLeaseObservationPendingV4(err, retained) || l.fact != retained || l.seen != seen || k.mutations != mutations {
		t.Fatal("fresh progress extended expired retained authority", err)
	}
}

func TestLeaseObservationV4RecoveryPropagatesOptionalSource(t *testing.T) {
	_, l, k, s := observationFixtureV4(t, true)
	ctx := context.Background()
	snapshot, err := l.PrepareSelectedSnapshotV3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := &Executor{lifetime: l.base.lifetime, run: l.base.run, identity: l.base.identity}
	options := LeaseOptions{Desired: l.desired, Owner: l.owner, Current: s.current, GetObservationV4: s.read}
	mutations := k.mutations
	recovered, _, err := recoverLeaseSelectedV3(ctx, base, options, snapshot, l.now)
	if err != nil || recovered.getObservationV4 == nil || recovered.VerifyObservationV4(ctx) != nil || k.mutations != mutations {
		t.Fatal("recovery dropped optional observation or changed L3", err)
	}
}

func TestLeaseMarginObservationV4ConstructorRejectsMalformedAssociation(t *testing.T) {
	_, l, _, _ := observationFixtureV4(t, true)
	for _, mode := range []string{"epoch", "hash", "owner", "boot", "run", "address-zero", "address-network", "address-broadcast", "ipv6", "prefix31", "noncanonical"} {
		owner, hash, epoch, address := l.owner, l.desired.Hash, uint64(11), l.fact.Address
		switch mode {
		case "epoch":
			epoch = 0
		case "hash":
			hash = "bad"
		case "owner":
			owner.PID = 0
		case "boot":
			owner.BootID = "bad"
		case "run":
			owner.RunID = "bad"
		case "address-zero":
			address = "0.0.0.0/24"
		case "address-network":
			address = "198.19.0.0/24"
		case "address-broadcast":
			address = "198.19.0.255/24"
		case "ipv6":
			address = "2001:db8::1/64"
		case "prefix31":
			address = "198.19.0.1/31"
		case "noncanonical":
			address = "198.19.0.1/024"
		}
		if marker, err := NewLeaseMarginObservationV4(owner, hash, epoch, address); err == nil || marker != nil {
			t.Fatal("invalid closure association admitted", mode)
		}
	}
}

func TestLeaseObservationV4StableMarginNeverBecomesLeaseFact(t *testing.T) {
	for _, mode := range []string{"valid", "old-deadline", "mixed-union", "epoch-mismatch", "wrong-owner", "wrong-address", "wrong-desired", "unstable", "zero-marker"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			b, l, k, s := observationFixtureV4(t, true)
			owner, address, hash := l.owner, l.fact.Address, l.desired.Hash
			if mode == "wrong-owner" {
				owner.Incarnation = strings.Repeat("c", 32)
			}
			if mode == "wrong-address" {
				address = "198.19.0.3/24"
			}
			if mode == "wrong-desired" {
				hash = strings.Repeat("c", 64)
			}
			marker, err := NewLeaseMarginObservationV4(owner, hash, 11, address)
			if err != nil {
				t.Fatal(err)
			}
			s.observation = LeaseObservationV4{Epoch: 11, Margin: marker}
			switch mode {
			case "old-deadline":
				l.now = func() (int64, error) { return l.fact.DeadlineBootNS + 1, nil }
			case "mixed-union":
				s.observation.Fact = l.fact
			case "epoch-mismatch":
				s.observation.Epoch++
			case "unstable":
				s.onRead = func(call int) {
					if call == 2 {
						s.observation.Epoch++
					}
				}
			case "zero-marker":
				s.observation.Margin = &LeaseMarginObservationV4{}
			}
			mutations, retained, seen := k.mutations, l.fact, l.seen
			err = b.VerifyObservationV4(ctx)
			wantPending := mode == "valid" || mode == "old-deadline"
			if err == nil || IsLeaseObservationPendingV4(err) != wantPending || wantPending && !MatchesLeaseObservationPendingV4(err, retained) || k.mutations != mutations || l.fact != retained || l.seen != seen || l.base.fenced {
				t.Fatal("margin became authority or bypassed scope", mode, err)
			}
		})
	}
}
