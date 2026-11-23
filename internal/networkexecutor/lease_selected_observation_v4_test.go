package networkexecutor

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestLeaseSelectedObservationV4OnlyTerminalSourceMarginClassifies(t *testing.T) {
	for _, mode := range []string{"valid", "no-observer", "mixed", "bad-marker", "scope", "drift", "cancel", "runner-first", "runner-second", "guard-runner"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, l, k, source := observationFixtureV4(t, true)
			snapshot, err := l.PrepareSelectedSnapshotV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			marker, err := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, 11, l.fact.Address)
			if err != nil {
				t.Fatal(err)
			}
			source.effectsErr = ErrLeaseUnavailable
			source.observation = LeaseObservationV4{Epoch: 11, Margin: marker}
			switch mode {
			case "no-observer":
				l.getObservationV4 = nil
			case "mixed":
				source.observation.Fact = l.fact
			case "bad-marker":
				source.observation.Margin = &LeaseMarginObservationV4{}
			case "scope":
				snapshot.Identity.RunID = "cccccccccccccccccccccccccccccccc"
			case "drift":
				k.state.Routes[0].Gateway = "198.19.0.9"
			case "cancel":
				source.onRead = func(int) { cancel() }
			}
			run := l.base.run
			reads := 0
			if mode == "runner-first" || mode == "runner-second" || mode == "guard-runner" {
				l.base.run = func(call context.Context, op operation) ([]byte, error) {
					if op.kind == "rules" && mode == "guard-runner" {
						return nil, ErrLeaseUnavailable
					}
					if op.kind == "routes" {
						reads++
						if mode == "runner-first" && reads == 1 || mode == "runner-second" && reads == 2 {
							return nil, ErrLeaseUnavailable
						}
					}
					return run(call, op)
				}
			}
			mutations, retained, seen, physical := k.mutations, l.fact, l.seen, cloneObservationTestV3(k.state)
			legacy := l.VerifySelectedStateV3(ctx, snapshot, LeaseSelectedTargetV3)
			if legacy == nil || IsLeaseObservationPendingV4(legacy) || source.calls != 0 {
				t.Fatal("legacy gained source classification", legacy, source.calls)
			}
			if mode == "valid" && legacy != ErrLeaseUnavailable {
				t.Fatal("legacy result changed", legacy)
			}
			reads = 0
			observed := l.VerifySelectedObservationV4(ctx, snapshot, LeaseSelectedTargetV3)
			valid := mode == "valid"
			if observed == nil || IsLeaseObservationPendingV4(observed) != valid || valid && !MatchesLeaseObservationPendingV4(observed, snapshot.Fact()) {
				t.Fatal("nonterminal failure became source margin", mode, observed)
			}
			if (mode == "runner-first" || mode == "runner-second" || mode == "guard-runner" || mode == "scope" || mode == "drift") && source.calls != 0 {
				t.Fatal("earlier failure reached source classifier", mode, source.calls)
			}
			if mode == "runner-first" && observed != ErrLeaseUnavailable {
				t.Fatal("first runner error changed", observed)
			}
			if mode == "runner-second" && !errors.Is(observed, ErrObservation) {
				t.Fatal("second runner legacy result changed", observed)
			}
			if k.mutations != mutations || l.fact != retained || l.seen != seen || !reflect.DeepEqual(k.state, physical) || l.base.fenced {
				t.Fatal("observation changed authority or physical state")
			}
		})
	}
}

func TestLeaseSelectedObservationV4RegularTerminalRequiresFirstResolvedFact(t *testing.T) {
	for _, mode := range []string{"valid", "changed-fact", "changed-epoch-and-fact", "no-observer", "mixed", "margin", "replay", "tuple", "owner", "expired", "current-error", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, l, k, source := observationFixtureV4(t, true)
			snapshot, err := l.PrepareSelectedSnapshotV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			retained, seen, mutations := l.fact, l.seen, k.mutations
			source.effects.Sequence++
			source.effects.DeadlineBootNS += int64(time.Minute)
			source.observation = LeaseObservationV4{Epoch: 11, Fact: source.effects}
			switch mode {
			case "changed-fact", "changed-epoch-and-fact":
				source.onRead = func(int) {
					source.observation.Fact.Sequence++
					if mode == "changed-epoch-and-fact" {
						source.observation.Epoch++
					}
				}
			case "no-observer":
				l.getObservationV4 = nil
			case "mixed", "margin":
				marker, e := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, 11, l.fact.Address)
				if e != nil {
					t.Fatal(e)
				}
				source.observation.Margin = marker
				if mode == "margin" {
					source.observation.Fact = LeaseFact{}
				}
			case "replay":
				source.effects.Sequence = retained.Sequence
			case "tuple":
				source.effects.Gateway = "198.19.0.3"
			case "owner":
				source.effects.Owner.PID++
			case "expired":
				source.effects.DeadlineBootNS, _ = l.now()
			case "current-error":
				source.effectsErr = ErrScope
			case "cancel":
				source.onRead = func(int) { cancel() }
			}
			legacy := l.VerifySelectedStateV3(ctx, snapshot, LeaseSelectedTargetV3)
			if legacy == nil || IsLeaseObservationPendingV4(legacy) || source.calls != 0 {
				t.Fatal("legacy gained classification", legacy)
			}
			if mode == "valid" && legacy != ErrScope {
				t.Fatal("legacy mismatched-source result changed", legacy)
			}
			err = l.VerifySelectedObservationV4(ctx, snapshot, LeaseSelectedTargetV3)
			valid := mode == "valid"
			if err == nil || IsLeaseObservationPendingV4(err) != valid || valid && !MatchesLeaseObservationPendingV4(err, snapshot.Fact()) {
				t.Fatal("later source read laundered first resolution", mode, err)
			}
			if l.fact != retained || l.seen != seen || k.mutations != mutations || l.base.fenced {
				t.Fatal("regular observation changed authority/effects")
			}
		})
	}
}

func TestLeaseSelectedObservationV4BaselineNeverNeedsSourceMarker(t *testing.T) {
	l, k, _, _ := leaseFixture(t)
	ctx := context.Background()
	snapshot, err := l.PrepareSelectedSnapshotV3(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	l.getObservationV4 = func(context.Context) (LeaseObservationV4, error) {
		reads++
		return LeaseObservationV4{}, ErrLeaseUnavailable
	}
	mutations := k.mutations
	if l.VerifySelectedStateV3(ctx, snapshot, LeaseSelectedBaselineV3) != nil || l.VerifySelectedObservationV4(ctx, snapshot, LeaseSelectedBaselineV3) != nil || reads != 0 || k.mutations != mutations {
		t.Fatal("baseline gained source dependency or effects")
	}
}
