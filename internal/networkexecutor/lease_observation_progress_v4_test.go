package networkexecutor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Both source observations are individually valid. A coherent advance during
// physical reads requires a complete stable reobservation, never direct success
// or a mutation of the retained lease authority. Epoch is not a sequence alias.
func TestLeaseObservationProgressV4CoherentAdvanceRequiresOneStableReobservation(t *testing.T) {
	for _, mode := range []string{"grant", "retained-grant", "margin"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			_, l, k, source := observationFixtureV4(t, true)
			retained, seen, mutations, effectCalls := l.fact, l.seen, k.mutations, source.effectCalls
			physical := cloneObservationTestV3(k.state)
			before := LeaseObservationV4{Epoch: 11, Fact: retained}
			if mode != "retained-grant" {
				before.Fact.Sequence++
				before.Fact.DeadlineBootNS += int64(time.Minute)
			}
			after := before
			after.Epoch = 37
			after.Fact.Sequence++
			after.Fact.DeadlineBootNS += int64(time.Minute)
			now, err := l.now()
			if err != nil {
				t.Fatal(err)
			}
			if !l.validObservationFactV4(before.Fact, now, true) || !l.validObservationFactV4(after.Fact, now, true) || before.Epoch == before.Fact.Sequence || after.Epoch == after.Fact.Sequence {
				t.Fatal("grant fixture does not prove coherent independent epoch/sequence progress")
			}
			if mode == "margin" {
				oldMarker, e := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, 11, retained.Address)
				if e != nil {
					t.Fatal(e)
				}
				newMarker, e := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, 29, retained.Address)
				if e != nil {
					t.Fatal(e)
				}
				before = LeaseObservationV4{Epoch: 11, Margin: oldMarker}
				after = LeaseObservationV4{Epoch: 29, Margin: newMarker}
				if oldMarker == newMarker || oldMarker.epoch != before.Epoch || newMarker.epoch != after.Epoch || oldMarker.owner != newMarker.owner || oldMarker.address != newMarker.address || oldMarker.desiredHash != newMarker.desiredHash {
					t.Fatal("margin fixture mutated or mixed markers")
				}
			}
			source.observation = before
			var captured []LeaseObservationV4
			source.onRead = func(call int) {
				if call > 4 {
					source.err = ErrScope
					return
				}
				captured = append(captured, source.observation)
			}
			run := l.base.run
			routes := 0
			l.base.run = func(call context.Context, op operation) ([]byte, error) {
				data, e := run(call, op)
				if e == nil && op.kind == "routes" {
					routes++
					if routes == 1 {
						source.observation = after
					}
				}
				return data, e
			}
			err = l.VerifyObservationV4(ctx)
			if !MatchesLeaseObservationPendingV4(err, retained) {
				t.Fatal("coherent source advance rejected without one complete stable reobservation", mode, err, "source reads", source.calls, "physical reads", routes)
			}
			if source.calls != 4 || routes != 4 || len(captured) != source.calls || !reflect.DeepEqual(captured[0], before) || !reflect.DeepEqual(captured[len(captured)-1], after) || !reflect.DeepEqual(captured[len(captured)-2], after) {
				t.Fatal("missing stable complete retry or unbounded source reads", source.calls, routes, captured)
			}
			if l.fact != retained || l.seen != seen || k.mutations != mutations || source.effectCalls != effectCalls || l.base.fenced || !reflect.DeepEqual(k.state, physical) {
				t.Fatal("reobservation altered retained deadline/authority, physical state or effect source")
			}
		})
	}
}

func TestLeaseObservationProgressV4RetryMustStartAtExactPriorBoundary(t *testing.T) {
	for _, mode := range []string{"grant-retained-kind-zero", "grant-rollback-above-retained", "grant-newer-boundary", "grant-cross-union", "margin-rollback-aba", "margin-newer-boundary", "margin-cross-union-kind-zero", "margin-cross-union-fresh"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			_, l, k, source := observationFixtureV4(t, true)
			retained, seen, mutations, effects := l.fact, l.seen, k.mutations, source.effectCalls
			physical := cloneObservationTestV3(k.state)
			before := LeaseObservationV4{Epoch: 11, Fact: retained}
			if mode == "grant-rollback-above-retained" {
				before.Fact.Sequence++
				before.Fact.DeadlineBootNS += int64(time.Minute)
			}
			boundary := before
			boundary.Epoch = 37
			boundary.Fact.Sequence++
			boundary.Fact.DeadlineBootNS += int64(time.Minute)
			if strings.HasPrefix(mode, "margin-") {
				first, e := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, 11, retained.Address)
				if e != nil {
					t.Fatal(e)
				}
				second, e := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, 37, retained.Address)
				if e != nil {
					t.Fatal(e)
				}
				before = LeaseObservationV4{Epoch: 11, Margin: first}
				boundary = LeaseObservationV4{Epoch: 37, Margin: second}
			}
			third := before
			switch mode {
			case "grant-newer-boundary":
				third = boundary
				third.Epoch++
				third.Fact.Sequence++
				third.Fact.DeadlineBootNS += int64(time.Minute)
			case "grant-cross-union", "margin-newer-boundary":
				epoch := uint64(37)
				if mode == "margin-newer-boundary" {
					epoch++
				}
				marker, e := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, epoch, retained.Address)
				if e != nil {
					t.Fatal(e)
				}
				third = LeaseObservationV4{Epoch: epoch, Margin: marker}
			case "margin-cross-union-kind-zero":
				third = LeaseObservationV4{Epoch: 37, Fact: retained}
			case "margin-cross-union-fresh":
				third = LeaseObservationV4{Epoch: 38, Fact: retained}
				third.Fact.Sequence++
				third.Fact.DeadlineBootNS += int64(time.Minute)
			}
			source.observation = before
			source.onRead = func(call int) {
				if call == 3 {
					source.observation = third
				}
				if call > 4 {
					source.err = ErrScope
				}
			}
			run := l.base.run
			routes := 0
			l.base.run = func(call context.Context, op operation) ([]byte, error) {
				data, e := run(call, op)
				if e == nil && op.kind == "routes" {
					routes++
					if routes == 1 {
						source.observation = boundary
					}
				}
				return data, e
			}
			err := l.VerifyObservationV4(ctx)
			if !errors.Is(err, ErrScope) || IsLeaseObservationPendingV4(err) || source.calls != 3 || routes != 2 {
				t.Fatal("retry boundary rollback/progress/union change became authority or another proof", mode, err, source.calls, routes)
			}
			if l.fact != retained || l.seen != seen || k.mutations != mutations || source.effectCalls != effects || l.base.fenced || !reflect.DeepEqual(k.state, physical) {
				t.Fatal("boundary rejection changed retained authority/deadline or physical state")
			}
		})
	}
}

func TestLeaseObservationProgressV4CannotRetryUnprovenOrSecondChanges(t *testing.T) {
	for _, mode := range []string{"second-change", "epoch-rollback", "sequence-rollback", "ip", "gateway", "owner", "invalid-after", "mixed", "scope-between", "drift-between", "cancel-between", "expiry-between", "clock-regression-between", "second-generic", "second-drift", "second-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, l, k, source := observationFixtureV4(t, true)
			retained, seen, mutations, effects := l.fact, l.seen, k.mutations, source.effectCalls
			physical := cloneObservationTestV3(k.state)
			before := LeaseObservationV4{Epoch: 11, Fact: retained}
			after := before
			after.Epoch = 37
			after.Fact.Sequence++
			after.Fact.DeadlineBootNS += int64(time.Minute)
			switch mode {
			case "epoch-rollback":
				after.Epoch = 10
			case "sequence-rollback":
				after.Fact.Sequence = retained.Sequence
			case "ip":
				after.Fact.Address = "198.19.0.9/24"
			case "gateway":
				after.Fact.Gateway = "198.19.0.3"
			case "owner":
				after.Fact.Owner.PID++
			case "invalid-after":
				after.Fact.DeadlineBootNS = 0
			case "mixed":
				marker, e := NewLeaseMarginObservationV4(l.owner, l.desired.Hash, after.Epoch, retained.Address)
				if e != nil {
					t.Fatal(e)
				}
				after.Margin = marker
			}
			source.observation = before
			source.onRead = func(call int) {
				if call > 4 || mode == "second-generic" && call == 3 {
					source.err = ErrScope
				}
				if mode == "second-cancel" && call == 4 {
					cancel()
				}
			}
			now := l.now
			clockReads := 0
			secondScope := false
			l.now = func() (int64, error) {
				clockReads++
				value, e := now()
				if clockReads == 2 {
					switch mode {
					case "scope-between":
						secondScope = true
					case "drift-between":
						k.state.Routes[0].Gateway = "198.19.0.9"
						physical = cloneObservationTestV3(k.state)
					case "cancel-between":
						cancel()
					}
				}
				if clockReads == 3 {
					if mode == "clock-regression-between" {
						return value - 1, e
					}
					if mode == "expiry-between" {
						return after.Fact.DeadlineBootNS, e
					}
				}
				return value, e
			}
			run := l.base.run
			routes := 0
			l.base.run = func(call context.Context, op operation) ([]byte, error) {
				if secondScope && op.kind == "rules" {
					return nil, ErrScope
				}
				data, e := run(call, op)
				if e == nil && op.kind == "routes" {
					routes++
					if routes == 1 {
						source.observation = after
					}
					if routes == 3 {
						switch mode {
						case "second-change":
							source.observation.Epoch++
							source.observation.Fact.Sequence++
							source.observation.Fact.DeadlineBootNS += int64(time.Minute)
						case "second-drift":
							k.state.Routes[0].Gateway = "198.19.0.9"
							physical = cloneObservationTestV3(k.state)
						}
					}
				}
				return data, e
			}
			err := l.VerifyObservationV4(ctx)
			if err == nil || IsLeaseObservationPendingV4(err) || !errors.Is(err, ErrScope) || source.calls > 4 || routes > 4 {
				t.Fatal("unproven/second source change acquired evidence or unbounded retry", mode, err, source.calls, routes)
			}
			if l.fact != retained || l.seen != seen || k.mutations != mutations || source.effectCalls != effects || l.base.fenced || !reflect.DeepEqual(k.state, physical) {
				t.Fatal("failed reobservation changed authority/deadline or physical state")
			}
		})
	}
}
