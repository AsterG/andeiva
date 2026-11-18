package nftguardian

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type closureObservationEngineV4 struct {
	pairedObservationEngine
	err    error
	result GroupObservationV1
	cancel context.CancelFunc
}

func (e *closureObservationEngineV4) ObserveCurrentOwned(context.Context) (GroupObservationV1, error) {
	if e.cancel != nil {
		e.cancel()
	}
	return e.result, e.err
}

func TestGroupObservationV4ErrorPreservedOnlyWithoutAuthority(t *testing.T) {
	for _, mode := range []string{"valid", "plan", "current", "owned", "matching", "cancel", "nil-error"} {
		t.Run(mode, func(t *testing.T) {
			cause := errors.New("closure-only witness")
			e := &closureObservationEngineV4{err: cause}
			g, err := NewGroup(e)
			if err != nil {
				t.Fatal(err)
			}
			g.plan = groupPlan("closure", strings.Repeat("a", 64), strings.Repeat("b", 64))
			e.result.Plan = g.plan
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "plan":
				e.result.Plan.Operation = "foreign"
			case "current":
				e.result.Current = strings.Repeat("c", 64)
			case "owned":
				e.result.Owned = g.plan.TargetOwned
			case "matching":
				e.result.MatchingOwned[0] = g.plan.TargetOwned
			case "cancel":
				e.cancel = cancel
			case "nil-error":
				e.err = nil
			}
			state, current, err := g.SnapshotObservedContext(ctx)
			if err == nil || !errors.Is(err, ErrLease) || errors.Is(err, cause) != (mode == "valid") || state != (State{}) || current != "" {
				t.Fatal("unselected cause or authority escaped", mode, state, current, err)
			}
		})
	}
}
