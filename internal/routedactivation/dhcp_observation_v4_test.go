package routedactivation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

type observationNetworkFixtureV4 struct {
	Network
	observationErr, effectErr error
	observations, effects     int
	after                     func()
}

func (n *observationNetworkFixtureV4) VerifyObservationV4(ctx context.Context) error {
	n.observations++
	if n.after != nil {
		n.after()
	}
	if n.observationErr != nil {
		return n.observationErr
	}
	return n.Network.Verify(ctx)
}
func (n *observationNetworkFixtureV4) Verify(ctx context.Context) error {
	n.effects++
	if n.effectErr != nil {
		return n.effectErr
	}
	return n.Network.Verify(ctx)
}

func observationRetainedFactV4() networkexecutor.LeaseFact {
	return networkexecutor.LeaseFact{
		Owner:    networkexecutor.LeaseOwner{Namespace: 7, BootID: "11111111-1111-1111-1111-111111111111", RunID: strings.Repeat("a", 32), Incarnation: strings.Repeat("b", 32), PID: 42, StartTicks: 99},
		Sequence: 1, DesiredHash: strings.Repeat("c", 64), WAN: networkplan.Binding{Name: "wan0", HardwareAddress: "02:00:00:00:00:01"},
		Address: "198.19.0.2/24", Gateway: "198.19.0.1", DeadlineBootNS: 123,
	}
}

func TestDHCPObservationV4PendingRefreshAndRecoveryWithoutAuthority(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	confirmFixture(t, f)
	ctx := context.Background()
	fact := observationRetainedFactV4()
	raw := networkexecutor.NewLeaseObservationPendingV4(fact)
	n := &observationNetworkFixtureV4{Network: f.engine.network, observationErr: raw, effectErr: networkexecutor.ErrScope}
	f.engine.network = n
	writes, effects, listeners := len(f.kernel.batches), f.network.calls, f.listeners.calls
	observation, err := f.engine.ObserveCurrentOwned(ctx)
	if !MatchesClosedLeaseObservationV4(err, fact, f.target.Composite.Hash) || observation.Plan != f.plan || observation.Current != "" || observation.Owned != "" || observation.MatchingOwned != ([2]string{}) || f.engine.fenced {
		t.Fatal("pending acquired authority or lost exact plan", observation, err)
	}
	if MatchesClosedLeaseObservationV4(raw, fact, f.target.Composite.Hash) || MatchesClosedLeaseObservationV4(err, fact, strings.Repeat("e", 64)) || MatchesClosedLeaseObservationV4(&closedLeaseObservationV4{}, fact, f.target.Composite.Hash) {
		t.Fatal("raw or unbound witness accepted")
	}
	wrong := fact
	wrong.Sequence++
	if MatchesClosedLeaseObservationV4(err, wrong, f.target.Composite.Hash) {
		t.Fatal("wrong retained fact accepted")
	}
	state, current, err := f.group.SnapshotObservedContext(ctx)
	if !errors.Is(err, nftguardian.ErrLease) || !MatchesClosedLeaseObservationV4(err, fact, f.target.Composite.Hash) || state != (nftguardian.State{}) || current != "" || f.engine.fenced {
		t.Fatal("group lost closure witness or exported authority", state, current, err)
	}
	if f.engine.Current() != "" || f.engine.MatchOwned(ctx, f.plan.TargetOwned) == nil || f.engine.matches(ctx, f.prepared.Target, f.prepared.Dependencies) || f.engine.fenced {
		t.Fatal("legacy effect matcher accepted pending authority")
	}
	// The explicit refresh is represented by the trusted source becoming current;
	// no observation writes, reapplication or fence reset is permitted here.
	n.observationErr, n.effectErr = nil, nil
	state, current, err = f.group.SnapshotObservedContext(ctx)
	if err != nil || state.Phase != "idle" || current != f.target.Composite.Hash || f.engine.fenced || len(f.kernel.batches) != writes || f.network.calls != effects || f.listeners.calls != listeners {
		t.Fatal("fresh observation failed to recover without effects", state, current, err)
	}
}

func TestDHCPObservationV4PendingNeverFallsBackToBefore(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	confirmFixture(t, f)
	n := &observationNetworkFixtureV4{Network: f.engine.network, observationErr: networkexecutor.NewLeaseObservationPendingV4(observationRetainedFactV4())}
	f.engine.network = n
	// Byte-identical physical predicates must still not manufacture a Before ref.
	f.engine.prepared.Before = f.engine.prepared.Target
	out, err := f.engine.ObserveCurrentOwned(context.Background())
	if !MatchesClosedLeaseObservationV4(err, observationRetainedFactV4(), f.target.Composite.Hash) || out.Owned != "" || out.Current != "" || n.effects != 0 || f.engine.fenced {
		t.Fatal("pending target fell back to Before", out, err, n.effects)
	}
}

func TestDHCPObservationV4DriftGenericAndFencesRemainLegacy(t *testing.T) {
	for _, mode := range []string{"legacy-table", "routed-table", "local-table", "listener", "generic", "mixed-generic", "wrapped-pending", "cancel", "fenced"} {
		t.Run(mode, func(t *testing.T) {
			f := assembleFixture(t)
			defer f.group.Close()
			confirmFixture(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			n := &observationNetworkFixtureV4{Network: f.engine.network, observationErr: networkexecutor.NewLeaseObservationPendingV4(observationRetainedFactV4()), effectErr: networkexecutor.ErrScope}
			f.engine.network = n
			switch mode {
			case "legacy-table":
				f.kernel.objects[LegacyTable] = nil
			case "routed-table":
				delete(f.kernel.objects, RoutedTable)
			case "local-table":
				delete(f.kernel.objects, LocalTable)
			case "listener":
				f.listeners.actual[0].Port++
			case "generic":
				n.observationErr = networkexecutor.ErrScope
			case "mixed-generic":
				n.observationErr = errors.Join(networkexecutor.ErrScope, n.observationErr)
			case "wrapped-pending":
				n.observationErr = fmt.Errorf("generic: %w", n.observationErr)
			case "cancel":
				n.after = cancel
			case "fenced":
				f.engine.fenced = true
			}
			out, err := f.engine.ObserveCurrentOwned(ctx)
			if err == nil || MatchesClosedLeaseObservationV4(err, observationRetainedFactV4(), f.target.Composite.Hash) || networkexecutor.IsLeaseObservationPendingV4(err) || out != (nftguardian.GroupObservationV1{}) || !f.engine.fenced {
				t.Fatal("drift or generic failure became classified recovery", mode, out, err)
			}
			if mode == "fenced" && n.observations != 0 {
				t.Fatal("preexisting fence was observed through")
			}
			n.observationErr, n.effectErr = nil, nil
			if _, err = f.engine.ObserveCurrentOwned(context.Background()); err == nil || !f.engine.fenced {
				t.Fatal("preexisting fence silently reset")
			}
		})
	}
}
