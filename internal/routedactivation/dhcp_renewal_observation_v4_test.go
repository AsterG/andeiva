package routedactivation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type renewalObservationNetworkV4 struct {
	Network
	stale       bool
	verifyCalls int
}

func (n *renewalObservationNetworkV4) Verify(ctx context.Context) error {
	n.verifyCalls++
	if n.stale {
		return networkexecutor.ErrScope
	}
	return n.Network.Verify(ctx)
}

// The Engine and selected-plan/fence behavior are real. Network, nft kernel and
// listeners are controlled fixture doubles: this isolates the consequence of
// the exact generic Verify error independently reproduced in networkexecutor.
func TestDHCPRenewalObservationV4LegacyEngineFenceSurvivesVerifyRecovery(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	confirmFixture(t, f)
	ctx := context.Background()
	network := &renewalObservationNetworkV4{Network: f.engine.network}
	f.engine.network = network
	initial, err := f.engine.ObserveCurrentOwned(ctx)
	if err != nil || initial.Owned != f.plan.TargetOwned || initial.Current != f.target.Composite.Hash || f.engine.fenced {
		t.Fatal("initial selected observation", initial, err)
	}
	tables, err := json.Marshal(f.kernel.objects)
	if err != nil {
		t.Fatal(err)
	}
	listeners, err := json.Marshal(f.listeners.actual)
	if err != nil {
		t.Fatal(err)
	}
	writes, networkEffects, listenerEffects := len(f.kernel.batches), f.network.calls, f.listeners.calls
	network.stale = true
	failed, err := f.engine.ObserveCurrentOwned(ctx)
	if !errors.Is(err, ErrState) || failed.Owned != "" || failed.Current != "" || !f.engine.fenced {
		t.Fatal("legacy observation did not reject and retain selected fence", failed, err)
	}
	network.stale = false
	if err = network.Verify(ctx); err != nil {
		t.Fatal("physical network did not recover in fixture", err)
	}
	reads := network.verifyCalls
	retried, err := f.engine.ObserveCurrentOwned(ctx)
	if !errors.Is(err, ErrState) || retried.Owned != "" || retried.Current != "" || !f.engine.fenced || network.verifyCalls != reads {
		t.Fatal("restored generic Verify silently cleared permanent fence", retried, err)
	}
	if err = f.engine.MatchOwned(ctx, f.plan.TargetOwned); !errors.Is(err, ErrState) {
		t.Fatal("fenced exact selected reference regained authority", err)
	}
	afterTables, err := json.Marshal(f.kernel.objects)
	if err != nil {
		t.Fatal(err)
	}
	afterListeners, err := json.Marshal(f.listeners.actual)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tables, afterTables) || !bytes.Equal(listeners, afterListeners) || len(f.kernel.batches) != writes || f.network.calls != networkEffects || f.listeners.calls != listenerEffects || !f.network.active {
		t.Fatal("reproducer changed physical predicates instead of only Verify outcome")
	}
	t.Log("A transient network Verify ErrScope permanently fences the selected real Engine despite unchanged nft/listeners and later successful Verify. This records legacy behavior; no repair or native qualification is asserted.")
}
