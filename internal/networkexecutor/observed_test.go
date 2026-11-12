package networkexecutor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/networkplan"
)

func observedBindings() []networkplan.Binding {
	bindings := []networkplan.Binding{}
	for _, i := range fixturePlan().Config.Interfaces {
		bindings = append(bindings, i.Binding)
	}
	return bindings
}

func TestObservedInventoryHasNoFabricatedDesiredPlanAndNoL3Ownership(t *testing.T) {
	e, kernel := fakeExecutor()
	observed, err := e.PrepareObserved(context.Background(), observedBindings())
	if err != nil || e.active != nil || kernel.mutations != 0 {
		t.Fatal("read-only observed capture", err)
	}
	data, err := ObservedSnapshotBytes(observed)
	if err != nil || bytes.Contains(data, []byte("plan_hash")) || bytes.Contains(data, []byte("198.18")) {
		t.Fatal("observation invented a desired subnet/plan", err)
	}
	prepared, err := e.Prepare(context.Background(), fixturePlan())
	if err != nil || !ObservedMatchesPrepared(observed, prepared) || observed.Hash == prepared.Hash {
		t.Fatal("typed exact physical comparison", err)
	}
	if e.VerifyObserved(context.Background(), observed) != nil || e.ApplyPrepared(context.Background(), fixturePlan(), prepared) != nil || e.VerifyObserved(context.Background(), observed) == nil {
		t.Fatal("managed target confused with no-network baseline")
	}
	if e.RestorePrepared(context.Background(), prepared) != nil || e.VerifyObserved(context.Background(), observed) != nil {
		t.Fatal("real managed rollback did not restore original observed inventory")
	}
	detached, err := CanonicalObservedSnapshot(observed)
	if err != nil {
		t.Fatal(err)
	}
	observed.Links[0].Flags[0] = "foreign"
	if detached.Links[0].Flags[0] != "UP" {
		t.Fatal("observed canonical value aliases caller")
	}
}

func TestObservedInventoryRejectsForeignBindingsResourcesAndTampering(t *testing.T) {
	for _, fault := range []string{"binding", "address", "route", "extra-link"} {
		e, kernel := fakeExecutor()
		bindings := observedBindings()
		switch fault {
		case "binding":
			bindings[0].HardwareAddress = "02:00:00:00:99:01"
		case "address":
			kernel.state.Links[0].Addresses = []address{{Family: "inet", Local: "198.18.0.9", Bits: 24}}
		case "route":
			kernel.state.Routes = []route{{Destination: "default", Device: "wan0", Protocol: "static"}}
		case "extra-link":
			kernel.state.Links = append(kernel.state.Links, link{Index: 3, Name: "foreign0", MAC: "02:00:00:00:03:01", MTU: 1500, Flags: []string{"UP"}})
		}
		if _, err := e.PrepareObserved(context.Background(), bindings); err == nil || kernel.mutations != 0 || e.active != nil {
			t.Fatal("foreign inventory granted ownership", fault)
		}
	}
	e, kernel := fakeExecutor()
	snapshot, err := e.PrepareObserved(context.Background(), observedBindings())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Links[0].Index++
	if _, err := CanonicalObservedSnapshot(snapshot); err == nil || e.VerifyObserved(context.Background(), snapshot) == nil || kernel.mutations != 0 {
		t.Fatal("tampered observed identity accepted")
	}
}

func TestObservedRecoveryRequiresOriginalOwnedIncarnationAndNeverCreatesTransaction(t *testing.T) {
	e, kernel := fakeExecutor()
	snapshot, err := e.PrepareObserved(context.Background(), observedBindings())
	if err != nil {
		t.Fatal(err)
	}
	identity := recoveryIdentityFixture()
	if !errors.Is(e.RecoverObserved(context.Background(), snapshot, identity), ErrScope) {
		t.Fatal("unscoped/lab constructor adopted observed state")
	}
	e.identity = &identity
	wrong := identity
	wrong.RunID = strings.Repeat("b", 32)
	if !errors.Is(e.RecoverObserved(context.Background(), snapshot, wrong), ErrScope) || kernel.mutations != 0 {
		t.Fatal("foreign original Work scope accepted")
	}
	if e.RecoverObserved(context.Background(), snapshot, identity) != nil || e.active != nil || kernel.mutations != 0 {
		t.Fatal("read-only recovery invented an L3 transaction")
	}
	kernel.state.Links[0].Index++
	if !errors.Is(e.RecoverObserved(context.Background(), snapshot, identity), ErrUncertain) || !e.fenced || kernel.mutations != 0 {
		t.Fatal("changed observation was adopted or mutated")
	}
}
