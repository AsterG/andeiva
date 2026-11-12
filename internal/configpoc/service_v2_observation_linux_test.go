//go:build linux

package configpoc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestServiceV2AtomicObservations(t *testing.T) {
	s, binding, _, _ := serviceV2Fixture(t, "admin")
	ns, err := s.Namespace(binding, "firewall", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := s.ObserveList(binding, ns.ID, "", 0, 10)
	if err != nil || len(empty.Operations) != 0 || empty.Current.Global.Lineage == "" || empty.Current.Snapshot.Generation != 9 || empty.Current.Global.Generation != 1 {
		t.Fatal("empty envelope lost mapping", err)
	}
	local := s.coordinator.store.state.Configuration.LocalServices.Running
	check := func(current CurrentV2) {
		t.Helper()
		composite, err := v2CompositeFromDomains(current.Snapshot.Running, local)
		if err != nil || composite.Hash != current.Global.Running || current.Snapshot.ReplayedGeneration != 0 {
			t.Error("torn global/domain observation", err)
		}
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for range 5 {
		wg.Go(func() {
			for range 10 {
				page, err := s.ObserveList(binding, ns.ID, "", 0, 100)
				if err != nil {
					t.Error(err)
					return
				}
				check(page.Current)
			}
		})
	}
	for range 8 {
		status, err := s.Status(binding)
		if err != nil {
			t.Fatal(err)
		}
		admitted, err := s.AdmitObserved(binding, ns.ID, status.GlobalGeneration, OperationRequestV2{Kind: OpSave})
		if err != nil {
			t.Fatal(err)
		}
		check(admitted.Current)
		executed, err := s.ExecuteObserved(context.Background(), binding, admitted.Operation.ID)
		if err != nil {
			t.Fatal(err)
		}
		check(executed.Current)
		if executed.Operation.Outcome.Generation != executed.Current.Global.Generation {
			t.Fatal("execute envelope not from outcome selection")
		}
		observed, err := s.Observe(binding, admitted.Operation.ID)
		if err != nil {
			t.Fatal(err)
		}
		check(observed.Current)
	}
	wg.Wait()
	if _, err := s.ObserveList(binding, ns.ID, "", ^uint64(0), 1); !errors.Is(err, errV2Invalid) {
		t.Fatal("future cursor accepted", err)
	}
}
func TestServiceV2ObservationsDoNotExposeLocalServiceWrites(t *testing.T) {
	s, binding, _, engines := serviceV2Fixture(t, "admin")
	ns, err := s.Namespace(binding, "local_services", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before := s.coordinator.store.state.HighWater
	if _, err := s.AdmitObserved(binding, ns.ID, s.coordinator.store.state.Generation, OperationRequestV2{Kind: OpValidate}); !errors.Is(err, ErrDenied) {
		t.Fatal("local admission accepted", err)
	}
	if s.coordinator.store.state.HighWater != before {
		t.Fatal("denied request was admitted")
	}
	if _, err := s.ObserveList(binding, ns.ID, "", 0, 10); !errors.Is(err, ErrDenied) {
		t.Fatal("unqualified local projection exposed", err)
	}
	if err := s.CloseObservedNamespace(binding, ns.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("unqualified local closure accepted", err)
	}
	if engines[2].applies.Load() != 0 {
		t.Fatal("local engine touched")
	}
}

func TestServiceV2ObservationsProjectRetiredSubjectsWithoutEnablingRevoke(t *testing.T) {
	s, binding, _, _ := serviceV2Fixture(t, "admin")
	store := s.coordinator.store
	bob, err := store.changeSubject("", "bob", checkpointDigest([]byte("explicit bob revision")), false, s.coordinator.now())
	if err != nil {
		t.Fatal(err)
	}
	bobAuth, bobBinding, _ := serviceV2Auth(t, bob.ID, "bob", "admin", bob.CredentialRevision)
	bobService := &ServiceV2{coordinator: s.coordinator, auth: bobAuth}
	if _, err := bobService.Status(bobBinding); err != nil {
		t.Fatal(err)
	}
	ns, err := s.Namespace(binding, "firewall", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := s.AdmitObserved(binding, ns.ID, store.state.Generation, OperationRequestV2{Kind: OpSave})
	if err != nil {
		t.Fatal(err)
	}
	before := store.state.HighWater
	if _, err := s.AdmitObserved(binding, ns.ID, store.state.Generation, OperationRequestV2{Kind: OpRevoke, Subject: bob.ID}); !errors.Is(err, errV2Invalid) {
		t.Fatal("unimplemented revoke accepted", err)
	}
	if before != store.state.HighWater {
		t.Fatal("revoke consumed an operation")
	}
	if _, err := store.changeSubject(bob.ID, bob.Login, bob.CredentialRevision, true, s.coordinator.now()); err != nil {
		t.Fatal(err)
	}
	observed, err := s.Observe(binding, admitted.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.ObserveList(binding, ns.ID, "", 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []CurrentV2{observed.Current, page.Current} {
		if len(current.Snapshot.Revoked) != 1 || current.Snapshot.Revoked[0] != bob.ID {
			t.Fatal("retirement not represented by durable subject ID")
		}
	}
	if _, err := bobService.Status(bobBinding); !errors.Is(err, ErrDenied) {
		t.Fatal("retired actor still authorized", err)
	}
}
