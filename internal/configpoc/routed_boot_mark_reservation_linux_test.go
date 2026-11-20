//go:build linux

package configpoc

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

func TestRoutedBootMarksReserveRollbackBeforeEffects(t *testing.T) {
	reader, c, _, w, authority := selectedDHCPReaderFixtureV3(t, func(cfg *Config) {
		lan, wan := cfg.Routed.Network.Config.Interfaces[0], cfg.Routed.Network.Config.Interfaces[1]
		enabled := true
		cfg.Routed.Rules = []routedmodel.Rule{{
			ID: "initial-rule", Enabled: &enabled, Action: "allow", Protocol: "tcp",
			Path:   routedmodel.Path{FromZone: lan.Zone, ToZone: wan.Zone, FromInterface: lan.ID, ToInterface: wan.ID},
			Source: "198.18.0.0/24", Destination: "198.19.0.2/32",
			SourcePorts: routedmodel.Ports{From: 1024, To: 65535}, DestinationPorts: routedmodel.Ports{From: 18080, To: 18080},
		}}
	})
	hash, err := w.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	authority.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	s := c.store
	id := authority.grant.Snapshot.Identity
	before, err := routedmodel.Canonical(*s.state.Configuration.Firewall.Running.Config.Routed)
	if err != nil || len(before.Policy.Rules) == 0 {
		t.Fatal("invalid fixture policy", err)
	}
	initial, _, closed, err := s.reserveRoutedBootMarksLocked(id, "adopt", nil, before, before)
	if err != nil || !closed || initial.Issued == 0 {
		t.Fatal("first adoption requires named marks and a closed path", err)
	}
	revision := clone(before.Policy)
	revision.Rules[0].ID = "replacement-rule"
	target, err := routedmodel.Canonical(revision)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("exhaustion rejects before durable or runtime effects", func(t *testing.T) {
		for _, issued := range []uint32{routedmodel.MaxAdmissionMarks - 1, routedmodel.MaxAdmissionMarks} {
			original := s.state.RoutedBootMarks.Issued
			s.state.RoutedBootMarks.Issued = issued
			state := clone(s.state)
			head, selection, used := s.selector, s.selection, s.used
			applied, restored, close, err := s.reserveRoutedBootMarksLocked(id, "exhausted-commit", &initial, before, target)
			if err != errV2Limited || err.Error() != "ANDEIVA_OPERATION_LIMITED" || applied.Issued != 0 || restored.Issued != 0 || close ||
				s.blocked || !reflect.DeepEqual(state, s.state) || head != s.selector || selection != s.selection || used != s.used {
				t.Fatalf("mark exhaustion at %d did not reject before effects: %v", issued, err)
			}
			s.state.RoutedBootMarks.Issued = original
			if _, err = reader.ResolveBootMarkPlanV1(context.Background(), hash, s.state.RoutedBootMarks.Reservation, "adopt"); err != nil {
				t.Fatal("existing selection became unavailable after rejection", err)
			}
		}
	})
	applied, restored, closed, err := s.reserveRoutedBootMarksLocked(id, "group-commit", &initial, before, target)
	if err != nil || closed || len(applied.Bindings) == 0 || applied.Issued <= initial.Issued ||
		restored.Issued <= applied.Issued || restored.Bindings[0].Mark <= applied.Bindings[0].Mark {
		t.Fatal("reservation failed to reserve a new restoration mark", applied, restored, err)
	}
	var stored v2State
	if s.readObject(s.selection.State, &stored) != nil || stored.RoutedBootMarks == nil ||
		stored.RoutedBootMarks.Boot != v2BootID(id.BootID) || stored.RoutedBootMarks.Issued != restored.Issued ||
		stored.RoutedDHCP.Work != hash || stored.Generation != s.state.Generation {
		t.Fatal("reservation was not selected durably before effects")
	}
	reservation, err := loadRoutedBootMarkReservationV1(stored.RoutedBootMarks, stored.Lineage, s.readObject)
	if err != nil || reservation.Scope != id || reservation.Work != hash ||
		!sameRoutedAdmissionMarksV1(reservation.Applied, applied) || !sameRoutedAdmissionMarksV1(reservation.Restored, restored) {
		t.Fatal("selected record did not bind both assignments to the original gateway and Work", err)
	}
	evidence, err := reader.ResolveBootMarkPlanV1(context.Background(), hash, stored.RoutedBootMarks.Reservation, "group-commit")
	if err != nil || !sameRoutedAdmissionMarksV1(evidence.Applied, applied) || !sameRoutedAdmissionMarksV1(evidence.Restored, restored) {
		t.Fatal("independent reader did not resolve the selected reservation", err)
	}
	if _, err = reader.ResolveBootMarkPlanV1(context.Background(), hash, stored.RoutedBootMarks.Reservation, "foreign-commit"); !errors.Is(err, ErrRecovery) {
		t.Fatal("another operation resolved the mark assignment", err)
	}
	originalConfig := clone(*s.state.Configuration)
	changedConfig := clone(originalConfig)
	changedConfig.Firewall.Running.Config.Routed = &target.Policy
	if !validReservedRoutedGroupMarksV1(stored, stored.RoutedBootMarks.Reservation, "group-commit", id, originalConfig, changedConfig, s.readObject) ||
		validReservedRoutedGroupMarksV1(stored, stored.RoutedBootMarks.Reservation, "group-commit", id, originalConfig, originalConfig, s.readObject) {
		t.Fatal("reservation did not constrain the exact grouped target")
	}
	// Simulate a lost effect reply. A retry using the same source policy and
	// the persisted cursor consumes fresh marks instead of recycling either
	// the attempted target or its reserved rollback.
	if err = s.readSelection(); err != nil {
		t.Fatal("could not reload the durable reservation", err)
	}
	retry, _, _, err := s.reserveRoutedBootMarksLocked(id, "group-commit", &initial, before, target)
	if err != nil || retry.Bindings[0].Mark <= restored.Bindings[0].Mark {
		t.Fatal("retry reused a reserved mark", retry, err)
	}
	if _, err = reader.ResolveBootMarkPlanV1(context.Background(), hash, stored.RoutedBootMarks.Reservation, "group-commit"); !errors.Is(err, ErrRecovery) {
		t.Fatal("a replaced reservation was still readable as selected", err)
	}
	previousCursor := *s.state.RoutedBootMarks
	if _, _, _, err = s.reserveRoutedBootMarksLocked(id, "group-commit", &initial, before, before); err != nil ||
		s.state.RoutedBootMarks.Issued != previousCursor.Issued ||
		s.state.RoutedBootMarks.Reservation == previousCursor.Reservation {
		t.Fatal("a reservation with unchanged rules used new marks or kept the previous plan", err)
	}
	head := s.selector.Current
	foreign := id
	foreign.Namespace++
	if _, _, _, err = s.reserveRoutedBootMarksLocked(foreign, "group-commit", &initial, before, target); !errors.Is(err, ErrRecovery) || s.selector.Current != head {
		t.Fatal("a foreign gateway reserved marks", err)
	}
	backward := clone(s.state)
	backward.RoutedBootMarks.Issued--
	if err = s.publish(backward); !errors.Is(err, errV2Unavailable) || s.selector.Current != head {
		t.Fatal("publication accepted a lower watermark", err)
	}
	// A writer reopening a valid selector without its selected reservation
	// must not bootstrap a fresh allocator from a structurally valid cursor.
	unavailable := s.state.RoutedBootMarks.Reservation
	reopening := &v2Store{root: s.root, access: s.access, objectReader: func(hash string, out any) error {
		if hash == unavailable {
			return ErrRecovery
		}
		return s.readObject(hash, out)
	}}
	if err = reopening.readSelection(); !errors.Is(err, errV2Unavailable) || reopening.selector.Current != "" {
		t.Fatal("writer loaded a cursor without its durable reservation", err)
	}
}
