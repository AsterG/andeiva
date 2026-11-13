//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type migrationGuardianReadFixtureV3 struct {
	states                   []firewalladmin.LeaseState
	hash                     string
	stateError, observeError error
	calls                    []string
}

func (f *migrationGuardianReadFixtureV3) State(context.Context) (firewalladmin.LeaseState, error) {
	f.calls = append(f.calls, "state")
	if f.stateError != nil || len(f.states) == 0 {
		return firewalladmin.LeaseState{}, errors.New("unavailable")
	}
	result := f.states[0]
	f.states = f.states[1:]
	return result, nil
}
func (f *migrationGuardianReadFixtureV3) Observe(context.Context) (firewallipc.Reply, error) {
	f.calls = append(f.calls, "observe")
	return firewallipc.Reply{Hash: f.hash}, f.observeError
}
func TestRoutedMigrationStateV3RequiresExactIdleWithoutClearingReceipt(t *testing.T) {
	expected := strings.Repeat("a", 64)
	// Idle after compensation can retain the target of the original lease, even
	// though observed Running equals its previous revision. Never rewrite it.
	original := firewalladmin.LeaseState{Phase: "idle", ID: "historical-lease", Previous: expected, Target: strings.Repeat("b", 64), Deadline: time.Unix(1700000000, 0).UTC()}
	fixture := &migrationGuardianReadFixtureV3{states: []firewalladmin.LeaseState{original, original}, hash: expected}
	got, err := readMigrationGuardianV3(context.Background(), fixture, expected)
	if err != nil || got != original || strings.Join(fixture.calls, ",") != "state,observe,state" {
		t.Fatal(got, err, fixture.calls)
	}
	for _, phase := range []string{"bootstrap", "armed", "pending", "expired", "blocked", ""} {
		changed := original
		changed.Phase = phase
		fixture = &migrationGuardianReadFixtureV3{states: []firewalladmin.LeaseState{changed, changed}, hash: expected}
		if _, err := readMigrationGuardianV3(context.Background(), fixture, expected); err == nil || len(fixture.calls) != 1 {
			t.Fatal("nonidle source accepted", phase, err, fixture.calls)
		}
	}
	changed := original
	changed.Deadline = changed.Deadline.Add(time.Nanosecond)
	fixture = &migrationGuardianReadFixtureV3{states: []firewalladmin.LeaseState{original, changed}, hash: expected}
	if _, err := readMigrationGuardianV3(context.Background(), fixture, expected); err == nil {
		t.Fatal("receipt changed during inspection")
	}
	for _, fixture := range []*migrationGuardianReadFixtureV3{
		{states: []firewalladmin.LeaseState{original, original}, hash: strings.Repeat("c", 64)},
		{stateError: errors.New("state failed")},
		{states: []firewalladmin.LeaseState{original}, hash: expected, observeError: errors.New("observation failed")},
	} {
		if _, err := readMigrationGuardianV3(context.Background(), fixture, expected); err == nil {
			t.Fatal("failed observation accepted")
		}
	}
}
