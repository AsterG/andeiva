//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testIntegrityV1 struct {
	inspect func(context.Context, SelectionReferenceV2) (IntegrityResultV1, error)
}

func (*testIntegrityV1) Attach(context.Context, SelectionReferenceV2) error { return nil }
func (g *testIntegrityV1) Inspect(ctx context.Context, ref SelectionReferenceV2) (IntegrityResultV1, error) {
	return g.inspect(ctx, ref)
}

func completeIntegrityV1(_ context.Context, ref SelectionReferenceV2) (IntegrityResultV1, error) {
	return IntegrityResultV1{Selection: ref, State: IntegrityCompleteV1}, nil
}

func TestRuntimeIntegrityV1QualificationAndFreshness(t *testing.T) {
	s, binding, _, _ := serviceV2Fixture(t, "admin")
	c := s.coordinator
	c.options.Integrity = &testIntegrityV1{inspect: completeIntegrityV1}
	if _, err := s.Namespace(binding, "firewall", time.Minute); !errors.Is(err, ErrRecovery) {
		t.Fatal("cold writes enabled", err)
	}
	before := c.store.selector
	if err := s.InspectRuntimeV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.store.selector != before || !c.integrityAllowsV1(false) {
		t.Fatal("inspection published or failed qualification")
	}
	if _, err := s.Namespace(binding, "firewall", time.Minute); err != nil {
		t.Fatal("qualified writes denied", err)
	}
	c.integrity.checked = c.now().Add(-IntegrityInspectionIntervalV1)
	if _, err := s.Namespace(binding, "firewall", time.Minute); !errors.Is(err, ErrRecovery) {
		t.Fatal("overdue writes enabled", err)
	}
	if _, err := s.Status(binding); err != nil {
		t.Fatal("overdue inspection disabled observation", err)
	}
	if err := s.InspectRuntimeV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.integrity.sequence = c.store.selection.Sequence + 1
	if c.integrityAllowsV1(false) {
		t.Fatal("sequence regression accepted")
	}
	c.integrity.sequence = c.store.selection.Sequence
	c.store.selection.Sequence += IntegrityPublicationLimitV1
	if c.integrityAllowsV1(false) {
		t.Fatal("publication budget ignored")
	}
	c.store.selection.Sequence -= IntegrityPublicationLimitV1
}

func TestRuntimeIntegrityV1IncompleteNeverEnablesWrites(t *testing.T) {
	for _, state := range []IntegrityStateV1{IntegrityCancelledV1, IntegrityStaleV1, IntegrityUnavailableV1, IntegrityFencedV1, "", "unknown"} {
		t.Run(string(state), func(t *testing.T) {
			s, binding, _, _ := serviceV2Fixture(t, "admin")
			gate := &testIntegrityV1{inspect: func(_ context.Context, ref SelectionReferenceV2) (IntegrityResultV1, error) {
				return IntegrityResultV1{Selection: ref, State: state}, nil
			}}
			s.coordinator.options.Integrity = gate
			if err := s.InspectRuntimeV1(context.Background()); !errors.Is(err, ErrRecovery) {
				t.Fatal("incomplete success", err)
			}
			if _, err := s.Namespace(binding, "firewall", time.Minute); !errors.Is(err, ErrRecovery) {
				t.Fatal("incomplete allowed writes", err)
			}
			gate.inspect = completeIntegrityV1
			err := s.InspectRuntimeV1(context.Background())
			if state == IntegrityFencedV1 {
				if !errors.Is(err, ErrRecovery) {
					t.Fatal("fence cleared", err)
				}
			} else if err != nil {
				t.Fatal("retry after unavailable", err)
			}
		})
	}
}

func TestRuntimeIntegrityV1WriterBarrierAndCancellation(t *testing.T) {
	s, binding, _, _ := serviceV2Fixture(t, "admin")
	entered, release := make(chan struct{}), make(chan struct{})
	s.coordinator.options.Integrity = &testIntegrityV1{inspect: func(ctx context.Context, ref SelectionReferenceV2) (IntegrityResultV1, error) {
		close(entered)
		<-release
		return completeIntegrityV1(ctx, ref)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.InspectRuntimeV1(ctx) }()
	<-entered
	if s.coordinator.store.mu.TryLock() {
		s.coordinator.store.mu.Unlock()
		t.Fatal("writer barrier released during inspection")
	}
	if _, err := s.Namespace(binding, "firewall", time.Minute); !errors.Is(err, ErrRecovery) {
		t.Fatal("concurrent admission", err)
	}
	if err := s.InspectRuntimeV1(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatal("duplicate inspection not coalesced", err)
	}
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, ErrRecovery) || s.coordinator.integrity.ready {
		t.Fatal("late success after cancellation", err)
	}
}

func TestRuntimeIntegrityV1RejectsUnexpectedTuple(t *testing.T) {
	s, _, _, _ := serviceV2Fixture(t, "admin")
	s.coordinator.options.Integrity = &testIntegrityV1{inspect: func(_ context.Context, ref SelectionReferenceV2) (IntegrityResultV1, error) {
		ref.Sequence++
		return IntegrityResultV1{Selection: ref, State: IntegrityCompleteV1}, nil
	}}
	if err := s.InspectRuntimeV1(context.Background()); !errors.Is(err, ErrRecovery) || s.coordinator.integrity.ready {
		t.Fatal("unexpected tuple accepted", err)
	}
}
