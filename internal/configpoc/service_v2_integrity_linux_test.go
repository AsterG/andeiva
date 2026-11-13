//go:build linux

package configpoc

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testIntegrityV1 struct {
	attach  func(context.Context, SelectionReferenceV2) error
	inspect func(context.Context, SelectionReferenceV2) (IntegrityResultV1, error)
}

type testIntegrityAdmissionV1 struct {
	*testIntegrityV1
	publication, closing bool
}

func (g *testIntegrityAdmissionV1) IntegrityPublicationAllowedV1() bool { return g.publication }
func (g *testIntegrityAdmissionV1) IntegrityClosingAllowedV1() bool     { return g.closing }

func (g *testIntegrityV1) Attach(ctx context.Context, ref SelectionReferenceV2) error {
	if g.attach != nil {
		return g.attach(ctx, ref)
	}
	return nil
}
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
				if !s.coordinator.store.blocked || !errors.Is(err, errV2Unavailable) {
					t.Fatal("incomplete allowed writes", err)
				}
			}
			if s.coordinator.store.blocked {
				c := s.coordinator
				before := c.store.selector
				c.store.mu.Lock()
				err := c.store.publish(clone(c.store.state))
				c.store.mu.Unlock()
				if !errors.Is(err, errV2Unavailable) || c.store.selector != before {
					t.Fatal("uncertain dispatch allowed non-administrative publication", err)
				}
			}
			gate.inspect = completeIntegrityV1
			err := s.InspectRuntimeV1(context.Background())
			if state == IntegrityFencedV1 || state == "" || state == "unknown" {
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

func TestRuntimeIntegrityV1DueInspectionPreservesReservedConfirmation(t *testing.T) {
	c, _, _, p, now := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	auth, binding, _ := serviceV2Auth(t, p.Subject, "alice", "admin", c.store.state.Subjects[0].CredentialRevision)
	s := &ServiceV2{coordinator: c, auth: auth}
	c.options.Integrity = &testIntegrityV1{inspect: completeIntegrityV1}
	c.integrity.attached = true // Models the authenticated pre-coordinator attachment.
	if err := s.InspectRuntimeV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	coordinatorV2Stage(t, c, p, "integrity-confirm")
	coordinatorV2Run(t, c, p, v2Request{Kind: OpValidate})
	seconds := uint64(120)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	deadline := committed.Current.Pending.Deadline
	*now = now.Add(70 * time.Second)
	if _, err := s.Admit(binding, committed.Operation.Namespace, c.store.state.Generation, v2Request{Kind: OpSave}); !errors.Is(err, ErrRecovery) {
		t.Fatal("overdue ordinary admission", err)
	}
	if err := s.InspectRuntimeV1(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatal("inspection accepted live lease", err)
	}
	namespace, err := s.Namespace(binding, "firewall", time.Minute)
	if err != nil {
		t.Fatal("reserved closing namespace denied", err)
	}
	op, err := s.Admit(binding, namespace.ID, c.store.state.Generation, v2Request{Kind: OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.Pending.Target})
	if err != nil || op.ID == "" {
		t.Fatal("reserved confirmation denied", err)
	}
	if !c.store.state.Configuration.Pending.Deadline.Equal(deadline) {
		t.Fatal("confirmation deadline changed")
	}
	if _, err = s.Execute(context.Background(), binding, op.ID); err != nil {
		t.Fatal("reserved confirmation execute denied", err)
	}
	if c.store.state.Configuration.Pending != nil {
		t.Fatal("confirmation not closed")
	}
	if err := s.InspectRuntimeV1(context.Background()); err != nil {
		t.Fatal("post-confirm inspection", err)
	}
}

func TestRuntimeIntegrityV1AttachPrecedesCoordinatorEffects(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	auth, _, _ := serviceV2Auth(t, p.Subject, "alice", "admin", c.store.state.Subjects[0].CredentialRevision)
	for _, engine := range engines {
		engine.reset()
	}
	wanted, err := selectedReferenceV2(c.store)
	if err != nil {
		t.Fatal(err)
	}
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	attached := false
	gate := &testIntegrityV1{attach: func(_ context.Context, ref SelectionReferenceV2) error {
		attached = true
		if ref != wanted {
			t.Fatal("attach changed expected selection")
		}
		for _, engine := range engines {
			if engine.applies.Load() != 0 || engine.reads.Load() != 0 {
				t.Fatal("coordinator effect or readback before attach")
			}
		}
		return ErrRecovery
	}, inspect: completeIntegrityV1}
	service, err := openServiceCoordinatorV2(context.Background(), area, BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}, auth, []Engine{engines[0], engines[1]}, []Engine{engines[2]}, v2CoordinatorOptions{Integrity: gate})
	if !attached || service != nil || !errors.Is(err, ErrRecovery) {
		t.Fatal("failed attachment returned a service", err)
	}
	// The failed constructor must release the sole-writer lock, permitting a
	// normal qualified restart rather than abandoning the store permanently.
	gate.attach = nil
	service, err = openServiceCoordinatorV2(context.Background(), area, BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}, auth, []Engine{engines[0], engines[1]}, []Engine{engines[2]}, v2CoordinatorOptions{Integrity: gate})
	if err != nil {
		t.Fatal("writer lock leaked", err)
	}
	defer service.Close()
	if !service.coordinator.integrity.ready {
		t.Fatal("constructor returned before qualification")
	}
}

func TestRuntimeIntegrityV1PublicationWakeupCoalesces(t *testing.T) {
	s, _, _, _ := serviceV2Fixture(t, "admin")
	c := s.coordinator
	c.options.Integrity = &testIntegrityV1{inspect: completeIntegrityV1}
	c.integrity.kick = make(chan struct{}, 1)
	c.store.afterPublication = c.integrityPublicationV1
	if err := s.InspectRuntimeV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := uint64(0); i < IntegrityPublicationLimitV1+2; i++ {
		c.store.mu.Lock()
		err := c.store.publish(clone(c.store.state))
		c.store.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if i+1 < IntegrityPublicationLimitV1 && len(c.integrity.kick) != 0 {
			t.Fatal("early publication event")
		}
	}
	select {
	case <-s.IntegrityPublicationsV1():
	default:
		t.Fatal("publication threshold did not wake inspection")
	}
	select {
	case <-s.IntegrityPublicationsV1():
		t.Fatal("unbounded duplicate wakeups")
	default:
	}
	if err := s.InspectRuntimeV1(context.Background()); err != nil || !c.integrityAllowsV1(false) {
		t.Fatal("wakeup inspection did not refresh", err)
	}
}

func TestRuntimeIntegrityV1LivePendingDefersQualificationWithoutClosingTimer(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, true)
	attachReserveManagerV2(t, c)
	auth, binding, _ := serviceV2Auth(t, p.Subject, "alice", "admin", c.store.state.Subjects[0].CredentialRevision)
	s := &ServiceV2{coordinator: c, auth: auth}
	coordinatorV2Stage(t, c, p, "pending-reconnect")
	coordinatorV2Run(t, c, p, v2Request{Kind: OpValidate})
	seconds := uint64(120)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	deadline := committed.Current.Pending.Deadline
	originalTimer := c.timer
	if originalTimer == nil {
		t.Fatal("test did not arm the real coordinator timer")
	}
	gate := &testIntegrityAdmissionV1{testIntegrityV1: &testIntegrityV1{inspect: func(context.Context, SelectionReferenceV2) (IntegrityResultV1, error) {
		t.Fatal("full inspection attempted during live lease")
		return IntegrityResultV1{}, ErrRecovery
	}}, closing: true}
	c.options.Integrity = gate
	c.integrity.attached = true // A correlated cold attachment is not full readiness.
	if err := s.qualifyRuntimeIntegrityV1(context.Background()); err != nil {
		t.Fatal("reconciling service rejected", err)
	}
	if c.closed || c.timer != originalTimer || c.integrity.ready || s.RuntimeIntegrityReadyV1() || !c.store.state.Configuration.Pending.Deadline.Equal(deadline) {
		t.Fatal("qualification closed recovery, reset deadline or claimed ready")
	}
	ns, err := s.Namespace(binding, "firewall", time.Minute)
	if err != nil {
		t.Fatal("cold attached closing namespace denied", err)
	}
	if _, err := s.Admit(binding, ns.ID, c.store.state.Generation, v2Request{Kind: OpSave}); !errors.Is(err, ErrRecovery) {
		t.Fatal("reconciling service admitted ordinary work", err)
	}
	if _, err := s.Status(binding); err != nil {
		t.Fatal("reconciling service lost observation", err)
	}
	gate.closing = false
	if _, err := s.Namespace(binding, "firewall", time.Minute); !errors.Is(err, ErrRecovery) {
		t.Fatal("uncertain controller permitted closing namespace", err)
	}
	gate.closing = true
	again, err := s.Namespace(binding, "firewall", time.Minute)
	if err != nil || again.ID != ns.ID {
		t.Fatal("closing namespace retry changed identity", err)
	}
	op, err := s.Admit(binding, ns.ID, c.store.state.Generation, v2Request{Kind: OpConfirm, Origin: committed.Operation.ID, Target: committed.Current.Pending.Target})
	if err != nil {
		t.Fatal("cold attached confirmation admission denied", err)
	}
	if _, err := s.Execute(context.Background(), binding, op.ID); err != nil {
		t.Fatal("cold attached confirmation execution denied", err)
	}
	if c.store.state.Configuration.Pending != nil || s.RuntimeIntegrityReadyV1() {
		t.Fatal("confirmation failed or fabricated full integrity readiness")
	}
}
