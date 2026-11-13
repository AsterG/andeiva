package networkexecutor

import (
	"context"
	"strings"
	"testing"
)

func TestLeaseSelectedV3GateRecoveryClosesAndConsumesOldSequence(t *testing.T) {
	l, _, _, _ := leaseFixture(t)
	s, err := l.PrepareSelectedSnapshotV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g, k, a, now := gateFixture(t)
	if g.Stage(context.Background()) != nil || g.Open(context.Background()) != nil {
		t.Fatal("initial gate")
	}
	recovered, err := newLeaseGate(context.Background(), s.Identity, g.opts, k, func() (int64, error) { return *now, nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	stages := k.stages
	a.unavailable = true // Closure cannot depend on the old owner surviving.
	if err = recovered.RecoverClosedSelectedV3(context.Background(), s); err != nil || k.enabled || k.token != nil || k.stages != stages {
		t.Fatal("recovery did not only close", err)
	}
	a.unavailable = false
	if recovered.Stage(context.Background()) == nil || k.stages != stages {
		t.Fatal("old sequence restaged")
	}
}

func TestLeaseSelectedV3GateRecoveryRefusesForeignStructureBeforeMutation(t *testing.T) {
	l, _, _, _ := leaseFixture(t)
	s, err := l.PrepareSelectedSnapshotV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g, k, _, now := gateFixture(t)
	k.observe = func(b []byte) []byte { return []byte(strings.Replace(string(b), "drop", "accept", 1)) }
	recovered, err := newLeaseGate(context.Background(), s.Identity, g.opts, k, func() (int64, error) { return *now, nil }, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	before := k.applies
	if recovered.RecoverClosedSelectedV3(context.Background(), s) == nil || k.applies != before {
		t.Fatal("foreign gate changed")
	}
}

func TestLeaseSelectedV3StateReadbackDoesNotConfuseBaselineAndTarget(t *testing.T) {
	l, k, f, now := leaseFixture(t)
	s, err := l.PrepareSelectedSnapshotV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.VerifySelectedStateV3(context.Background(), s, LeaseSelectedBaselineV3) != nil || l.VerifySelectedStateV3(context.Background(), s, LeaseSelectedTargetV3) == nil {
		t.Fatal("baseline confused")
	}
	if _, err = l.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := k.mutations
	if l.VerifySelectedStateV3(context.Background(), s, LeaseSelectedTargetV3) != nil || l.VerifySelectedStateV3(context.Background(), s, LeaseSelectedBaselineV3) == nil {
		t.Fatal("target confused")
	}
	*now = f.DeadlineBootNS
	if l.VerifySelectedStateV3(context.Background(), s, LeaseSelectedTargetV3) == nil || k.mutations != before {
		t.Fatal("expired target/read-only")
	}
	if _, err = l.WithdrawSelectedV3(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.VerifySelectedStateV3(context.Background(), s, LeaseSelectedBaselineV3) != nil {
		t.Fatal("expired baseline withdrawal")
	}
}
