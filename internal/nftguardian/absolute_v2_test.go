package nftguardian

import (
	"context"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

type slowAbsoluteEngine struct {
	*configpoc.SimEngine
	delay time.Duration
}

func (e *slowAbsoluteEngine) Current() string {
	if e.delay > 0 {
		time.Sleep(e.delay)
	}
	return e.SimEngine.Current()
}
func TestAbsoluteDeadlineConsumesSlowReadback(t *testing.T) {
	a, b := revisions()
	e := &slowAbsoluteEngine{SimEngine: configpoc.NewSimEngine("slow")}
	_ = e.Apply(context.Background(), a)
	g := New(e)
	defer g.Close()
	e.delay = 150 * time.Millisecond
	deadline := time.Now().UTC().Add(600 * time.Millisecond)
	if g.ArmUntil("slow", a, b, deadline) == nil || g.state.Phase != "idle" {
		t.Fatal("slow readback extended remaining minimum")
	}
	e.delay = 0
	deadline = time.Now().UTC().Add(700 * time.Millisecond)
	if err := g.ArmUntil("exact", a, b, deadline); err != nil {
		t.Fatal(err)
	}
	s := g.Status()
	if !s.Deadline.Equal(deadline) {
		t.Fatal("changed deadline")
	}
	for _, delta := range []time.Duration{-time.Nanosecond, time.Nanosecond} {
		bad := s
		bad.Deadline = bad.Deadline.Add(delta)
		if g.ApplyLease(context.Background(), b, bad) == nil || g.ConfirmLease(bad) == nil || g.RecoverLease(bad.ID, bad.Previous, bad.Target, bad.Deadline) == nil {
			t.Fatal("foreign deadline accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := g.ApplyLease(ctx, b, s); err != nil {
		t.Fatal(err)
	}
	cancel()
	if e.Current() != b.Hash {
		t.Fatal("cancellation consumed independent lease")
	}
	limit := time.Now().Add(2 * time.Second)
	for e.Current() != a.Hash && time.Now().Before(limit) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.Current() != a.Hash || g.ConfirmLease(s) == nil {
		t.Fatal("independent expiry failed")
	}
}
func TestAbsoluteDeadlineRejectsBoundsAndOffset(t *testing.T) {
	a, b := revisions()
	e := configpoc.NewSimEngine("bounds")
	_ = e.Apply(context.Background(), a)
	g := New(e)
	defer g.Close()
	for _, d := range []time.Time{{}, time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(400 * time.Millisecond), time.Now().UTC().Add(31 * time.Second), time.Now().In(time.FixedZone("offset", 0)).Add(time.Second)} {
		if g.ArmUntil("bad", a, b, d) == nil {
			t.Fatal("invalid deadline accepted", d)
		}
	}
}

func TestAbsoluteHelperRestartRequiresBootstrap(t *testing.T) {
	a, b := revisions()
	e := configpoc.NewSimEngine("new-helper")
	g := NewRestricted(e)
	defer g.Close()
	if g.ArmUntil("old", a, b, time.Now().UTC().Add(time.Second)) == nil || e.Current() != "" || g.Status().Phase != "bootstrap" {
		t.Fatal("helper restart implicitly rearmed")
	}
}
