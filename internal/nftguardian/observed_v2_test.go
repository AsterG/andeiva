package nftguardian

import (
	"context"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestObservedV2DoesNotInitializeOrRestore(t *testing.T) {
	a, b := revisions()
	e := configpoc.NewSimEngine("snapshot")
	g := NewRestricted(e)
	defer g.Close()
	s, h, err := g.SnapshotObserved()
	if err != nil || s.Phase != "bootstrap" || h != "" {
		t.Fatal(s, h, err)
	}
	if g.MatchObserved(s, h) != nil || e.Current() != "" {
		t.Fatal("cold attach mutated engine")
	}
	if g.Bootstrap(context.Background(), a) != nil || g.Arm("lease", a, b, time.Second) != nil || g.Apply(context.Background(), b) != nil {
		t.Fatal("fixture")
	}
	s, h, err = g.SnapshotObserved()
	if err != nil {
		t.Fatal(err)
	}
	if g.MatchObserved(s, h) != nil || e.Current() != b.Hash || g.Status().Phase != "pending" {
		t.Fatal("attach recovered lease")
	}
	foreign := s
	foreign.Deadline = foreign.Deadline.Add(time.Nanosecond)
	if g.MatchObserved(foreign, h) == nil || e.Current() != b.Hash || !g.Status().Deadline.Equal(s.Deadline) {
		t.Fatal("stale attach mutated authority")
	}
	g.mu.Lock()
	g.state.Phase = "blocked"
	g.mu.Unlock()
	if _, _, err = g.SnapshotObserved(); err == nil {
		t.Fatal("blocked snapshot accepted")
	}
}
