package nftguardian

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func revisions() (configpoc.Revision, configpoc.Revision) {
	a, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 1, DefaultAction: "deny"})
	b, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "fixture", Action: "allow"}}})
	return a, b
}

func TestLeaseExpiresWithoutController(t *testing.T) {
	a, b := revisions()
	e := configpoc.NewSimEngine("test")
	_ = e.Apply(context.Background(), a)
	g := New(e)
	defer g.Close()
	if err := g.Arm("lease", a, b, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for e.Current() != a.Hash && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.Current() != a.Hash || g.Status().Phase != "expired" {
		t.Fatal("independent expiry failed")
	}
	if g.Confirm("lease", b.Hash) == nil || g.Apply(context.Background(), b) == nil {
		t.Fatal("late target accepted")
	}
	if err := g.RecoverPrevious(); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseFailuresBlockAndRecover(t *testing.T) {
	a, b := revisions()
	e := configpoc.NewSimEngine("test")
	_ = e.Apply(context.Background(), a)
	g := New(e)
	defer g.Close()
	if g.Arm("bad", a, b, time.Millisecond) == nil {
		t.Fatal("unbounded lease accepted")
	}
	if err := g.Arm("lease", a, b, time.Second); err != nil {
		t.Fatal(err)
	}
	if g.Confirm("wrong", b.Hash) == nil {
		t.Fatal("wrong confirm accepted")
	}
	if err := g.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	e.SetFailure(a.Hash, "before")
	if g.RecoverPrevious() == nil || g.Status().Phase != "blocked" {
		t.Fatal("failed compensation not blocked")
	}
	if g.Apply(context.Background(), b) == nil {
		t.Fatal("blocked mutation accepted")
	}
	e.ClearFailure()
	if err := g.RecoverPrevious(); err != nil {
		t.Fatal(err)
	}
	if e.Current() != a.Hash {
		t.Fatal("recovery lost previous")
	}
}

func TestConfirmAndClosePreserveSafeState(t *testing.T) {
	a, b := revisions()
	e := configpoc.NewSimEngine("test")
	_ = e.Apply(context.Background(), a)
	g := New(e)
	if err := g.Arm("lease", a, b, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = g.Status() }()
	}
	if err := g.Confirm("lease", b.Hash); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if e.Current() != b.Hash {
		t.Fatal("confirmed state reverted")
	}
	g = New(e)
	if err := g.Arm("next", b, a, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if e.Current() != b.Hash {
		t.Fatal("close abandoned provisional")
	}
}

type lateEngine struct {
	*configpoc.SimEngine
	target string
}

func (e lateEngine) Apply(ctx context.Context, r configpoc.Revision) error {
	if r.Hash == e.target {
		time.Sleep(550 * time.Millisecond)
		return e.SimEngine.Apply(context.Background(), r)
	}
	return e.SimEngine.Apply(ctx, r)
}
func TestLateApplyCannotPublishAndCloseFailureIsVisible(t *testing.T) {
	a, b := revisions()
	sim := configpoc.NewSimEngine("late")
	_ = sim.Apply(context.Background(), a)
	g := New(lateEngine{sim, b.Hash})
	if err := g.Arm("lease", a, b, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if g.Apply(context.Background(), b) == nil || sim.Current() != a.Hash {
		t.Fatal("late apply was published")
	}
	if g.Confirm("lease", b.Hash) == nil {
		t.Fatal("late confirm accepted")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	g = New(sim)
	if err := g.Arm("second", a, b, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	sim.SetFailure(a.Hash, "before")
	if g.Close() == nil || g.Status().Phase != "blocked" {
		t.Fatal("close hid failed rollback")
	}
}

func TestConcurrentExpiryConfirmAndForeignTarget(t *testing.T) {
	a, b := revisions()
	e := configpoc.NewSimEngine("test")
	_ = e.Apply(context.Background(), a)
	g := New(e)
	defer g.Close()
	bad := b
	bad.Hash = "incorrect"
	if g.Arm("bad", a, bad, time.Second) == nil || g.Apply(context.Background(), bad) == nil {
		t.Fatal("bad revision accepted")
	}
	if err := g.Arm("lease", a, b, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	third, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "third", Action: "allow"}}})
	if g.Apply(context.Background(), third) == nil {
		t.Fatal("foreign target accepted")
	}
	time.Sleep(500 * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = g.Confirm("lease", b.Hash); _ = g.Status() }()
	}
	wg.Wait()
	if e.Current() != a.Hash || g.Status().Phase != "expired" {
		t.Fatal("expiry lost to late confirmation")
	}
}
