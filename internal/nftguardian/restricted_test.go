package nftguardian

import (
	"context"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestRestrictedBootstrapLeaseAndCompensation(t *testing.T) {
	e := configpoc.NewSimEngine("restricted")
	g := NewRestricted(e)
	defer g.Close()
	ctx := context.Background()
	a, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 1, DefaultAction: "deny"})
	b, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 1, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "a", Action: "allow"}}})
	if g.Apply(ctx, a) == nil {
		t.Fatal("apply before bootstrap")
	}
	if err := g.Bootstrap(ctx, a); err != nil {
		t.Fatal(err)
	}
	if g.Bootstrap(ctx, b) == nil || g.Apply(ctx, b) == nil {
		t.Fatal("unarmed activation")
	}
	if err := g.Arm("transaction", a, b, 120*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := g.Confirm("transaction", b.Hash); err != nil {
		t.Fatal(err)
	}
	// Durable publication may fail after effective confirmation. Only the known
	// previous revision is available for compensation, never an arbitrary rule.
	if err := g.Apply(ctx, a); err != nil {
		t.Fatal(err)
	}
	if e.Current() != a.Hash {
		t.Fatal("compensation failed")
	}
	if g.Apply(ctx, b) == nil {
		t.Fatal("unarmed target reactivation")
	}
}

func TestRestrictedUnchangedActivationHasExactReceipt(t *testing.T) {
	e := configpoc.NewSimEngine("same")
	g := NewRestricted(e)
	defer g.Close()
	a, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny"})
	if err := g.Bootstrap(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{120 * time.Second, 30*time.Second - time.Millisecond} {
		if err := g.Arm("same", a, a, ttl); err != nil {
			t.Fatal(err)
		}
		if err := g.Apply(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		if err := g.Confirm("same", a.Hash); err != nil {
			t.Fatal(err)
		}
		if g.Status().Phase != "idle" || g.Status().Target != a.Hash {
			t.Fatal("missing receipt")
		}
	}
}
