package networkexecutor

import (
	"context"
	"reflect"
	"testing"
)

func TestSameEffectiveLeaseV4ExactScope(t *testing.T) {
	l, k, _, _ := leaseFixture(t)
	p, err := l.PrepareSelectedSnapshotV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := p
	n.Sequence++
	n.DeadlineBootNS-- // No artificial monotonic lease-duration rule.
	n, err = canonicalLeaseSelectedV3(n)
	if err != nil || ValidateSameEffectiveLeaseV4(p, n) != nil {
		t.Fatal("renewal", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*LeaseSelectedSnapshotV3)
	}{
		{"replay", func(s *LeaseSelectedSnapshotV3) { s.Sequence = p.Sequence }},
		{"owner", func(s *LeaseSelectedSnapshotV3) { s.OwnerStartTicks++ }},
		{"run", func(s *LeaseSelectedSnapshotV3) { s.Identity.RunID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }},
		{"prefix", func(s *LeaseSelectedSnapshotV3) { s.Address = "198.19.0.1/25" }},
		{"gateway", func(s *LeaseSelectedSnapshotV3) { s.Gateway = "198.19.0.3" }},
		{"index", func(s *LeaseSelectedSnapshotV3) { s.WANIndex++ }},
		{"metric", func(s *LeaseSelectedSnapshotV3) { s.Metric++ }},
		{"zero-deadline", func(s *LeaseSelectedSnapshotV3) { s.DeadlineBootNS = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, e := canonicalLeaseSelectedV3(n)
			if e != nil {
				t.Fatal(e)
			}
			tc.change(&x)
			if canonical, e := canonicalLeaseSelectedV3(x); e == nil {
				x = canonical
			}
			if ValidateSameEffectiveLeaseV4(p, x) == nil {
				t.Fatal("changed scope accepted")
			}
		})
	}
	if k.mutations != 0 {
		t.Fatal("predicate caused effects")
	}
}

func TestSameEffectiveLeaseV4RefreshNeverMutatesL3(t *testing.T) {
	for _, failure := range []string{"", "replay", "expired", "revoked", "changed-during-read", "drift", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l, k, fact, now := leaseFixture(t)
			previous, err := l.PrepareSelectedSnapshotV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.Refresh(ctx); err != nil {
				t.Fatal(err)
			}
			fact.Sequence++
			fact.DeadlineBootNS += 1_000_000_000
			next, err := l.PrepareSelectedSnapshotV3(ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "replay":
				next = previous
			case "expired":
				*now = next.DeadlineBootNS
			case "revoked":
				fact.Revoked = true
			case "cancelled":
				cancel()
			case "drift":
				if _, err = k.run(ctx, operation{kind: "route-delete", name: previous.WAN.Name, gateway: previous.Gateway, metric: previous.Metric}); err != nil {
					t.Fatal(err)
				}
			case "changed-during-read":
				run := l.base.run
				l.base.run = func(c context.Context, op operation) ([]byte, error) {
					b, e := run(c, op)
					if op.kind == "routes" {
						fact.Sequence++
					}
					return b, e
				}
			}
			mutations, retained := k.mutations, l.fact
			err = l.RefreshSameEffectiveSelectedV4(ctx, previous, next)
			if k.mutations != mutations {
				t.Fatal("renewal mutated L3")
			}
			if failure == "" {
				if err != nil || l.fact != next.Fact() {
					t.Fatal("fresh evidence", err)
				}
				if e := l.RefreshSameEffectiveSelectedV4(ctx, previous, next); e == nil {
					t.Fatal("replay")
				}
				if !reflect.DeepEqual(l.baseline.Links, previous.Links) {
					t.Fatal("baseline changed")
				}
			} else if err == nil || l.fact != retained {
				t.Fatal("invalid renewal changed evidence", err)
			}
		})
	}
}
