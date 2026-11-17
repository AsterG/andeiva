package networkexecutor

import (
	"context"
	"errors"
	"testing"
	"time"
)

type gateRenewalRaceAuthorityV4 struct {
	*gateAuthorityFake
	err error
}

func (a *gateRenewalRaceAuthorityV4) Current(ctx context.Context) (LeaseGateGrant, error) {
	if a.err != nil {
		return LeaseGateGrant{}, a.err
	}
	return a.gateAuthorityFake.Current(ctx)
}

func TestLeaseGateRenewalDuringCurrentRecheckClosesWithoutLosingWatermark(t *testing.T) {
	for _, phase := range []string{"stage-current", "stage-before-write", "stage-after-write", "open-before-write", "open-after-write", "verify-after-authority"} {
		for _, classified := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/generic", true: "/classified"}[classified], func(t *testing.T) {
				ctx := context.Background()
				g, k, base, _ := gateFixture(t)
				a := &gateRenewalRaceAuthorityV4{gateAuthorityFake: base}
				g.opts.Authority = a
				var call func(context.Context) error
				if phase == "open-before-write" || phase == "open-after-write" || phase == "verify-after-authority" {
					if err := g.Stage(ctx); err != nil {
						t.Fatal(err)
					}
				}
				if phase == "verify-after-authority" {
					if err := g.Open(ctx); err != nil {
						t.Fatal(err)
					}
				}
				cause := ErrLeaseUnavailable
				if classified {
					cause = ErrLeaseGateRenewal
				}
				switch phase {
				case "stage-current":
					a.err = cause
					call = g.Stage
				case "stage-before-write":
					a.verify = func() error { a.err = cause; return nil }
					call = g.Stage
				case "stage-after-write":
					k.observe = func(b []byte) []byte {
						if k.token != nil {
							a.err = cause
						}
						return b
					}
					call = g.Stage
				case "open-before-write":
					a.verify = func() error { a.err = cause; return nil }
					call = g.Open
				case "open-after-write":
					k.observe = func(b []byte) []byte {
						if k.enabled {
							a.err = cause
						}
						return b
					}
					call = g.Open
				case "verify-after-authority":
					a.verify = func() error { a.err = cause; return nil }
					call = g.Verify
				}
				err := call(ctx)
				if err == nil || classified && !errors.Is(err, ErrLeaseGateRenewal) {
					t.Fatal("renewal classification lost", err)
				}
				if g.opened || k.enabled || k.token != nil || g.fenced == classified {
					t.Fatal("closure/fence invariant", g.fenced, k.enabled)
				}
				consumed := g.seen
				if (phase == "stage-current" || phase == "stage-before-write") && consumed != 0 || phase != "stage-current" && phase != "stage-before-write" && consumed != 1 {
					t.Fatal("lost consumed sequence", consumed)
				}
				a.err, a.verify, k.observe = nil, nil, nil
				a.grant.Fact.Sequence++
				a.grant.Fact.DeadlineBootNS += int64(30 * time.Second)
				if err := g.Stage(ctx); (err == nil) != classified {
					t.Fatal("wrong retry eligibility", err)
				}
				if classified {
					if err := g.Open(ctx); err != nil {
						t.Fatal("fresh authenticated evidence did not reopen", err)
					}
					if g.seen != 2 {
						t.Fatal("watermark not advanced")
					}
				}
			})
		}
	}
}

func TestLeaseGateClassifiedRecheckWithUncertainCloseStillFences(t *testing.T) {
	g, k, base, _ := gateFixture(t)
	ctx := context.Background()
	if err := g.Stage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(ctx); err != nil {
		t.Fatal(err)
	}
	a := &gateRenewalRaceAuthorityV4{gateAuthorityFake: base}
	g.opts.Authority = a
	a.verify = func() error { a.err = ErrLeaseGateRenewal; k.failClose = true; return nil }
	if err := g.Verify(ctx); err == nil || !g.fenced {
		t.Fatal("uncertain closure rehabilitated gate", err)
	}
	a.err, a.verify, k.failClose = nil, nil, false
	if err := g.Stage(ctx); err == nil {
		t.Fatal("uncertain fence reset")
	}
}
