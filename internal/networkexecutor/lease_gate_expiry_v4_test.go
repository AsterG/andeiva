package networkexecutor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLeaseGateV4ExpiryClosesWithoutReplayingConsumedSequence(t *testing.T) {
	g, k, _, now := gateFixture(t)
	g.opts.CloseOnExpiryV4 = true
	ctx := context.Background()
	if err := g.Stage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(ctx); err != nil {
		t.Fatal(err)
	}
	sequence, floor := g.seen, g.expiryFloorBootNS
	*now = floor
	if err := g.Verify(ctx); !errors.Is(err, ErrLeaseGateExpired) {
		t.Fatal("expected expiry was not closed", err)
	}
	if g.fenced || g.opened || k.enabled || k.token != nil || g.seen != sequence || g.staged != (LeaseGateGrant{}) || g.expiryFloorBootNS != 0 {
		t.Fatal("expiry left authority, lost watermark or rehabilitated a fence")
	}
	if g.CheckFreshSequenceV4(ctx, sequence) == nil {
		t.Fatal("consumed sequence accepted")
	}
	if err := g.Stage(ctx); err == nil || k.stages != 1 {
		t.Fatal("expired token recreated", err)
	}
	// Stage's legacy replay rejection is irreversible, so use a separate gate
	// below to test a genuinely newer grant rather than clearing that fence.
	if !g.fenced {
		t.Fatal("explicit replay rejection lost its fence")
	}
}

func TestLeaseGateV4ExpiryCrossesDuringKernelRead(t *testing.T) {
	g, k, _, now := gateFixture(t)
	g.opts.CloseOnExpiryV4 = true
	ctx := context.Background()
	if err := g.Stage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(ctx); err != nil {
		t.Fatal(err)
	}
	floor, sequence := g.expiryFloorBootNS, g.seen
	*now = floor - 1
	reads := 0
	k.observe = func(b []byte) []byte {
		reads++
		if reads == 1 {
			*now = floor
			return []byte(`{"nftables":[]}`)
		}
		return b
	}
	if err := g.Verify(ctx); !errors.Is(err, ErrLeaseGateExpired) {
		t.Fatal("expiry crossing was fenced without attempting verified closure", err)
	}
	if reads < 2 || g.fenced || g.opened || k.enabled || k.token != nil || g.seen != sequence || g.expiryFloorBootNS != 0 {
		t.Fatal("expiry crossing skipped final readback or lost watermark")
	}
}

func TestLeaseGateV4FreshGrantAfterExpectedExpiry(t *testing.T) {
	g, k, authority, now := gateFixture(t)
	g.opts.CloseOnExpiryV4 = true
	ctx := context.Background()
	if err := g.Stage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(ctx); err != nil {
		t.Fatal(err)
	}
	*now = g.expiryFloorBootNS
	if err := g.Verify(ctx); !errors.Is(err, ErrLeaseGateExpired) {
		t.Fatal(err)
	}
	authority.grant.Fact.Sequence++
	authority.grant.Fact.DeadlineBootNS = *now + int64(time.Minute)
	if err := g.CheckFreshSequenceV4(ctx, authority.grant.Fact.Sequence); err != nil {
		t.Fatal(err)
	}
	if err := g.Stage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(ctx); err != nil {
		t.Fatal(err)
	}
	if !g.opened || g.fenced || k.stages != 2 || k.opens != 2 {
		t.Fatal("fresh grant could not open after verified expiry closure")
	}
}

func TestLeaseGateV4ExpiryDoesNotRelaxLegacyDriftClockOrClosureFailure(t *testing.T) {
	for _, problem := range []string{"legacy", "early-drift", "foreign-object", "close-failure", "clock", "cancelled", "lifetime"} {
		t.Run(problem, func(t *testing.T) {
			g, k, _, now := gateFixture(t)
			g.opts.CloseOnExpiryV4 = problem != "legacy"
			ctx := context.Background()
			if err := g.Stage(ctx); err != nil {
				t.Fatal(err)
			}
			if err := g.Open(ctx); err != nil {
				t.Fatal(err)
			}
			*now = g.expiryFloorBootNS
			switch problem {
			case "early-drift":
				*now--
				k.token = nil
			case "foreign-object":
				k.observe = func([]byte) []byte { return []byte(`{"nftables":[{"table":{"family":"inet","name":"foreign"}}]}`) }
			case "close-failure":
				k.failClose = true
			case "clock":
				g.now = func() (int64, error) { return 0, errors.New("clock failed") }
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "lifetime":
				lifetime, cancel := context.WithCancel(ctx)
				g.lifetime = lifetime
				cancel()
			}
			err := g.Verify(ctx)
			if err == nil || errors.Is(err, ErrLeaseGateExpired) {
				t.Fatal("invalid proof reported ordinary expiry", err)
			}
			if problem != "cancelled" && problem != "lifetime" && !g.fenced {
				t.Fatal("uncertainty did not fence")
			}
		})
	}
}
