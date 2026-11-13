package networkexecutor

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLeaseSelectedV3ExportDetachesExactBaseline(t *testing.T) {
	l, k, f, _ := leaseFixture(t)
	s, err := l.PrepareSelectedSnapshotV3(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Fact() != *f || s.WANIndex != 2 || s.RouteProtocol != "static" || s.RouteTable != "main" || k.mutations != 0 {
		t.Fatal("snapshot differs or mutated")
	}
	if _, err := CanonicalLeaseSelectedSnapshotV3(s); err != nil {
		t.Fatal(err)
	}
	s.Links[0].Addresses[0].Local = "203.0.113.8"
	s.Desired.Config.Interfaces[0].Binding.Name = "bad0"
	if l.baseline.Links[0].Addresses[0].Local == "203.0.113.8" || l.desired.Config.Interfaces[0].Binding.Name == "bad0" {
		t.Fatal("snapshot aliases retained state")
	}
}

func TestLeaseSelectedV3RecoverExactStatesThenWithdraw(t *testing.T) {
	for _, state := range []LeaseSelectedStateV3{LeaseSelectedBaselineV3, LeaseSelectedAddressV3, LeaseSelectedTargetV3} {
		t.Run(string(state), func(t *testing.T) {
			l, k, _, now := leaseFixture(t)
			s, err := l.PrepareSelectedSnapshotV3(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if state != LeaseSelectedBaselineV3 {
				if _, err := l.Refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
				if state == LeaseSelectedAddressV3 {
					if _, err := k.run(context.Background(), operation{kind: "route-delete", name: s.WAN.Name, gateway: s.Gateway, metric: s.Metric}); err != nil {
						t.Fatal(err)
					}
				}
			}
			base := &Executor{lifetime: context.Background(), identity: l.base.identity, run: l.base.run}
			before := k.mutations
			// Expiry does not prevent withdrawing authenticated owned state. It
			// must prevent treating that state as current traffic authority.
			*now = s.DeadlineBootNS + int64(time.Second)
			recovered, actual, err := recoverLeaseSelectedV3(context.Background(), base, LeaseOptions{Desired: l.desired, Owner: l.owner, Current: l.current}, s, l.now)
			if err != nil || actual != state || k.mutations != before {
				t.Fatal("read-only recovery", actual, err)
			}
			if state != LeaseSelectedAddressV3 && recovered.Verify(context.Background()) == nil {
				t.Fatal("expired grant is live")
			}
			if out, err := recovered.WithdrawSelectedV3(context.Background()); err != nil || out != LeaseWANWithdrawn {
				t.Fatal(out, err)
			}
			if !reflect.DeepEqual(k.state, l.baseline) {
				t.Fatal("LAN baseline not preserved")
			}
		})
	}
}

func TestLeaseSelectedV3RejectsForeignStateAndScope(t *testing.T) {
	for _, change := range []string{"lan-address", "wan-extra", "link-index", "boot", "run", "owner", "desired", "hash", "deadline"} {
		t.Run(change, func(t *testing.T) {
			l, k, _, _ := leaseFixture(t)
			s, err := l.PrepareSelectedSnapshotV3(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = l.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			identity := *l.base.identity
			opts := LeaseOptions{Desired: l.desired, Owner: l.owner, Current: l.current}
			switch change {
			case "lan-address":
				k.state.Links[0].Addresses[0].Local = "198.18.0.3"
			case "wan-extra":
				k.state.Links[1].Addresses = append(k.state.Links[1].Addresses, k.state.Links[1].Addresses[0])
			case "link-index":
				k.state.Links[1].Index++
			case "boot":
				identity.BootID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
			case "run":
				identity.RunID = strings.Repeat("e", 32)
			case "owner":
				opts.Owner.StartTicks++
			case "desired":
				opts.Desired.Hash = strings.Repeat("f", 64)
			case "hash":
				s.Hash = strings.Repeat("f", 64)
			case "deadline":
				s.DeadlineBootNS++
			}
			before := k.mutations
			base := &Executor{lifetime: context.Background(), identity: &identity, run: l.base.run}
			if got, _, err := recoverLeaseSelectedV3(context.Background(), base, opts, s, l.now); err == nil || got != nil || k.mutations != before {
				t.Fatal("foreign recovery accepted/mutated")
			}
		})
	}
}

func TestLeaseSelectedV3RejectsInvalidSnapshotDespiteRehash(t *testing.T) {
	for _, change := range []string{"occupied-baseline", "lan-missing", "wrong-metric", "wrong-index", "wrong-table", "wrong-protocol", "zero-sequence", "wrong-owner", "extra-route"} {
		t.Run(change, func(t *testing.T) {
			l, _, _, _ := leaseFixture(t)
			s, err := l.PrepareSelectedSnapshotV3(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "occupied-baseline":
				s.Links[1].Addresses = append(s.Links[1].Addresses, s.Links[0].Addresses[0])
			case "lan-missing":
				s.Links[0].Addresses = nil
			case "wrong-metric":
				s.Metric++
			case "wrong-index":
				s.WANIndex++
			case "wrong-table":
				s.RouteTable = "100"
			case "wrong-protocol":
				s.RouteProtocol = "dhcp"
			case "zero-sequence":
				s.Sequence = 0
			case "wrong-owner":
				s.OwnerPID = 0
			case "extra-route":
				s.Routes = append(s.Routes, route{Destination: "default", Device: "lan0"})
			}
			if _, err := canonicalLeaseSelectedV3(s); err == nil {
				t.Fatal("invalid shape accepted")
			}
		})
	}
}
