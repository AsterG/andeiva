package previewruntime

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func TestRoutedDHCPObservationV4SeparatesMarginFromGrant(t *testing.T) {
	s := dhcpRuntimeSnapshotV3(t)
	fact := RoutedDHCPOwnerFactV3{Epoch: 1, Fact: s.Fact()}
	for _, mode := range []string{"grant", "margin", "mixed", "foreign", "wrong-desired", "zero-epoch", "revoked", "unavailable", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			x, sourceErr := fact, error(nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "margin":
				x = RoutedDHCPOwnerFactV3{}
				sourceErr = routedDHCPMarginClosedV4{1, fact.Fact.Address}
			case "mixed":
				sourceErr = routedDHCPMarginClosedV4{1, fact.Fact.Address}
			case "foreign":
				x.Fact.Owner.PID++
			case "wrong-desired":
				x.Fact.DesiredHash = strings.Repeat("a", 64)
			case "zero-epoch":
				x.Epoch = 0
			case "revoked":
				x.Fact.Revoked = true
			case "unavailable":
				sourceErr = configpoc.ErrRecovery
			case "cancelled":
				cancel()
			}
			read := routedDHCPObservationSourceV4(fact.Fact.Owner, fact.Fact.DesiredHash, func(context.Context) (RoutedDHCPOwnerFactV3, error) { return x, sourceErr })
			got, err := read(ctx)
			switch mode {
			case "grant":
				if err != nil || got.Fact != fact.Fact || got.Epoch != 1 || got.Margin != nil {
					t.Fatal("valid grant changed", got, err)
				}
			case "margin":
				if err != nil || got.Margin == nil || got.Fact != (networkexecutor.LeaseFact{}) || got.Epoch != 1 {
					t.Fatal("margin became authority or unavailable", got, err)
				}
			default:
				if err == nil || got != (networkexecutor.LeaseObservationV4{}) {
					t.Fatal("invalid source accepted", got, err)
				}
			}
		})
	}
}

func TestRoutedDHCPObservationV4MarginCannotHidePolicyFailure(t *testing.T) {
	for _, rawWitness := range []bool{false, true} {
		t.Run(map[bool]string{false: "generic", true: "unwrapped-network"}[rawWitness], func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
				t.Fatal(err)
			}
			grant, err := r.begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			work := &dhcpRuntimeWorkV3{grant: grant, phase: "prepared", hash: strings.Repeat("e", 64)}
			reader.work = work
			if err = r.apply(ctx, work.hash); err != nil {
				t.Fatal(err)
			}
			work.phase = "applied"
			if err = r.open(ctx, work.hash); err != nil {
				t.Fatal(err)
			}
			masked := false
			r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
				if masked {
					return RoutedDHCPOwnerFactV3{}, routedDHCPMarginClosedV4{fact.Epoch, fact.Fact.Address}
				}
				return *fact, nil
			}
			r.policy = func(context.Context, routedDHCPWorkV3) error {
				masked = true
				if rawWitness {
					return networkexecutor.NewLeaseObservationPendingV4(grant.Snapshot.Fact())
				}
				return configpoc.ErrRecovery
			}
			err = (routedDHCPGateAuthorityV3{r}).Verify(ctx, k.grant)
			if err == nil || errors.Is(err, networkexecutor.ErrLeaseGateRenewal) || errors.Is(err, networkexecutor.ErrLeaseGateMarginClosed) {
				t.Fatal("unproven policy failure classified by concurrent margin", err)
			}
			if r.grant.Epoch != grant.Epoch || r.grant.Snapshot.Hash != grant.Snapshot.Hash || r.renewalWaiting {
				t.Fatal("error changed selected authority")
			}
		})
	}
}
