package previewruntime

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type dhcpCountLeaseV4 struct {
	routedDHCPLeaseV3
	events *[]string
	fail   bool
}

func (l dhcpCountLeaseV4) VerifySelectedStateV3(ctx context.Context, s networkexecutor.LeaseSelectedSnapshotV3, state networkexecutor.LeaseSelectedStateV3) error {
	*l.events = append(*l.events, "lease")
	if l.fail {
		return configpoc.ErrRecovery
	}
	return l.routedDHCPLeaseV3.VerifySelectedStateV3(ctx, s, state)
}

func TestRoutedDHCPFailureStageAuthorityShortCircuitOrder(t *testing.T) {
	for _, tt := range []struct {
		fail string
		want []string
	}{
		{"selected", []string{"selected"}},
		{"owner", []string{"selected", "owner"}},
		{"lease", []string{"selected", "owner", "lease"}},
		{"policy", []string{"selected", "owner", "lease", "policy"}},
		{"owner_after", []string{"selected", "owner", "lease", "policy", "owner"}},
		{"", []string{"selected", "owner", "lease", "policy", "owner"}},
	} {
		t.Run(tt.fail, func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			r.grant = configpoc.RoutedDHCPGrantV3{Epoch: fact.Epoch, Snapshot: k.snapshot}
			work := &dhcpRuntimeWorkV3{grant: r.grant, phase: "applied", hash: strings.Repeat("c", 64), generation: 1}
			reader.work, reader.denied, k.target = work, tt.fail == "selected", true
			r.lease = dhcpCountLeaseV4{dhcpRuntimeLeaseV3{k}, &k.events, tt.fail == "lease"}
			calls := 0
			r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
				k.events = append(k.events, "owner")
				calls++
				if tt.fail == "owner" || tt.fail == "owner_after" && calls == 2 {
					return RoutedDHCPOwnerFactV3{}, configpoc.ErrRecovery
				}
				return *fact, nil
			}
			r.policy = func(context.Context, routedDHCPWorkV3) error {
				k.events = append(k.events, "policy")
				if tt.fail == "policy" {
					return configpoc.ErrRecovery
				}
				return nil
			}
			err := (routedDHCPGateAuthorityV3{r}).Verify(context.Background(), networkexecutor.LeaseGateGrant{Fact: fact.Fact, WorkHash: work.hash})
			if (err != nil) != (tt.fail != "") || !reflect.DeepEqual(k.events, tt.want) {
				t.Fatalf("changed short circuit: err=%v events=%v want=%v", err, k.events, tt.want)
			}
		})
	}
}

func TestRoutedDHCPFailureStageOpenAndWithdrawOrder(t *testing.T) {
	for _, failure := range []string{"selected", "owner", "gate_open", "withdraw_selected"} {
		t.Run(failure, func(t *testing.T) {
			r, k, reader, _ := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			g, err := r.begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			work := &dhcpRuntimeWorkV3{grant: g, phase: "prepared", hash: strings.Repeat("c", 64), generation: 1}
			reader.work = work
			if err = r.apply(ctx, work.hash); err != nil {
				t.Fatal(err)
			}
			work.phase, k.events = "applied", nil
			var want []string
			switch failure {
			case "selected":
				reader.denied = true
				want = []string{"selected"}
			case "owner":
				r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
					k.events = append(k.events, "owner")
					return RoutedDHCPOwnerFactV3{}, configpoc.ErrRecovery
				}
				want = []string{"selected", "owner"}
			case "gate_open":
				k.failOpen = true
				want = []string{"selected", "selected", "policy", "stage", "gate-close", "forward-off"}
			case "withdraw_selected":
				reader.denied = true
				want = []string{"gate-close", "forward-off", "selected"}
			}
			if failure == "withdraw_selected" {
				err = r.withdraw(ctx, work.hash)
			} else {
				err = r.open(ctx, work.hash)
			}
			if err == nil || !reflect.DeepEqual(k.events, want) || k.forward || k.gate {
				t.Fatalf("failure reordered effects: err=%v events=%v want=%v", err, k.events, want)
			}
		})
	}
}
