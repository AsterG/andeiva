package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// Kernel/store doubles exercise budget enforcement, not native timing.
func adoptionRuntimeV4(t *testing.T) (*RoutedDHCPRuntimeV3, *dhcpRuntimeKernelV3, *dhcpRuntimeReaderV3, *RoutedDHCPOwnerFactV3) {
	t.Helper()
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	g, err := r.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reader.work = &dhcpRuntimeWorkV3{grant: g, phase: "prepared", hash: strings.Repeat("e", 64)}
	if err = r.apply(context.Background(), reader.work.hash); err != nil {
		t.Fatal(err)
	}
	reader.work.phase = "applied"
	if err = r.open(context.Background(), reader.work.hash); err != nil {
		t.Fatal(err)
	}
	return r, k, reader, fact
}

func TestRoutedDHCPAdoptionBudgetV4RejectsAtEveryOpenBoundary(t *testing.T) {
	for phase := 1; phase <= 5; phase++ {
		t.Run(string(rune('0'+phase)), func(t *testing.T) {
			r, k, reader, _ := adoptionRuntimeV4(t)
			if err := r.closeUnder(context.Background()); err != nil {
				t.Fatal(err)
			}
			r.renewalWaiting = true
			r.hookEpoch, r.hookBootNS = r.grant.Epoch, int64(100*time.Second)
			calls := 0
			r.adoptionClock = func() (int64, error) {
				calls++
				if calls >= phase {
					return int64(112*time.Second) + 1, nil
				}
				return int64(111 * time.Second), nil
			}
			err := r.open(context.Background(), reader.work.hash)
			if !errors.Is(err, errRoutedDHCPAdoptionBudgetV4) || k.gate || k.forward || r.opened || !k.target || r.retired || r.adoptionOverruns != 1 {
				t.Fatal("budget did not close safely", err, r.adoptionOverruns, k.events)
			}
			if r.forward.VerifyClosed(context.Background()) != nil || r.gate.VerifyClosedSelectedV3(context.Background()) != nil {
				t.Fatal("closure not verified")
			}
			if r.DiagnosticsV4().Notice != "ANDEIVA_WAN_UPDATE_BUDGET_EXCEEDED" {
				t.Fatal("missing generic notice")
			}
			// A later clock cannot rehabilitate the same hook or count it again.
			r.adoptionClock = func() (int64, error) { return int64(101 * time.Second), nil }
			for range 10 {
				if !errors.Is(r.open(context.Background(), reader.work.hash), errRoutedDHCPAdoptionBudgetV4) {
					t.Fatal("same rejected epoch reopened")
				}
			}
			if r.adoptionOverruns != 1 {
				t.Fatal("retries inflated overrun counter")
			}
		})
	}
}

func TestRoutedDHCPAdoptionBudgetV4BoundaryAndUnknownEvidence(t *testing.T) {
	for _, mode := range []string{"exact", "missing", "backward", "clock_error"} {
		t.Run(mode, func(t *testing.T) {
			r, k, reader, _ := adoptionRuntimeV4(t)
			if err := r.closeUnder(context.Background()); err != nil {
				t.Fatal(err)
			}
			r.renewalWaiting = true
			r.hookEpoch, r.hookBootNS = r.grant.Epoch, int64(100*time.Second)
			r.adoptionClock = func() (int64, error) { return int64(112 * time.Second), nil }
			switch mode {
			case "missing":
				r.hookEpoch = 0
			case "backward":
				r.adoptionClock = func() (int64, error) { return int64(99 * time.Second), nil }
			case "clock_error":
				r.adoptionClock = func() (int64, error) { return 0, errors.New("unavailable") }
			}
			err := r.open(context.Background(), reader.work.hash)
			if mode == "exact" {
				if err != nil || !k.forward || !r.opened {
					t.Fatal("exact inclusive boundary rejected", err)
				}
				return
			}
			if !errors.Is(err, errRoutedDHCPAdoptionClockV4) || k.forward || k.gate || r.adoptionOverruns != 0 {
				t.Fatal("unknown evidence counted as measured overrun or opened", err)
			}
		})
	}
}

func TestRoutedDHCPMarginRuntimeV4WaitsClosedForFreshNaturalGrant(t *testing.T) {
	r, k, reader, fact := adoptionRuntimeV4(t)
	previous, work, retained := r.grant, reader.work, r.gate
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
		return RoutedDHCPOwnerFactV3{}, routedDHCPMarginClosedV4{epoch: previous.Epoch + 1, address: previous.Snapshot.Address}
	}
	for range 100 {
		r.watchLeaseV4(context.Background())
	}
	if r.opened || k.gate || k.forward || !k.target || !r.renewalWaiting || r.failed || r.retired || r.withdrawn || !reflect.DeepEqual(r.grant, previous) || reader.work != work || r.gate != retained || r.marginClosures != 1 {
		t.Fatal("margin discarded work, opened or repeated notice", k.events)
	}
	if r.forward.VerifyClosed(context.Background()) != nil || r.gate.VerifyClosedSelectedV3(context.Background()) != nil {
		t.Fatal("margin closure not verified")
	}
	if _, err := r.renewSameEffectiveV4(context.Background(), work.hash, previous.Snapshot.Hash); err == nil || k.forward {
		t.Fatal("mask accepted as renewal")
	}
	next := previous
	next.Epoch += 2
	next.Snapshot = dhcpRuntimeRenewedSnapshotV4(t, previous.Snapshot)
	*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
	k.snapshot = next.Snapshot
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) { return *fact, nil }
	r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
		if k.forward || k.gate || !k.target {
			return configpoc.ErrRecovery
		}
		return nil
	}}
	if _, err := r.renewSameEffectiveV4(context.Background(), work.hash, next.Snapshot.Hash); err != nil || !r.opened || !k.forward || reader.work != work || r.gate != retained {
		t.Fatal("fresh natural grant did not recover normally", err, k.events)
	}
}
