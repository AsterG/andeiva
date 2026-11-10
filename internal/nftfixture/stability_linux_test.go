package nftfixture

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestHostStartupQuietWindowAndDelayedDHCP(t *testing.T) {
	for _, changeAt := range []int{-1, 7, 9} {
		t.Run(strconv.Itoa(changeAt), func(t *testing.T) {
			start := time.Unix(100, 0)
			clock := start
			reads := 0
			input := map[string][]byte{"routes": []byte("before"), "links": []byte("ens33")}
			read := func(ctx context.Context) (map[string][]byte, error) {
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > hostStabilityLimit {
					t.Fatal("snapshot did not receive bounded context")
				}
				reads++
				if changeAt >= 0 && clock.Sub(start) >= time.Duration(changeAt)*time.Second {
					input["routes"] = []byte("after")
				}
				return input, nil
			}
			baseline, err := waitStableHost(context.Background(), read, func() time.Time { return clock }, func(context.Context) error { clock = clock.Add(time.Second); return nil })
			if err != nil {
				t.Fatal(err)
			}
			want := 10
			if changeAt >= 0 {
				want += changeAt
			}
			if clock.Sub(start) != time.Duration(want)*time.Second || reads != want+1 {
				t.Fatalf("quiet window/reset/recapture: elapsed %s reads %d", clock.Sub(start), reads)
			}
			// Later observations cannot mutate or replace the accepted baseline.
			input["routes"][0] = 'X'
			if sameHostSnapshot(baseline, input) {
				t.Fatal("baseline aliases later observations")
			}
			if sameHostSnapshot(baseline, map[string][]byte{"routes": baseline["routes"]}) {
				t.Fatal("missing snapshot category accepted")
			}
		})
	}
}

func TestHostStartupContinuousChangesExhaustBudget(t *testing.T) {
	start := time.Unix(100, 0)
	clock := start
	reads := 0
	baseline, err := waitStableHost(context.Background(), func(context.Context) (map[string][]byte, error) {
		reads++
		return map[string][]byte{"routes": []byte(strconv.Itoa(reads))}, nil
	}, func() time.Time { return clock }, func(context.Context) error { clock = clock.Add(time.Second); return nil })
	if !errors.Is(err, errHostUnstable) || baseline != nil || reads != 30 || clock.Sub(start) != hostStabilityLimit {
		t.Fatalf("unbounded unstable startup: %v reads=%d elapsed=%s", err, reads, clock.Sub(start))
	}
}

func TestHostStartupCancellationAndQueryFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	read := func(context.Context) (map[string][]byte, error) { called = true; return nil, nil }
	if _, err := waitStableHost(ctx, read, time.Now, waitSnapshotInterval); !errors.Is(err, context.Canceled) || called {
		t.Fatal("canceled startup queried host")
	}
	queryErr := errors.New("query failure")
	if baseline, err := waitStableHost(context.Background(), func(context.Context) (map[string][]byte, error) { return nil, queryErr }, time.Now, waitSnapshotInterval); baseline != nil || !errors.Is(err, queryErr) {
		t.Fatal("query failure accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if _, err := waitStableHost(ctx, func(context.Context) (map[string][]byte, error) {
		cancel()
		return map[string][]byte{"routes": []byte("stable")}, nil
	}, time.Now, waitSnapshotInterval); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel during query accepted")
	}
	if err := waitSnapshotInterval(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("wait ignored cancellation")
	}
}

func TestHostStartupDeadlineIncludesSlowQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	baseline, err := waitStableHost(ctx, func(query context.Context) (map[string][]byte, error) {
		got, _ := query.Deadline()
		if got.After(deadline) {
			t.Fatal("parent deadline extended")
		}
		<-query.Done()
		return nil, query.Err()
	}, time.Now, waitSnapshotInterval)
	if baseline != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked query escaped deadline")
	}
}

func TestHostStartupRejectsEmptyOrOverdueObservation(t *testing.T) {
	for _, overdue := range []bool{false, true} {
		clock := time.Unix(100, 0)
		waited := false
		baseline, err := waitStableHost(context.Background(), func(context.Context) (map[string][]byte, error) {
			if overdue {
				clock = clock.Add(hostStabilityLimit)
				return map[string][]byte{"routes": []byte("stable")}, nil
			}
			return map[string][]byte{}, nil
		}, func() time.Time { return clock }, func(context.Context) error { waited = true; return nil })
		if baseline != nil || !errors.Is(err, errHostUnstable) || waited {
			t.Fatal("empty or overdue observation accepted")
		}
	}
}

func TestHostSnapshotPolicyChangesRemainSignificant(t *testing.T) {
	baseline := map[string][]byte{"routes": []byte("gateway-a"), "routes6": []byte("v6-a"), "links": []byte("ens33-up"), "rules": []byte("deny"), "ipv4": []byte("0"), "ipv6": []byte("0")}
	for key := range baseline {
		changed := copyHostSnapshot(baseline)
		changed[key] = []byte("changed")
		if sameHostSnapshot(baseline, changed) {
			t.Fatalf("change to %s ignored", key)
		}
	}
}
