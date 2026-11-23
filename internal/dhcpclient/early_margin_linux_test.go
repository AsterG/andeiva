//go:build linux

package dhcpclient

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func marginClientV4(t *testing.T, seconds uint32) (*Client, Lease) {
	t.Helper()
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{early: newEarlyRenewal(), iface: "wan0", pid: 123, lastGrant: now - int64(time.Second), initialWaiting: true}
	e, err := HookEvent(replace(goodEnv(), "new_dhcp_lease_time", strconv.FormatUint(uint64(seconds), 10)), now-int64(time.Millisecond))
	if err != nil || c.acceptEvent(e, now) != nil {
		t.Fatal("valid short hook killed acquisition", err)
	}
	return c, c.lease
}

func TestEarlyMarginClosedRetainsSourceAndMasksAuthority(t *testing.T) {
	for _, seconds := range []uint32{30, 53, 54, 60, 70} {
		t.Run(strconv.Itoa(int(seconds)), func(t *testing.T) {
			c, lease := marginClientV4(t, seconds)
			lastGrant, lastEvent := c.lastGrant, c.lastEvent
			for range 100 {
				c.closeEarlyMargin("test_margin")
				c.notifyEarlyRenewal()
				o, err := c.ObserveAcquisition()
				if err != nil || o.State != AcquisitionMarginClosed || o.ObservedEpoch != lease.Epoch || o.ListenerAddress != lease.Event.Address || !reflect.DeepEqual(o.Lease, Lease{}) {
					t.Fatal("masked lease escaped", o, err)
				}
				if _, err := c.Current(); !errors.Is(err, ErrUnavailable) {
					t.Fatal("Current exposed masked authority", err)
				}
			}
			if c.failed || c.failure != "" || c.epoch != lease.Epoch || c.lastGrant != lastGrant || c.lastEvent != lastEvent || !reflect.DeepEqual(c.lease, lease) || c.early.marginEpoch != lease.Epoch || c.early.responseBy != 0 {
				t.Fatal("margin closure changed source authority")
			}
			if _, err := c.requestEarlyRenewal(lease.Epoch, 0); !errors.Is(err, errEarlyMargin) || c.early.responseBy != 0 {
				t.Fatal("masked source reached signal path", err)
			}
			if l, state, err := c.AcquisitionSnapshot(); err != nil || state != AcquisitionMarginClosed || !reflect.DeepEqual(l, Lease{}) {
				t.Fatal("atomic snapshot lost margin state", l, state, err)
			}
		})
	}
}

func TestEarlyMarginRejectsExportedRenewAndRebind(t *testing.T) {
	c, _ := marginClientV4(t, 70)
	// No child exists in this fixture: reaching Process.Signal would panic.
	for range 100 {
		if !errors.Is(c.Renew(), ErrUnavailable) || !errors.Is(c.Rebind(), ErrUnavailable) {
			t.Fatal("explicit signal bypassed WAIT-only closure")
		}
	}
}

func TestEarlySupportedMinimumAndNaturalRemainingAuthority(t *testing.T) {
	sec := int64(time.Second)
	for _, tc := range []struct {
		seconds   uint32
		remaining int64
		eligible  bool
	}{
		{30, 30 * sec, false}, {53, 53 * sec, false}, {54, 54 * sec, false},
		{60, 60 * sec, false}, {70, 70 * sec, false}, {71, 35 * sec, true},
		{71, 35*sec - 1, false}, {72, 36 * sec, true}, {120, 60 * sec, true},
		{3600, 1800*sec - 100000000, true},
	} {
		_, ok := earlySupportedRenewalDue(1000*sec, Lease{Event: Event{Seconds: tc.seconds, BootNS: 1000 * sec}, DeadlineBootNS: 1000*sec + tc.remaining})
		if ok != tc.eligible {
			t.Fatalf("lease=%d remaining=%d eligible=%v", tc.seconds, tc.remaining, ok)
		}
	}
}

func TestEarlyMarginObservationAddressAndEpochAreAtomic(t *testing.T) {
	c, _ := marginClientV4(t, 53)
	done, failures := make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(done)
		for epoch := uint64(2); epoch <= 200; epoch++ {
			now, err := bootNow()
			if err != nil {
				failures <- err
				return
			}
			address := "198.18.1.10"
			if epoch%2 == 0 {
				address = "198.18.1.11"
			}
			env := replace(replace(goodEnv(), "new_ip_address", address), "new_dhcp_lease_time", "53")
			e, err := HookEvent(env, now)
			if err == nil {
				err = c.acceptEvent(e, now)
			}
			if err != nil {
				failures <- err
				return
			}
		}
	}()
	for {
		o, err := c.ObserveAcquisition()
		want := "198.18.1.10/24"
		if o.ObservedEpoch%2 == 0 {
			want = "198.18.1.11/24"
		}
		if err != nil || o.State != AcquisitionMarginClosed || o.ListenerAddress != want || !reflect.DeepEqual(o.Lease, Lease{}) {
			t.Fatal("mixed socket hint and grant epoch", o, err)
		}
		select {
		case <-done:
			select {
			case err := <-failures:
				t.Fatal(err)
			default:
			}
			return
		default:
		}
	}
}

func TestEarlyMarginSafeNaturalHookResumesWithOriginalDeadlineRule(t *testing.T) {
	c, old := marginClientV4(t, 53)
	stale := old.Event
	if c.acceptEvent(stale, stale.BootNS) == nil || c.early.marginEpoch != old.Epoch {
		t.Fatal("same hook removed mask")
	}
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	e, err := HookEvent(replace(goodEnv(), "reason", "RENEW"), now)
	if err != nil || c.acceptEvent(e, now) != nil {
		t.Fatal("safe natural hook rejected", err)
	}
	o, err := c.ObserveAcquisition()
	if err != nil || o.State != AcquisitionGranted || o.ObservedEpoch != old.Epoch+1 || o.ListenerAddress != "" || c.early.marginEpoch != 0 || c.failed || o.Lease.DeadlineBootNS != old.Event.BootNS+int64(e.Seconds)*int64(time.Second) {
		t.Fatal("natural hook did not restore only fresh evidence", o, err)
	}
	// Closing an otherwise eligible grant also masks only the same epoch.
	c.closeEarlyMargin("test_forced_margin")
	if o, err = c.ObserveAcquisition(); err != nil || o.State != AcquisitionMarginClosed || o.ObservedEpoch != old.Epoch+1 {
		t.Fatal("forced closure did not revoke", o, err)
	}
}

func TestEarlyMarginNeverPromotesExpiredFailedOrDisabledSource(t *testing.T) {
	for _, mode := range []string{"expired", "failed", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := marginClientV4(t, 53)
			now, _ := bootNow()
			switch mode {
			case "expired":
				c.lease.DeadlineBootNS = now - 1
			case "failed":
				c.failAt("test_owner_exit")
			case "disabled":
				c.early = nil
			}
			c.closeEarlyMargin("test_margin")
			o, err := c.ObserveAcquisition()
			if o.State == AcquisitionMarginClosed || mode != "disabled" && o.State == AcquisitionGranted {
				t.Fatal("dead or disabled source promoted", mode, o, err)
			}
			if mode == "disabled" && c.failed {
				t.Fatal("default-off path acquired failure")
			}
			if o.ListenerAddress != "" {
				t.Fatal("socket hint escaped margin-only observation")
			}
		})
	}
}

func TestEarlyMarginForcedClosurePreservesPendingTimeout(t *testing.T) {
	c, _ := marginClientV4(t, 120)
	now, _ := bootNow()
	c.early.responseBy = now + int64(earlyResponse)
	c.early.pendingEpoch = c.epoch
	c.closeEarlyMargin("test_forced_margin")
	if c.early.marginEpoch != 0 || c.failed || c.early.responseBy != now+int64(earlyResponse) {
		t.Fatal("forced margin replaced pending response timeout")
	}
	c.early.responseBy = now - 1
	c.closeEarlyMargin("test_forced_margin")
	if !c.failed || c.failure != "early_response_timeout" || c.early.marginEpoch != 0 {
		t.Fatal("expired response timeout bypassed")
	}
}

func TestEarlyMarginWorkerWaitsWithoutSignalsOrTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := startEarlyTestOwner(ctx)
		h.mu.Lock()
		h.o = earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionMarginClosed, ObservedEpoch: 1}}
		h.mu.Unlock()
		h.wake <- struct{}{}
		synctest.Wait()
		for range 100 {
			h.wake <- struct{}{}
			synctest.Wait()
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if len(h.signalSnapshot()) != 0 || h.failureSnapshot() != "" {
			t.Fatal("masked owner signalled or failed")
		}
		h.grant(2, 60*time.Second)
		time.Sleep(16 * time.Second)
		synctest.Wait()
		if !reflect.DeepEqual(h.signalSnapshot(), []uint64{2}) {
			t.Fatal("fresh natural grant did not rearm", h.signalSnapshot())
		}
		cancel()
		<-h.exited
	})
}

func TestEarlyMarginUnsafeWorkerClosesTimerAndWaitsForNewHook(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		wake, done := make(chan struct{}, 1), make(chan struct{})
		var masked atomic.Bool
		var signals, closes, timers atomic.Int32
		start := time.Now()
		clock := func() int64 { return int64(100*time.Second + time.Since(start)) }
		go func() {
			defer close(done)
			runEarlyRenewal(ctx, wake, nil, func() (int64, error) { return clock(), nil }, func(int64) (earlyRenewalObservation, error) {
				if masked.Load() {
					return earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionMarginClosed, ObservedEpoch: 1}}, nil
				}
				return earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionGranted, ObservedEpoch: 1, Lease: Lease{Event: Event{Seconds: 30, BootNS: clock()}, Epoch: 1, DeadlineBootNS: clock() + int64(30*time.Second)}}}, nil
			}, func(uint64, int64) (int64, error) { signals.Add(1); return 0, nil }, func(stage string) {
				if stage != "early_short_lease" {
					t.Error(stage)
				}
				closes.Add(1)
				masked.Store(true)
			}, func() (earlyRenewalTimer, error) { timers.Add(1); return newEarlyTestTimer(clock), nil })
		}()
		synctest.Wait()
		for range 100 {
			wake <- struct{}{}
			synctest.Wait()
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if signals.Load() != 0 || closes.Load() != 1 || timers.Load() != 0 {
			t.Fatal("WAIT-only emitted signal/timer or repeated closure", signals.Load(), closes.Load(), timers.Load())
		}
		cancel()
		<-done
	})
}
