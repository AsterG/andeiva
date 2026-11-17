//go:build linux

package dhcpclient

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type earlyTestTimer struct {
	clock      func() int64
	timer      *time.Timer
	tick       chan error
	stop, done chan struct{}
}

func newEarlyTestTimer(clock func() int64) *earlyTestTimer {
	t := &earlyTestTimer{clock: clock, timer: time.NewTimer(time.Hour), tick: make(chan error, 1), stop: make(chan struct{}), done: make(chan struct{})}
	t.timer.Stop()
	go func() {
		defer close(t.done)
		for {
			select {
			case <-t.stop:
				return
			case <-t.timer.C:
				select {
				case t.tick <- nil:
				case <-t.stop:
					return
				}
			}
		}
	}()
	return t
}

func (t *earlyTestTimer) arm(at int64) error {
	t.timer.Reset(time.Duration(at - t.clock()))
	return nil
}
func (t *earlyTestTimer) wait() <-chan error { return t.tick }
func (t *earlyTestTimer) close()             { t.timer.Stop(); close(t.stop); <-t.done }

func TestEarlyRenewalFormula(t *testing.T) {
	sec := int64(time.Second)
	for _, tc := range []struct {
		remaining int64
		interval  int64
		ok        bool
	}{{14 * sec, 0, false}, {16*sec - 1, 0, false}, {16 * sec, sec, true}, {60 * sec, 23 * sec, true}, {60*sec + 1, 23 * sec, true}} {
		now := 100 * sec
		due, ok := earlyRenewalDue(now, now+tc.remaining)
		if ok != tc.ok || ok && due-now != tc.interval {
			t.Fatalf("R=%d due=%d ok=%v", tc.remaining, due, ok)
		}
		if ok && due+int64(earlyDispatch+earlyResponse) >= now+tc.remaining-int64(earlyTokenMargin+earlyResponse) {
			t.Fatal("does not preserve the token and response margins")
		}
	}
	for _, pair := range [][2]int64{{0, sec}, {-1, sec}, {sec, sec}, {2 * sec, sec}} {
		if _, ok := earlyRenewalDue(pair[0], pair[1]); ok {
			t.Fatal("invalid clock/deadline accepted")
		}
	}
}

func TestEarlyRenewalShortFirstGrantKeepsStartupLowerBound(t *testing.T) {
	sec := int64(time.Second)
	for _, tc := range []struct {
		lease, arrival int
		eligible       bool
	}{
		{10, 1, false}, {10, 11, false}, {20, 1, true}, {20, 5, false},
		{20, 20, false}, {30, 1, true}, {30, 15, false}, {30, 31, false},
		{60, 1, true}, {60, 44, true}, {60, 45, false},
	} {
		c := &Client{iface: "wan0", pid: 123, lastGrant: 100 * sec, initialWaiting: true}
		now := (100 + int64(tc.arrival)) * sec
		e, err := HookEvent(replace(goodEnv(), "new_dhcp_lease_time", strconv.Itoa(tc.lease)), now)
		if err != nil {
			t.Fatal(err)
		}
		err = c.accept(e, now)
		eligible := false
		if err == nil {
			if c.lease.DeadlineBootNS != (100+int64(tc.lease))*sec {
				t.Fatal("grant extended startup lower bound")
			}
			_, eligible = earlyRenewalDue(now, c.lease.DeadlineBootNS)
		}
		if eligible != tc.eligible {
			t.Fatalf("lease=%d arrival=%d eligible=%v", tc.lease, tc.arrival, eligible)
		}
	}
}

type earlyTestOwner struct {
	mu      sync.Mutex
	wake    chan struct{}
	done    chan struct{}
	exited  chan struct{}
	clock   func() int64
	o       earlyRenewalObservation
	signals []uint64
	failure string
	err     error
}

func startEarlyTestOwner(ctx context.Context) *earlyTestOwner {
	start := time.Now()
	h := &earlyTestOwner{wake: make(chan struct{}, 1), done: make(chan struct{}), exited: make(chan struct{}), o: earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionInitialWaiting}}}
	h.clock = func() int64 { return int64(100*time.Second + time.Since(start)) }
	go func() {
		defer close(h.exited)
		runEarlyRenewal(ctx, h.wake, h.done, func() (int64, error) { return h.clock(), nil }, func(int64) (earlyRenewalObservation, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.o, h.err
		}, func(epoch uint64, due int64) (int64, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.o.Lease.Epoch != epoch {
				return 0, nil
			}
			h.signals = append(h.signals, epoch)
			return h.clock(), nil
		}, func(stage string) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.failure = stage
		}, func() (earlyRenewalTimer, error) { return newEarlyTestTimer(h.clock), nil })
	}()
	return h
}

func (h *earlyTestOwner) grant(epoch uint64, remaining time.Duration) {
	h.mu.Lock()
	h.o = earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionGranted, ObservedEpoch: epoch, Lease: Lease{Epoch: epoch, DeadlineBootNS: h.clock() + int64(remaining)}}, completedEpoch: epoch - 1, completedBootNS: h.clock()}
	h.mu.Unlock()
	h.wake <- struct{}{}
	synctest.Wait()
}

func (h *earlyTestOwner) signalSnapshot() []uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uint64(nil), h.signals...)
}
func (h *earlyTestOwner) failureSnapshot() string { h.mu.Lock(); defer h.mu.Unlock(); return h.failure }
func (h *earlyTestOwner) observationSnapshot() earlyRenewalObservation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.o
}

func TestEarlyRenewalThreeCyclesOnlyHooksAdvanceEvidence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := startEarlyTestOwner(ctx)
		synctest.Wait()
		time.Sleep(time.Hour) // No grant: no timer or periodic signal.
		synctest.Wait()
		if len(h.signalSnapshot()) != 0 || h.failureSnapshot() != "" {
			t.Fatal("timer without a grant")
		}
		for epoch := uint64(1); epoch <= 3; epoch++ {
			h.grant(epoch, 60*time.Second)
			before := h.observationSnapshot()
			time.Sleep(23 * time.Second)
			synctest.Wait()
			if len(h.signalSnapshot()) != int(epoch) || h.signalSnapshot()[epoch-1] != epoch || !reflect.DeepEqual(before, h.observationSnapshot()) {
				t.Fatal("signal changed evidence or wrong number of requests", h.signalSnapshot())
			}
			for range 8 {
				h.wake <- struct{}{}
				synctest.Wait()
			}
			time.Sleep(2 * time.Second)
			synctest.Wait()
			if len(h.signalSnapshot()) != int(epoch) || h.failureSnapshot() != "" {
				t.Fatal("duplicate request while awaiting a hook")
			}
		}
		cancel()
		<-h.exited
		time.Sleep(time.Hour)
		if len(h.signalSnapshot()) != 3 || h.failureSnapshot() != "" {
			t.Fatal("worker survived cancellation")
		}
	})
}

func TestEarlyRenewalUnansweredRequestClosesWithoutRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := startEarlyTestOwner(context.Background())
		h.grant(1, 60*time.Second)
		time.Sleep(28 * time.Second)
		<-h.exited
		if h.failureSnapshot() != "early_response_timeout" || len(h.signalSnapshot()) != 1 || h.o.ObservedEpoch != 1 {
			t.Fatal("missing response did not close once", h.failureSnapshot(), h.signalSnapshot())
		}
		time.Sleep(time.Hour)
		if len(h.signalSnapshot()) != 1 {
			t.Fatal("retry burst after timeout")
		}
	})
}

func TestEarlyRenewalUnsolicitedGrantReplacesOldSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := startEarlyTestOwner(ctx)
		h.grant(1, 60*time.Second)
		time.Sleep(10 * time.Second)
		h.grant(2, 60*time.Second)
		time.Sleep(13 * time.Second)
		synctest.Wait()
		if len(h.signalSnapshot()) != 0 {
			t.Fatal("old epoch signalled")
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if !reflect.DeepEqual(h.signalSnapshot(), []uint64{2}) {
			t.Fatal("new valid hook did not reschedule", h.signalSnapshot())
		}
		cancel()
		<-h.exited
	})
}

func TestEarlyRenewalNoLeaseAndOwnerLossDisarm(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := startEarlyTestOwner(ctx)
			h.grant(1, 60*time.Second)
			h.mu.Lock()
			h.o = earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionNoLease, ObservedEpoch: 1}}
			if unavailable {
				h.err = ErrUnavailable
			}
			h.mu.Unlock()
			h.wake <- struct{}{}
			synctest.Wait()
			time.Sleep(time.Hour)
			synctest.Wait()
			if len(h.signalSnapshot()) != 0 || h.failureSnapshot() != "" {
				t.Fatal("signal without ownership/lease")
			}
			cancel()
			<-h.exited
		})
	}
}

func TestEarlyRenewalRejectsUnsafeSchedule(t *testing.T) {
	sec := int64(time.Second)
	grant := func(epoch uint64, deadline int64) earlyRenewalObservation {
		return earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionGranted, ObservedEpoch: epoch, Lease: Lease{Epoch: epoch, DeadlineBootNS: deadline}}}
	}
	for _, tc := range []struct {
		name string
		at   int64
		o    earlyRenewalObservation
	}{
		{"short", 100 * sec, grant(1, 115*sec)},
		{"dispatch late including resume", 125 * sec, grant(1, 160*sec)},
		{"clock backwards", 0, grant(1, 160*sec)},
		{"epoch replay", 110 * sec, grant(0, 160*sec)},
		{"expired", 161 * sec, grant(1, 160*sec)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s earlyRenewalCycle
			if _, failure := s.next(grant(1, 160*sec), 100*sec); failure != "" {
				t.Fatal(failure)
			}
			if tc.name == "short" {
				s = earlyRenewalCycle{}
			}
			if _, failure := s.next(tc.o, tc.at); failure == "" {
				t.Fatal("unsafe schedule accepted")
			}
		})
	}
}

func TestEarlyRenewalClockAndSignalErrorsRevoke(t *testing.T) {
	for _, clockFailure := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			var stage string
			clock := func() (int64, error) {
				if clockFailure {
					return 0, errors.New("clock")
				}
				return int64(100*time.Second + time.Since(start)), nil
			}
			runEarlyRenewal(context.Background(), nil, nil, clock, func(int64) (earlyRenewalObservation, error) {
				return earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionGranted, ObservedEpoch: 1, Lease: Lease{Epoch: 1, DeadlineBootNS: int64(160 * time.Second)}}}, nil
			}, func(uint64, int64) (int64, error) { return 0, ErrUnavailable }, func(s string) { stage = s }, func() (earlyRenewalTimer, error) {
				return newEarlyTestTimer(func() int64 { n, _ := clock(); return n }), nil
			})
			want := "early_signal"
			if clockFailure {
				want = "early_clock"
			}
			if stage != want {
				t.Fatal(stage)
			}
		})
	}
}

func TestEarlyRenewalLateHookCannotWinDelayedWorker(t *testing.T) {
	sec := int64(time.Second)
	for _, accepted := range []int64{127 * sec, 128*sec - 1, 128 * sec, 129 * sec} {
		s := earlyRenewalCycle{epoch: 1, sentEpoch: 1, responseBy: 128 * sec}
		o := earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionGranted, ObservedEpoch: 2, Lease: Lease{Epoch: 2, DeadlineBootNS: 190 * sec}}, completedEpoch: 1, completedBootNS: accepted}
		_, failure := s.next(o, 130*sec)
		if (failure == "") != (accepted < 128*sec) {
			t.Fatal("late acceptance bypasses pending or timely hook rejected", accepted, failure)
		}
	}
}

func TestEarlyRenewalCompletedRequestSurvivesLaterUnsolicitedHooks(t *testing.T) {
	sec := int64(time.Second)
	s := earlyRenewalCycle{epoch: 1, sentEpoch: 1, responseBy: 128 * sec}
	// Epoch2 was accepted at127; unsolicited epoch3 arrived at129. Completion
	// belongs to the request, not to the latest hook's timestamp or epoch.
	o := earlyRenewalObservation{AcquisitionObservation: AcquisitionObservation{State: AcquisitionGranted, ObservedEpoch: 3, Lease: Lease{Epoch: 3, DeadlineBootNS: 190 * sec}}, completedEpoch: 1, completedBootNS: 127 * sec}
	if _, failure := s.next(o, 130*sec); failure != "" {
		t.Fatal(failure)
	}
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{early: newEarlyRenewal(), iface: "wan0", pid: 123, lastGrant: now - int64(time.Second), epoch: 1}
	c.early.pendingEpoch, c.early.responseBy = 1, now+int64(earlyResponse)
	for range 2 {
		now, err = bootNow()
		if err != nil {
			t.Fatal(err)
		}
		e, err := HookEvent(goodEnv(), now)
		if err != nil || c.acceptEvent(e, now) != nil {
			t.Fatal("valid hook rejected", err)
		}
	}
	if c.early.completedEpoch != 1 || c.early.completedBootNS == 0 || c.early.responseBy != 0 || c.epoch != 3 {
		t.Fatal("completion overwritten by unsolicited grant")
	}
}

func TestEarlyRenewalObservationRechecksClockAfterLock(t *testing.T) {
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{early: newEarlyRenewal(), epoch: 1, lease: Lease{Epoch: 1, DeadlineBootNS: now + int64(time.Minute)}}
	c.early.responseBy = now + int64(5*time.Millisecond)
	c.early.mu.Lock()
	started, result := make(chan struct{}), make(chan error, 1)
	go func() { close(started); _, err := c.observationAt(now); result <- err }()
	<-started
	time.Sleep(10 * time.Millisecond)
	c.early.mu.Unlock()
	if err := <-result; !errors.Is(err, ErrUnavailable) || c.failure != "early_response_timeout" {
		t.Fatal("stale pre-lock clock published authority", err)
	}
}

func TestEarlyRenewalObservationClosesExpiredPendingWithoutWorker(t *testing.T) {
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{early: newEarlyRenewal(), epoch: 1, lease: Lease{Epoch: 1, DeadlineBootNS: now + int64(time.Minute)}}
	c.early.responseBy = now
	if _, err := c.observationAt(now); !errors.Is(err, ErrUnavailable) || !c.failed || c.epoch != 1 || c.failure != "early_response_timeout" {
		t.Fatal("pending expiry published authority or changed epoch", err, c.failure)
	}
}

func TestEarlyRenewalLateHookRejectedBeforeExternalPublication(t *testing.T) {
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{early: newEarlyRenewal(), iface: "wan0", pid: 123, lastGrant: now - int64(time.Second), epoch: 1, lease: Lease{Epoch: 1, DeadlineBootNS: now + int64(time.Minute)}}
	c.early.responseBy = now
	e, err := HookEvent(goodEnv(), now)
	if err != nil {
		t.Fatal(err)
	}
	if c.acceptEvent(e, now) == nil || c.epoch != 1 || c.lastGrant != now-int64(time.Second) {
		t.Fatal("late hook changed authority")
	}
	if _, err := c.ObserveAcquisition(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("late hook visible", err)
	}
}

func TestEarlyBootTimerAbsoluteAndClose(t *testing.T) {
	for _, armed := range []bool{false, true} {
		timer, err := newEarlyBootTimer()
		if err != nil {
			t.Fatal(err)
		}
		if armed {
			now, err := bootNow()
			if err != nil {
				t.Fatal(err)
			}
			if err := timer.arm(now + int64(5*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-timer.wait():
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("BOOTTIME timer did not fire")
			}
		}
		timer.close() // Must also wake and reap a reader on an unarmed timer.
	}
}
