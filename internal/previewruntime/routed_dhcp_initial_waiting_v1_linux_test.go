//go:build linux

package previewruntime

import (
	"context"
	"testing"
	"time"
)

func TestRoutedDHCPInitialWaitingV1ConfirmedProducerThenGrant(t *testing.T) {
	x := newRoutedDeferredTestV4(t)
	_, lease := routedDeferredFixtureV4(t)
	x.source.set(routedDHCPOwnerLeaseV3{}, errRoutedDHCPInitialWaitingV1)
	x.send(t, 1, "activate", nil)
	e := x.event(t, "acquiring")
	x.send(t, 2, "confirm", e.Acquisition)
	x.event(t, "active")
	for range 2 {
		fact, err := x.reader.Current(context.Background())
		if err != errRoutedDHCPInitialWaitingV1 || fact.Epoch != 0 || x.reader.reader.dead || x.stops.Load() != 0 {
			t.Fatal("confirmed wait", err)
		}
	}
	x.source.set(lease, nil)
	fact, err := x.reader.Current(context.Background())
	if err != nil || fact.Epoch != lease.Epoch {
		t.Fatal("fresh lease", err)
	}
	x.source.set(routedDHCPOwnerLeaseV3{}, errRoutedDHCPInitialWaitingV1)
	if _, err = x.reader.Current(context.Background()); err == nil || err == errRoutedDHCPInitialWaitingV1 || !x.reader.reader.dead {
		t.Fatal("waiting revived after grant", err)
	}
	x.finish(t, false)
}

func TestRoutedDHCPInitialWaitingV1OwnerRejectsUnprovenWait(t *testing.T) {
	for _, kind := range []string{"unknown-version", "zero-version", "unavailable", "lease", "missing-acquisition", "wrong-acquisition", "replay", "dead", "cancel", "eof", "after-unavailable"} {
		t.Run(kind, func(t *testing.T) {
			binding, lease := routedDeferredFixtureV4(t)
			qr, qw := routedOwnerPipeV3(t)
			rr, rw := routedOwnerPipeV3(t)
			alive := true
			if kind == "dead" {
				alive = false
			}
			r, err := newRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4{Request: qw, Reply: rr}, binding, func() bool { return alive }, func() (int64, error) { return int64(11 * time.Second), nil })
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer rw.Close()
				scan := routedDHCPOwnerScannerV3(qr)
				if !scan.Scan() {
					return
				}
				seq := uint64(1)
				if kind == "after-unavailable" {
					if routedDHCPOwnerWriteV3(rw, routedDHCPDeferredReplyV4{Version: 4, Incarnation: binding.Owner.Incarnation, Sequence: seq, Unavailable: true}) != nil || !scan.Scan() {
						return
					}
					seq++
				}
				version := 1
				id := RoutedDHCPAcquisitionIdentityV4{50, 124}
				reply := routedDHCPDeferredReplyV4{Version: 4, Incarnation: binding.Owner.Incarnation, Sequence: seq, WaitingVersion: &version, Acquisition: &id}
				switch kind {
				case "unknown-version":
					version = 2
				case "zero-version":
					version = 0
				case "unavailable":
					reply.Unavailable = true
				case "lease":
					reply.Lease = &lease
				case "missing-acquisition":
					reply.Acquisition = nil
				case "wrong-acquisition":
					id.PID = int32(binding.Owner.PID)
				case "replay":
					reply.Sequence--
				case "cancel":
					cancel()
				case "eof":
					return
				}
				_ = routedDHCPOwnerWriteV3(rw, reply)
			}()
			if kind == "after-unavailable" {
				if _, err = r.Current(ctx); err == nil || err == errRoutedDHCPInitialWaitingV1 {
					t.Fatal("generic unavailable classified waiting")
				}
			}
			fact, err := r.Current(ctx)
			if err == nil || err == errRoutedDHCPInitialWaitingV1 || fact.Epoch != 0 || !r.reader.dead {
				t.Fatal("unproven wait", kind, err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("reply writer leaked")
			}
		})
	}
}

func TestRoutedDHCPInitialWaitingV1ProducerRequiresConfirmedLiveChild(t *testing.T) {
	for _, kind := range []string{"confirmed", "standby", "unconfirmed", "death-during-read", "terminal"} {
		t.Run(kind, func(t *testing.T) {
			live := true
			s := &routedDHCPDeferredStateV4{confirmed: true, acquisition: &routedDHCPDeferredAcquisitionV4{identity: RoutedDHCPAcquisitionIdentityV4{50, 124}, alive: func() bool { return live }, source: routedDeferredSourceFuncV4(func() (routedDHCPOwnerLeaseV3, error) {
				if kind == "death-during-read" {
					live = false
				}
				return routedDHCPOwnerLeaseV3{}, errRoutedDHCPInitialWaitingV1
			})}}
			switch kind {
			case "standby":
				s.acquisition = nil
			case "unconfirmed":
				s.confirmed = false
			case "terminal":
				s.terminal = true
			}
			_, id, fatal, err := s.current()
			if (err == errRoutedDHCPInitialWaitingV1) != (kind == "confirmed") {
				t.Fatal("producer waiting", kind, err)
			}
			if kind == "confirmed" && (fatal || id.PID != 50) {
				t.Fatal("missing actual acquisition identity")
			}
			if kind == "death-during-read" && !fatal {
				t.Fatal("child death not terminal")
			}
		})
	}
}
