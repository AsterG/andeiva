//go:build linux

package previewruntime

import (
	"context"
	"testing"
	"time"
)

func TestRoutedDHCPNoLeaseV1ConfirmedServiceReacquiresWithoutRestart(t *testing.T) {
	x := newRoutedDeferredTestV4(t)
	_, lease := routedDeferredFixtureV4(t)
	x.send(t, 1, "activate", nil)
	e := x.event(t, "acquiring")
	x.send(t, 2, "confirm", e.Acquisition)
	x.event(t, "active")
	first, err := x.reader.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	x.source.set(routedDHCPOwnerLeaseV3{}, routedDHCPNoLeaseV1{lease.Epoch})
	for range 2 {
		f, err := x.reader.Current(context.Background())
		epoch, ok := routedDHCPNoLeaseEpochV1(err)
		if !ok || epoch != lease.Epoch || f != (RoutedDHCPOwnerFactV3{}) || x.reader.reader.dead || x.stops.Load() != 0 {
			t.Fatal("revocation killed service or produced grant", err)
		}
	}
	lease.Epoch++
	lease.Event.BootNS += int64(time.Second)
	x.now.Add(int64(time.Second))
	x.source.set(lease, nil)
	next, err := x.reader.Current(context.Background())
	if err != nil || next.Epoch != lease.Epoch || next.Fact.Sequence <= first.Fact.Sequence || next.Fact.Owner != first.Fact.Owner || next.Fact.DeadlineBootNS != lease.DeadlineBootNS || x.starts.Load() != 1 {
		t.Fatal("fresh grant required a restart or extended deadline", err)
	}
	x.childAlive.Store(false)
	if _, err = x.reader.Current(context.Background()); err == nil {
		t.Fatal("dead acquisition still granted")
	} else if _, ok := routedDHCPNoLeaseEpochV1(err); ok {
		t.Fatal("death became no-lease")
	}
	x.finish(t, false)
}

func TestRoutedDHCPNoLeaseV1RejectsReplayedRevokedEpoch(t *testing.T) {
	x := newRoutedDeferredTestV4(t)
	_, lease := routedDeferredFixtureV4(t)
	x.send(t, 1, "activate", nil)
	e := x.event(t, "acquiring")
	x.send(t, 2, "confirm", e.Acquisition)
	x.event(t, "active")
	x.source.set(routedDHCPOwnerLeaseV3{}, routedDHCPNoLeaseV1{lease.Epoch})
	if _, err := x.reader.Current(context.Background()); err == nil {
		t.Fatal("revocation granted")
	}
	x.source.set(lease, nil)
	if _, err := x.reader.Current(context.Background()); err == nil || !x.reader.reader.dead {
		t.Fatal("revoked epoch reappeared")
	}
	x.finish(t, false)
}

func TestRoutedDHCPNoLeaseV1OwnerRejectsUnprovenState(t *testing.T) {
	for _, mode := range []string{"version", "zero-epoch", "mixed-waiting", "mixed-lease", "mixed-unavailable", "missing-identity", "wrong-identity", "replay", "old-epoch", "dead", "cancel", "eof"} {
		t.Run(mode, func(t *testing.T) {
			binding, lease := routedDeferredFixtureV4(t)
			qr, qw := routedOwnerPipeV3(t)
			rr, rw := routedOwnerPipeV3(t)
			r, err := newRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4{Request: qw, Reply: rr}, binding, func() bool { return mode != "dead" }, func() (int64, error) { return int64(11 * time.Second), nil })
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if mode == "old-epoch" {
				r.reader.facts.revokedEpoch = 2
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer rw.Close()
				if !routedDHCPOwnerScannerV3(qr).Scan() {
					return
				}
				id := RoutedDHCPAcquisitionIdentityV4{50, 124}
				reply := routedDHCPDeferredReplyV4{Version: 4, Incarnation: binding.Owner.Incarnation, Sequence: 1, Acquisition: &id, NoLease: &routedDHCPNoLeaseWireV1{1, 1}}
				switch mode {
				case "version":
					reply.NoLease.Version = 2
				case "zero-epoch":
					reply.NoLease.ObservedEpoch = 0
				case "mixed-waiting":
					v := 1
					reply.WaitingVersion = &v
				case "mixed-lease":
					reply.Lease = &lease
				case "mixed-unavailable":
					reply.Unavailable = true
				case "missing-identity":
					reply.Acquisition = nil
				case "wrong-identity":
					id.PID = int32(binding.Owner.PID)
				case "replay":
					reply.Sequence = 0
				case "cancel":
					cancel()
				case "eof":
					return
				}
				_ = routedDHCPOwnerWriteV3(rw, reply)
			}()
			f, err := r.Current(ctx)
			if _, noLease := routedDHCPNoLeaseEpochV1(err); err == nil || noLease || f.Epoch != 0 {
				t.Fatal("unproven no-lease accepted", mode, err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("reply writer did not drain")
			}
		})
	}
}

func TestRoutedDHCPNoLeaseV1ResourceViewPermitsNoUDP(t *testing.T) {
	c, id, profile, _ := serviceSocketModelV1()
	phase := routedDHCPServicePhaseV1{noLeaseEpoch: 2}
	if !phase.withoutLease() || phase.initialWaiting {
		t.Fatal("revocation conflated with initial waiting")
	}
	if matchRoutedDHCPSocketsV1(c, id, profile, RoutedDHCPOwnerFactV3{}, phase.withoutLease()) == nil {
		t.Fatal("no-lease service allowed UDP")
	}
	c.udp, c.tables = nil, nil
	if matchRoutedDHCPSocketsV1(c, id, profile, RoutedDHCPOwnerFactV3{}, phase.withoutLease()) != nil {
		t.Fatal("bounded acquisition RAW inventory rejected")
	}
	c.packet[0].Interface++
	if matchRoutedDHCPSocketsV1(c, id, profile, RoutedDHCPOwnerFactV3{}, phase.withoutLease()) == nil {
		t.Fatal("no-lease service allowed foreign raw interface")
	}
}
