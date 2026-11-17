//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRoutedDHCPMarginV4WaitsWithoutRestartAndRequiresNewEpoch(t *testing.T) {
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
	x.source.set(routedDHCPOwnerLeaseV3{}, routedDHCPMarginClosedV4{lease.Epoch, lease.Event.Address})
	for range 4 {
		fact, err := x.reader.Current(context.Background())
		closed, ok := routedDHCPMarginV4(err)
		if !ok || closed.epoch != lease.Epoch || closed.address != lease.Event.Address || fact != (RoutedDHCPOwnerFactV3{}) || x.reader.reader.dead || x.stops.Load() != 0 {
			t.Fatal("margin state became grant or terminated acquisition", fact, err)
		}
	}
	lease.Epoch++
	lease.Event.BootNS += int64(time.Second)
	x.now.Add(int64(time.Second))
	x.source.set(lease, nil)
	next, err := x.reader.Current(context.Background())
	if err != nil || next.Epoch != lease.Epoch || next.Fact.Sequence <= first.Fact.Sequence || next.Fact.Owner != first.Fact.Owner || x.starts.Load() != 1 {
		t.Fatal("safe natural grant did not recover monotonically", err)
	}
	x.send(t, 3, "stop", nil)
	x.event(t, "stopped")
	x.finish(t, true)
}

func TestRoutedDHCPMarginV4RejectsMalformedAndLegacy(t *testing.T) {
	for _, mode := range []string{"version", "zero_epoch", "bad_address", "network_address", "broadcast_address", "mixed_lease", "mixed_waiting", "mixed_no_lease", "mixed_unavailable", "missing_identity", "wrong_identity", "replayed", "null", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			binding, lease := routedDeferredFixtureV4(t)
			qr, qw := routedOwnerPipeV3(t)
			rr, rw := routedOwnerPipeV3(t)
			r, err := newRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4{Request: qw, Reply: rr}, binding, func() bool { return true }, func() (int64, error) { return int64(11 * time.Second), nil })
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer rw.Close()
				if !routedDHCPOwnerScannerV3(qr).Scan() {
					return
				}
				id := RoutedDHCPAcquisitionIdentityV4{50, 124}
				p := routedDHCPDeferredReplyV4{Version: 4, Incarnation: binding.Owner.Incarnation, Sequence: 1, Acquisition: &id, MarginClosed: &routedDHCPMarginClosedWireV4{4, 1, lease.Event.Address}}
				switch mode {
				case "version":
					p.MarginClosed.Version = 3
				case "zero_epoch":
					p.MarginClosed.ObservedEpoch = 0
				case "bad_address":
					p.MarginClosed.ListenerAddress = "127.0.0.1/24"
				case "network_address":
					p.MarginClosed.ListenerAddress = "198.18.1.0/24"
				case "broadcast_address":
					p.MarginClosed.ListenerAddress = "198.18.1.255/24"
				case "mixed_lease":
					p.Lease = &lease
				case "mixed_waiting":
					v := 1
					p.WaitingVersion = &v
				case "mixed_no_lease":
					p.NoLease = &routedDHCPNoLeaseWireV1{1, 1}
				case "mixed_unavailable":
					p.Unavailable = true
				case "missing_identity":
					p.Acquisition = nil
				case "wrong_identity":
					id.PID = int32(binding.Owner.PID)
				case "replayed":
					p.Sequence = 0
				}
				raw, _ := json.Marshal(p)
				if mode == "null" {
					var members map[string]json.RawMessage
					_ = json.Unmarshal(raw, &members)
					members["margin_closed"] = json.RawMessage("null")
					raw, _ = json.Marshal(members)
				}
				if mode == "legacy" {
					if _, _, err := decodeRoutedDHCPOwnerReplyV3(raw, routedDHCPOwnerRequestV3{3, binding.Owner.Incarnation, 1, "current"}); err == nil {
						t.Error("legacy decoder accepted margin")
					}
					p.Version = 3
					raw, _ = json.Marshal(p)
				}
				_, _ = rw.Write(append(raw, '\n'))
			}()
			fact, err := r.Current(context.Background())
			_, closed := routedDHCPMarginV4(err)
			if err == nil || closed || fact != (RoutedDHCPOwnerFactV3{}) || !r.reader.dead {
				t.Fatal("malformed margin promoted", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("writer not drained")
			}
		})
	}
}

func TestRoutedDHCPMarginV4ListenerAssociationRemainsExact(t *testing.T) {
	c, id, profile, f := serviceSocketModelV1()
	phase := routedDHCPServicePhaseV1{marginEpoch: 2}
	if phase.withoutLease() || matchRoutedDHCPSocketsV1(c, id, profile, f, phase.withoutLease()) != nil {
		t.Fatal("closed-margin owned listener rejected")
	}
	c.udp[0].CreationCgroup++
	if matchRoutedDHCPSocketsV1(c, id, profile, f, phase.withoutLease()) == nil {
		t.Fatal("margin accepted foreign listener")
	}
}
