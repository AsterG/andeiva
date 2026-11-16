package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

// Real private protocol over net.Pipe with a simulated selected grant. This
// checks admission/deadlines, not a native owner, kernel state or DHCP traffic.
type dhcpSchedulerPeerV4 struct {
	requests         atomic.Int32
	live             atomic.Bool
	firstLiveSuccess chan struct{}
	done             chan struct{}
}

func dhcpSchedulerFixtureV4(t *testing.T, currentDelay, liveDelay time.Duration) (*RoutedDHCPControllerV3, *dhcpSchedulerPeerV4) {
	t.Helper()
	snapshot := dhcpRuntimeSnapshotV3(t)
	a, b := net.Pipe()
	peer := &dhcpSchedulerPeerV4{done: make(chan struct{}), firstLiveSuccess: make(chan struct{})}
	go func() {
		defer close(peer.done)
		defer b.Close()
		scan := bufio.NewScanner(b)
		scan.Buffer(make([]byte, 4096), firewallipc.RoutedFrameMaxV3)
		if !scan.Scan() {
			return
		}
		hello, err := firewallipc.DecodeRoutedHelloV3(scan.Bytes(), false)
		if err != nil {
			return
		}
		hello.Run, hello.Epoch = hello.RuntimeRun, 1
		if json.NewEncoder(b).Encode(hello) != nil {
			return
		}
		last := hello.Epoch << 32
		for scan.Scan() {
			q, _, err := firewallipc.DecodeRoutedRequestV3(scan.Bytes(), hello.Run, hello.Namespace, last)
			if err != nil {
				return
			}
			last = q.Sequence
			peer.requests.Add(1)
			var payload any = struct{}{}
			switch q.Verb {
			case "dhcp_current":
				time.Sleep(currentDelay)
				payload = firewallipc.RoutedDHCPGrantV3{Epoch: 1, Snapshot: snapshot}
			case "dhcp_live":
				time.Sleep(liveDelay)
			default:
				return
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				return
			}
			reply := firewallipc.RoutedReplyV3{ProtocolVersion: firewallipc.RoutedProtocolV3, Run: q.Run, Sequence: q.Sequence, Namespace: q.Namespace, Domain: "routed", Verb: q.Verb, Payload: raw}
			if json.NewEncoder(b).Encode(reply) != nil {
				return
			}
			if q.Verb == "dhcp_live" && !peer.live.Swap(true) {
				close(peer.firstLiveSuccess)
			}
		}
	}()
	client, err := firewallipc.ConnectRoutedDHCPV3(context.Background(), a, snapshot.Identity.RunID, snapshot.Identity.Namespace)
	if err != nil {
		_ = a.Close()
		<-peer.done
		t.Fatal(err)
	}
	c := &RoutedDHCPControllerV3{remote: &routedDHCPRemoteV3{client: client}, work: snapshot.Hash, grant: configpoc.RoutedDHCPGrantV3{Epoch: 1, Snapshot: snapshot}}
	t.Cleanup(func() {
		c.closeSchedulerV4()
		_ = client.Close()
		<-peer.done
	})
	return c, peer
}

func TestRoutedDHCPSchedulerV4SkipsBusyLaneBeforeDeadline(t *testing.T) {
	c, peer := dhcpSchedulerFixtureV4(t, 2*time.Second, 0)
	c.mu.Lock()
	c.scheduleV4(true)
	// Mutex waits are not durable blocks in synctest; this contention case
	// deliberately uses a bounded real clock rather than hanging its bubble.
	time.Sleep(2 * time.Second)
	requestsWhileBusy := peer.requests.Load()
	c.mu.Unlock()
	if requestsWhileBusy != 0 {
		t.Fatalf("busy controller sent %d requests", requestsWhileBusy)
	}
	// Wait for the actual reply, allowing scheduling jitter without changing
	// the individual RPC's three-second deadline.
	select {
	case <-peer.firstLiveSuccess:
	case <-time.After(8 * time.Second):
		t.Fatal("controller lock wait consumed the scheduler's RPC budget")
	}
}

func TestRoutedDHCPSchedulerV4CancelBusyLaneDoesNotWaitForUnlock(t *testing.T) {
	c, peer := dhcpSchedulerFixtureV4(t, 0, 0)
	c.mu.Lock()
	c.scheduleV4(true)
	time.Sleep(20 * time.Millisecond)
	c.scheduleV4(false)
	stopped := false
	select {
	case <-c.scheduleDone:
		stopped = true
	case <-time.After(200 * time.Millisecond):
	}
	c.mu.Unlock()
	if !stopped || peer.requests.Load() != 0 {
		t.Fatal("canceled scheduler queued behind the occupied controller")
	}
}
func TestRoutedDHCPSchedulerV4PreservesThreeSecondDeadline(t *testing.T) {
	for _, tt := range []struct {
		name          string
		current, live time.Duration
		requests      int32
	}{
		{"single_rpc", 4 * time.Second, 0, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, peer := dhcpSchedulerFixtureV4(t, tt.current, tt.live)
				c.scheduleV4(true)
				time.Sleep(3100 * time.Millisecond)
				synctest.Wait()
				_, err := c.remote.Current(context.Background())
				if !errors.Is(err, firewallipc.ErrChannel) || peer.live.Load() || peer.requests.Load() != tt.requests {
					t.Fatalf("deadline did not fence: err=%v live=%v requests=%d", err, peer.live.Load(), peer.requests.Load())
				}
				if c.remote.client.IntegrityPublicationAllowedV1() || c.remote.client.IntegrityClosingAllowedV1() {
					t.Fatal("expired scheduler retained qualification")
				}
			})
		})
	}
}

// Err is first observed by the scheduler after TryLock. Cancel at that exact
// boundary without adding a production hook or relying on a timing race.
type dhcpAdmissionCancelContextV4 struct {
	context.Context
	cancel     context.CancelFunc
	controller *RoutedDHCPControllerV3
	checked    bool
	lockHeld   bool
}

func (c *dhcpAdmissionCancelContextV4) Err() error {
	c.cancel()
	c.checked = true
	c.lockHeld = !c.controller.mu.TryLock()
	if !c.lockHeld {
		c.controller.mu.Unlock()
	}
	return c.Context.Err()
}

func TestRoutedDHCPSchedulerV4CancelAtAdmissionReleasesLane(t *testing.T) {
	c, peer := dhcpSchedulerFixtureV4(t, 0, 0)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &dhcpAdmissionCancelContextV4{Context: parent, cancel: cancel, controller: c}
	c.reconcileScheduledV4(ctx)
	if !ctx.checked || !ctx.lockHeld || peer.requests.Load() != 0 {
		t.Fatal("cancellation was not checked inside admission before RPC")
	}
	if !c.mu.TryLock() {
		t.Fatal("cancellation retained the controller lane")
	}
	c.mu.Unlock()
}

func TestRoutedDHCPSchedulerV4BusyLaneDoesNotInspectContext(t *testing.T) {
	c, peer := dhcpSchedulerFixtureV4(t, 0, 0)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &dhcpAdmissionCancelContextV4{Context: parent, cancel: cancel, controller: c}
	c.mu.Lock()
	c.reconcileScheduledV4(ctx)
	c.mu.Unlock()
	if ctx.checked || peer.requests.Load() != 0 {
		t.Fatal("busy tick entered deadline/RPC work")
	}
	// A skipped tick must leave the authenticated channel usable.
	if _, err := c.remote.Current(context.Background()); err != nil {
		t.Fatalf("busy tick damaged channel: %v", err)
	}
}
