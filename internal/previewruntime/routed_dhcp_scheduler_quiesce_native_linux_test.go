//go:build linux

package previewruntime

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Orderly laboratory withdrawal reuses the channel. Management shutdown instead
// intentionally cancels in-flight calls and closes that channel.
func nativeDHCPJobsQuiesceSchedulerV4(c *RoutedDHCPControllerV3) {
	c.mu.Lock()
	c.closeSchedulerV4()
	c.mu.Unlock()
}

func TestRoutedDHCPSchedulerV4OrderlyQuiescenceRetainsChannel(t *testing.T) {
	c, peer := dhcpSchedulerFixtureV4(t, 20*time.Millisecond, 20*time.Millisecond)
	hold := make(chan struct{})
	peer.currentHold.Store(&hold)
	var release sync.Once
	defer release.Do(func() { close(hold) })
	before := c.grant
	c.scheduleV4(true)
	deadline := time.Now().Add(2 * time.Second)
	for peer.requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if peer.requests.Load() != 1 {
		t.Fatal("fixture did not enter the first scheduled RPC")
	}
	// A real clock is required: waiting for c.mu is not a durable synctest block.
	quiesced := make(chan struct{})
	go func() {
		nativeDHCPJobsQuiesceSchedulerV4(c)
		close(quiesced)
	}()
	select {
	case <-quiesced:
		t.Fatal("quiescence cancelled the blocked admitted RPC")
	case <-time.After(10 * time.Millisecond):
	}
	release.Do(func() { close(hold) })
	select {
	case <-quiesced:
	case <-time.After(2 * time.Second):
		t.Fatal("quiescence did not drain the admitted RPC")
	}
	if !peer.live.Load() || peer.requests.Load() != 2 || !reflect.DeepEqual(c.grant, before) {
		t.Fatal("quiescence cancelled an admitted RPC or changed its grant")
	}
	select {
	case <-c.scheduleDone:
	default:
		t.Fatal("scheduler did not drain")
	}
	if _, err := c.remote.Current(context.Background()); err != nil {
		t.Fatal("orderly withdrawal lost its authenticated channel", err)
	}
	requests := peer.requests.Load()
	c.scheduleV4(true)
	time.Sleep(30 * time.Millisecond)
	if peer.requests.Load() != requests || !c.scheduleClosed {
		t.Fatal("quiesced scheduler restarted")
	}
}
