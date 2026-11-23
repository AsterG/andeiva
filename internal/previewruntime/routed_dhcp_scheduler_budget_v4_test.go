package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

func TestRoutedDHCPSchedulerV4SeparateAttemptAndRPCBudgets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := dhcpSchedulerFixtureV4(t, 2*time.Second, 2*time.Second)
		before := c.grant
		start := time.Now()
		c.reconcileScheduledV4(context.Background())
		synctest.Wait()
		if !peer.live.Load() || peer.requests.Load() != 2 || time.Since(start) != 4*time.Second {
			t.Fatalf("sequential RPCs lost independent budgets: live=%v requests=%d elapsed=%v", peer.live.Load(), peer.requests.Load(), time.Since(start))
		}
		if !reflect.DeepEqual(c.grant, before) {
			t.Fatal("attempt budget changed lease authority")
		}
	})
}

func TestRoutedDHCPSchedulerV4CallerDeadlineStillFencesLateReply(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := dhcpSchedulerFixtureV4(t, 2*time.Second, 2*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c.reconcileScheduledV4(ctx)
		if peer.live.Load() || c.work == "" || c.grant.Epoch == 0 {
			t.Fatal("deadline published late success or lost recovery references")
		}
		if _, err := c.remote.Current(context.Background()); !errors.Is(err, firewallipc.ErrChannel) {
			t.Fatal("expired attempt retained channel", err)
		}
		if c.remote.client.IntegrityPublicationAllowedV1() || c.remote.client.IntegrityClosingAllowedV1() {
			t.Fatal("expired attempt retained qualification")
		}
	})
}

func TestRoutedDHCPSchedulerV4ManualCallerBudgetUnchanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := dhcpSchedulerFixtureV4(t, 2*time.Second, 2*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.Reconcile(ctx); err == nil {
			t.Fatal("manual deadline accepted late reply")
		}
		if peer.live.Load() || peer.requests.Load() != 2 || c.work == "" {
			t.Fatal("manual budget or recovery reference changed")
		}
		if _, err := c.remote.Current(context.Background()); !errors.Is(err, firewallipc.ErrChannel) {
			t.Fatal("manual expiry retained channel", err)
		}
	})
}

func TestRoutedDHCPSchedulerV4CloseCancelsActiveAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, peer := dhcpSchedulerFixtureV4(t, 2*time.Second, 2*time.Second)
		c.scheduleV4(true)
		time.Sleep(time.Second)
		synctest.Wait()
		if peer.requests.Load() != 1 {
			t.Fatal("attempt not active")
		}
		c.closeSchedulerV4()
		if peer.live.Load() || !c.mu.TryLock() {
			t.Fatal("close did not drain scheduler")
		}
		c.mu.Unlock()
		if _, err := c.remote.Current(context.Background()); !errors.Is(err, firewallipc.ErrChannel) {
			t.Fatal("cancel did not close channel", err)
		}
		c.scheduleV4(true)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if peer.requests.Load() != 1 {
			t.Fatal("closed scheduler restarted")
		}
	})
}
