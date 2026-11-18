package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type routedDHCPRemoteV3 struct{ client *firewallipc.RoutedClientV3 }

// One cooperative budget for the complete scheduled attempt. Individual RPCs
// retain their three-second limits; this does not extend lease authority or
// guarantee a bound on non-cancelable store I/O and shutdown.
const routedDHCPReconciliationAttemptBudgetV4 = 30 * time.Second

func (r *routedDHCPRemoteV3) Current(ctx context.Context) (configpoc.RoutedDHCPGrantV3, error) {
	x, err := r.client.Call(ctx, "dhcp_current", firewallipc.RoutedDHCPRequestV3{})
	return configpoc.RoutedDHCPGrantV3{Epoch: x.DHCP.Epoch, Snapshot: x.DHCP.Snapshot}, err
}
func (r *routedDHCPRemoteV3) RenewSameEffective(ctx context.Context, work string, expected configpoc.RoutedDHCPGrantV3, refreshOnly bool) error {
	result, err := r.client.Call(ctx, "dhcp_renew", firewallipc.RoutedDHCPRequestV3{Work: work, Snapshot: expected.Snapshot.Hash, RefreshOnly: refreshOnly})
	got := configpoc.RoutedDHCPGrantV3{Epoch: result.DHCP.Epoch, Snapshot: result.DHCP.Snapshot}
	if err != nil || !reflect.DeepEqual(got, expected) {
		return errors.Join(err, ErrUnavailable)
	}
	return nil
}
func (r *routedDHCPRemoteV3) VerifyClosed(ctx context.Context, s networkexecutor.LeaseSelectedSnapshotV3, state networkexecutor.LeaseSelectedStateV3) error {
	if _, err := networkexecutor.CanonicalLeaseSelectedSnapshotV3(s); err != nil {
		return err
	}
	_, err := r.client.Call(ctx, "dhcp_verify", firewallipc.RoutedDHCPRequestV3{Snapshot: s.Hash, State: state})
	return err
}
func (r *routedDHCPRemoteV3) WithdrawSelected(ctx context.Context, ref configpoc.SelectionReferenceV2) error {
	_, err := r.client.Call(ctx, "dhcp_withdraw", firewallipc.RoutedDHCPRequestV3{Work: ref.WorkHash})
	return err
}
func (r *routedDHCPRemoteV3) ReleaseWithdrawn(ctx context.Context) error {
	_, err := r.client.Call(ctx, "dhcp_retire", firewallipc.RoutedDHCPRequestV3{})
	return err
}

// RoutedDHCPControllerV3 is a trusted assembly lane, not an HTTP handler. It
// serializes selected Prepare -> helper Apply -> selected Applied -> helper Open.
// The selected work blocks conflicting configuration publication until Withdraw.
type routedDHCPSelectedWriterV3 interface {
	Prepare(context.Context) (string, error)
	Applied(context.Context, string) error
	Withdrawn(context.Context, string) error
}

type RoutedDHCPControllerV3 struct {
	mu              sync.Mutex
	remote          *routedDHCPRemoteV3
	writer          routedDHCPSelectedWriterV3
	work            string
	grant           configpoc.RoutedDHCPGrantV3
	recoveryOnly    bool // Controller ownership; incomplete inspection never admits new Work.
	inspectionWake  func() bool
	inspectionWork  string
	inspectionGrant configpoc.RoutedDHCPGrantV3
	scheduleMu      sync.Mutex
	scheduleCancel  context.CancelFunc
	scheduleDone    chan struct{}
	scheduleClosed  bool
}

func (c *RoutedDHCPControllerV3) startIntegritySchedulerV4(service routedIntegrityScheduledServiceV3) *routedIntegritySchedulerV3 {
	c.mu.Lock()
	defer c.mu.Unlock()
	scheduler := startRoutedIntegrityCallbackV4(service, func(call context.Context) error {
		// Same order as Reconcile: controller ownership, then store barrier.
		c.mu.Lock()
		defer c.mu.Unlock()
		err := service.InspectRuntimeV1(call)
		c.afterInspectionV4(err, c.remote.client.DHCPSelectedV4())
		return err
	})
	if c.remote.client.DHCPRenewalEnabledV4() {
		c.inspectionWake = scheduler.WakeV4
	}
	c.scheduleV4(c.remote.client.DHCPSelectedV4())
	return scheduler
}

// Caller holds c.mu. Recovery alone proves nothing: authenticate the fresh
// retained target under closed gates before asking the independent full scan.
func (c *RoutedDHCPControllerV3) wakeClosedInspectionV4(ctx context.Context, got configpoc.RoutedDHCPGrantV3) error {
	if !c.recoveryOnly || c.work == "" || c.inspectionWake == nil || !c.remote.client.DHCPRenewalEnabledV4() || !sameRenewalGrantV4(c.grant, got) || ctx.Err() != nil {
		return configpoc.ErrRecovery
	}
	c.scheduleMu.Lock()
	closed := c.scheduleClosed
	c.scheduleMu.Unlock()
	if closed || c.inspectionWork == c.work && !sameRenewalGrantV4(c.inspectionGrant, got) {
		return configpoc.ErrRecovery
	}
	if err := c.remote.VerifyClosed(ctx, got.Snapshot, networkexecutor.LeaseSelectedTargetV3); err != nil {
		return errors.Join(configpoc.ErrRecovery, err)
	}
	if ctx.Err() == nil && c.inspectionWake() {
		c.inspectionWork, c.inspectionGrant = c.work, got
	}
	return configpoc.ErrRecovery
}

// Caller holds c.mu, as in the production and native full-inspection callbacks.
func (c *RoutedDHCPControllerV3) afterInspectionV4(err error, selected bool) {
	if !c.remote.client.DHCPRenewalEnabledV4() {
		c.recoveryOnly = false
		c.scheduleV4(err == nil && selected)
		return
	}
	c.recoveryOnly = err != nil
	c.scheduleV4(err == nil && selected || err != nil && c.work != "")
}

// This loop exists only after an authenticated complete inspection reports a
// selected DHCP plan. It reads fresh owner/selected facts on every iteration;
// the hint itself cannot authorize Current, Apply or Open.
func (c *RoutedDHCPControllerV3) scheduleV4(selected bool) {
	c.scheduleMu.Lock()
	defer c.scheduleMu.Unlock()
	if c.scheduleClosed {
		return
	}
	if !selected {
		if c.scheduleCancel != nil {
			c.scheduleCancel()
			c.scheduleCancel = nil
		}
		return
	}
	if c.scheduleCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	previous := c.scheduleDone
	done := make(chan struct{})
	c.scheduleCancel, c.scheduleDone = cancel, done
	go func() {
		defer close(done)
		if previous != nil {
			select {
			case <-previous:
			case <-ctx.Done():
				return
			}
		}
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			c.reconcileScheduledV4(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (c *RoutedDHCPControllerV3) reconcileScheduledV4(ctx context.Context) {
	// Inspection owns the same lane. Skip a busy tick so lock contention
	// cannot consume the reconciliation's attempt budget.
	if !c.mu.TryLock() {
		return
	}
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	call, stop := context.WithTimeout(ctx, routedDHCPReconciliationAttemptBudgetV4)
	defer stop()
	_ = c.reconcileLocked(call)
}

func (c *RoutedDHCPControllerV3) closeSchedulerV4() {
	c.scheduleMu.Lock()
	c.scheduleClosed = true
	if c.scheduleCancel != nil {
		c.scheduleCancel()
	}
	done := c.scheduleDone
	c.scheduleMu.Unlock()
	if done != nil {
		<-done
	}
}

func newRoutedDHCPControllerV3(service *configpoc.ServiceV2, client *firewallipc.RoutedClientV3, id networkexecutor.OwnedNamespaceIdentity) (*RoutedDHCPControllerV3, error) {
	if client == nil || !client.DHCPEnabled() {
		return nil, ErrIdentity
	}
	remote := &routedDHCPRemoteV3{client}
	writer, err := configpoc.NewRoutedDHCPSelectedStoreV3(service, id, remote)
	if err != nil {
		return nil, err
	}
	return &RoutedDHCPControllerV3{remote: remote, writer: writer}, nil
}

// Startup has exclusive controller ownership. Bind the existing Work to a
// fresh, stable helper observation before starting workers or serving traffic.
func (c *RoutedDHCPControllerV3) restoreRetainedWorkV4(ctx context.Context) error {
	writer, ok := c.writer.(*configpoc.RoutedDHCPSelectedStoreV3)
	if !ok || !c.remote.client.DHCPRenewalEnabledV4() {
		return ErrIdentity
	}
	work, durable, err := writer.RetainedWorkV4(ctx)
	if err != nil || work == "" {
		return err
	}
	before, err := c.remote.Current(ctx)
	if err != nil || !reflect.DeepEqual(durable, before) && !sameRenewalGrantV4(durable, before) {
		return errors.Join(configpoc.ErrRecovery, err)
	}
	if _, err = c.remote.client.Call(ctx, "dhcp_live", firewallipc.RoutedDHCPRequestV3{Work: work}); err != nil {
		return err
	}
	after, err := c.remote.Current(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || ctx.Err() != nil {
		return errors.Join(configpoc.ErrRecovery, err)
	}
	c.work, c.grant = work, after
	return nil
}

// Reconcile applies at most one fresh authenticated grant. An unchanged grant
// verifies existing authority; an explicitly negotiated same-effective renewal
// refreshes only the operational lease proof while retaining selected L3 work.
func (c *RoutedDHCPControllerV3) Reconcile(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcileLocked(ctx)
}

// Caller holds c.mu and supplies the original bounded operation context.
func (c *RoutedDHCPControllerV3) reconcileLocked(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if c.work != "" {
		if c.recoveryOnly && c.remote.client.DHCPRenewalEnabledV4() {
			// Revoke with retained correlation before any fallible owner read.
			// Recovery is expected: this lane never reports an opened grant.
			err := c.remote.RenewSameEffective(ctx, c.work, c.grant, true)
			if !errors.Is(err, configpoc.ErrRecovery) {
				return errors.Join(configpoc.ErrRecovery, err)
			}
		}
		got, err := c.remote.Current(ctx)
		if err != nil {
			if !c.remote.client.DHCPRenewalEnabledV4() {
				if err = c.withdraw(ctx); err != nil {
					return err
				}
				return c.acquireLocked(ctx)
			}
			// Preserve the last selected L3 work when the read-only owner source
			// is temporarily unavailable. The helper watchdog and expiring gate
			// remain authoritative; this path grants no new forwarding authority.
			return err
		}
		if err == nil && reflect.DeepEqual(got, c.grant) {
			if c.recoveryOnly && c.remote.client.DHCPRenewalEnabledV4() {
				return configpoc.ErrRecovery // Already requested closure before Current.
			}
			_, err = c.remote.client.Call(ctx, "dhcp_live", firewallipc.RoutedDHCPRequestV3{Work: c.work})
			if err == nil {
				return nil
			}
			// The owner may publish a same-effective renewal between Current and
			// Live. Live correctly rejects the now-stale epoch; re-read once so
			// this race does not withdraw an otherwise unchanged selected lease.
			// A different tuple still follows the normal fail-closed withdrawal.
			if c.remote.client.DHCPRenewalEnabledV4() {
				if ctx.Err() != nil {
					return ErrUnavailable
				}
				got, err = c.remote.Current(ctx)
				if err != nil {
					return err
				}
				if reflect.DeepEqual(got, c.grant) {
					// A failed live proof without a changed owner grant does not
					// authorize a new selection or deleting the existing one.
					return configpoc.ErrRecovery
				}
			}
		}
		if err == nil && c.remote.client.DHCPRenewalEnabledV4() && sameRenewalGrantV4(c.grant, got) {
			if err = c.remote.RenewSameEffective(ctx, c.work, got, c.recoveryOnly); err != nil {
				if c.recoveryOnly && errors.Is(err, configpoc.ErrRecovery) {
					return c.wakeClosedInspectionV4(ctx, got)
				}
				return err
			}
			if c.recoveryOnly {
				return errors.Join(configpoc.ErrRecovery, ErrUnavailable)
			}
			c.grant = got
			return nil
		}
		if c.recoveryOnly && c.remote.client.DHCPRenewalEnabledV4() {
			return configpoc.ErrRecovery // A changed tuple cannot retire retained Work here.
		}
		if err := c.withdraw(ctx); err != nil {
			return err
		}
	}
	return c.acquireLocked(ctx)
}

func (c *RoutedDHCPControllerV3) acquireLocked(ctx context.Context) error {
	if c.recoveryOnly || ctx.Err() != nil {
		return configpoc.ErrRecovery
	}
	result, err := c.remote.client.Call(ctx, "dhcp_begin", firewallipc.RoutedDHCPRequestV3{})
	if err != nil {
		return err
	}
	grant := configpoc.RoutedDHCPGrantV3{Epoch: result.DHCP.Epoch, Snapshot: result.DHCP.Snapshot}
	work, err := c.writer.Prepare(ctx)
	if err != nil {
		return err
	}
	c.work = work
	if _, err = c.remote.client.Call(ctx, "dhcp_apply", firewallipc.RoutedDHCPRequestV3{Work: work}); err == nil {
		err = c.writer.Applied(ctx, work)
	}
	if err == nil {
		_, err = c.remote.client.Call(ctx, "dhcp_open", firewallipc.RoutedDHCPRequestV3{Work: work})
	}
	if err != nil {
		return errors.Join(err, c.withdraw(ctx))
	}
	c.grant = grant
	return nil
}

func (c *RoutedDHCPControllerV3) Withdraw(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrIdentity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.withdraw(ctx)
}
func (c *RoutedDHCPControllerV3) withdraw(ctx context.Context) error {
	if c.work == "" {
		return nil
	}
	if err := c.remote.WithdrawSelected(ctx, configpoc.SelectionReferenceV2{WorkHash: c.work}); err != nil {
		return err
	}
	if err := c.writer.Withdrawn(ctx, c.work); err != nil {
		return err
	}
	if err := c.remote.ReleaseWithdrawn(ctx); err != nil {
		return err
	}
	c.work, c.grant = "", configpoc.RoutedDHCPGrantV3{}
	c.inspectionWork, c.inspectionGrant = "", configpoc.RoutedDHCPGrantV3{}
	return nil
}
