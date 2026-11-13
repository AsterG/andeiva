package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type routedDHCPRemoteV3 struct{ client *firewallipc.RoutedClientV3 }

func (r *routedDHCPRemoteV3) Current(ctx context.Context) (configpoc.RoutedDHCPGrantV3, error) {
	x, err := r.client.Call(ctx, "dhcp_current", firewallipc.RoutedDHCPRequestV3{})
	return configpoc.RoutedDHCPGrantV3{Epoch: x.DHCP.Epoch, Snapshot: x.DHCP.Snapshot}, err
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
type RoutedDHCPControllerV3 struct {
	mu     sync.Mutex
	remote *routedDHCPRemoteV3
	writer *configpoc.RoutedDHCPSelectedStoreV3
	work   string
	grant  configpoc.RoutedDHCPGrantV3
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

// Reconcile applies at most one fresh authenticated grant. Unchanged authority
// is verified without extending the original token. Renewal is serial and
// interrupts WAN while the previous selected work is retired.
func (c *RoutedDHCPControllerV3) Reconcile(ctx context.Context) error {
	if c == nil || ctx == nil {
		return ErrIdentity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.work != "" {
		got, err := c.remote.Current(ctx)
		if err == nil && reflect.DeepEqual(got, c.grant) {
			_, err = c.remote.client.Call(ctx, "dhcp_live", firewallipc.RoutedDHCPRequestV3{Work: c.work})
			if err == nil {
				return nil
			}
		}
		if err := c.withdraw(ctx); err != nil {
			return err
		}
	}
	result, err := c.remote.client.Call(ctx, "dhcp_begin", firewallipc.RoutedDHCPRequestV3{})
	if err != nil {
		return err
	}
	c.grant = configpoc.RoutedDHCPGrantV3{Epoch: result.DHCP.Epoch, Snapshot: result.DHCP.Snapshot}
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
	return nil
}
