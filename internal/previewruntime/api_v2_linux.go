//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

// OperationsRuntimeOptionsV2 contains only trusted assembly resources. Store,
// pool roots, identities and BootID are never populated from HTTP requests.
type OperationsRuntimeOptionsV2 struct {
	RoutedDHCP       bool // Explicit trusted grouped profile; requires inventory and integrity.
	RoutedInventory  bool // Trusted grouped assembly requires the helper-only inventory capability.
	Store            *os.Root
	Budget           configpoc.BudgetV2
	Auth             *adminauth.Manager
	Local            []configpoc.Engine
	Runtime          configpoc.RuntimeOptionsV2
	Origin           string
	Static           http.Handler
	NetworkInventory func(context.Context) (networkinventory.Snapshot, error)
}
type OperationsRuntimeV2 struct {
	Handler http.Handler
	Service *configpoc.ServiceV2
	client  *firewallipc.ClientV2
}

func (r *OperationsRuntimeV2) Close() error {
	if r == nil {
		return nil
	}
	var serviceErr, clientErr error
	if r.Service != nil {
		serviceErr = r.Service.Close()
	}
	if r.client != nil {
		clientErr = r.client.Close()
	}
	return errors.Join(serviceErr, clientErr)
}

// OpenOperationsRuntimeV2 authenticates the real helper socket and selects one
// v2 service. It neither opens v1 state nor performs bootstrap outside Intent.
// Existing cold-boot reservation fences remain enforced by the coordinator.
func OpenOperationsRuntimeV2(ctx context.Context, m Metadata, ids Identities, options OperationsRuntimeOptionsV2) (*OperationsRuntimeV2, error) {
	if options.RoutedDHCP || !bootPattern.MatchString(m.BootID) || options.Runtime.BootID != m.BootID {
		return nil, ErrIdentity
	}
	if options.Runtime.Routed != nil && options.Runtime.RoutedIdentity != (networkexecutor.OwnedNamespaceIdentity{UID: ids.HelperUID, GID: ids.IPCGID, Namespace: m.GatewayNamespace, Host: m.HostNamespace, BootID: m.BootID, RunID: m.RunID}) {
		return nil, ErrIdentity
	}
	client, err := connectHelperV2(ctx, m, ids)
	if err != nil {
		return nil, err
	}
	runtime, err := assembleOperationsRuntimeV2(ctx, client, options)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return runtime, nil
}
func assembleOperationsRuntimeV2(ctx context.Context, client *firewallipc.ClientV2, options OperationsRuntimeOptionsV2) (*OperationsRuntimeV2, error) {
	if options.RoutedDHCP || client == nil || options.Store == nil || options.Auth == nil {
		return nil, ErrIdentity
	}
	observed, err := client.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if err = client.AttachObserved(ctx, observed); err != nil {
		return nil, err
	}
	guard, err := firewalladmin.NewPreparedAbsoluteGuardedEngine(client, firewallipc.AuthorityV2{Client: client})
	if err != nil {
		return nil, err
	}
	service, err := configpoc.OpenRuntimeServiceV2(ctx, options.Store, options.Budget, options.Auth, []configpoc.Engine{guard}, options.Local, options.Runtime)
	if err != nil {
		return nil, err
	}
	handler, err := adminapi.NewOperationsV2(adminapi.Options{Origin: options.Origin, Auth: options.Auth, Static: options.Static, FirewallRuleState: true, NetworkInventory: options.NetworkInventory}, service)
	if err != nil {
		return nil, errors.Join(err, service.Close())
	}
	return &OperationsRuntimeV2{Handler: handler, Service: service, client: client}, nil
}
