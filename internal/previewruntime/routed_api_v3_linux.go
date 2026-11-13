//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net"
	"net/http"
	"syscall"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type RoutedOperationsRuntimeV3 struct {
	Handler            http.Handler
	Service            *configpoc.ServiceV2
	routed             *firewallipc.RoutedClientV3
	legacy             *firewallipc.ClientV2
	integrityScheduler *routedIntegritySchedulerV3
}

// Close releases only this management writer and its channels. Namespace,
// listeners, effective rules and the independent helper guardian remain owned
// by the supervisor/helper; none is removed by management shutdown.
func (r *RoutedOperationsRuntimeV3) Close() error {
	if r == nil {
		return nil
	}
	if r.integrityScheduler != nil {
		r.integrityScheduler.Close()
	}
	var se, re, le error
	if r.Service != nil {
		se = r.Service.Close()
	}
	if r.routed != nil {
		re = r.routed.Close()
	}
	if r.legacy != nil {
		le = r.legacy.Close()
	}
	return errors.Join(se, re, le)
}

// OpenRoutedOperationsRuntimeV3 requires the capless API process, pinned shared
// storage and the authenticated helper PID. The v3 handshake precedes all store
// opening. Both inherited sockets transfer to this factory on every path;
// independent pool/root handles and local engines remain caller-owned.
// This factory does not activate a listener, provision storage or enable a unit.
func OpenRoutedOperationsRuntimeV3(ctx context.Context, m Metadata, ids Identities, routed, legacy *net.UnixConn, routedPID, legacyPID int32, o OperationsRuntimeOptionsV2) (*RoutedOperationsRuntimeV3, error) {
	return openRoutedOperationsModeV3(ctx, m, ids, routed, legacy, routedPID, legacyPID, o, false)
}

// OpenRoutedIntegrityOperationsRuntimeV3 requires the negotiated private control gate.
// It never falls back to the legacy full-reader helper profile.
func OpenRoutedIntegrityOperationsRuntimeV3(ctx context.Context, m Metadata, ids Identities, routed, legacy *net.UnixConn, routedPID, legacyPID int32, o OperationsRuntimeOptionsV2) (*RoutedOperationsRuntimeV3, error) {
	return openRoutedOperationsModeV3(ctx, m, ids, routed, legacy, routedPID, legacyPID, o, true)
}
func openRoutedOperationsModeV3(ctx context.Context, m Metadata, ids Identities, routed, legacy *net.UnixConn, routedPID, legacyPID int32, o OperationsRuntimeOptionsV2, integrity bool) (*RoutedOperationsRuntimeV3, error) {
	fail := func() (*RoutedOperationsRuntimeV3, error) {
		if routed != nil {
			_ = routed.Close()
		}
		if legacy != nil {
			_ = legacy.Close()
		}
		return nil, ErrIdentity
	}
	if (o.RoutedInventory && (!integrity || o.NetworkInventory != nil)) || ctx == nil || ctx.Err() != nil || routed == nil || legacy == nil || !distinctRoutedChannelsV3(routed, legacy) || m.ValidateRouted() != nil || ids.Validate() != nil || checkPrivileges(ids, false) != nil {
		return fail()
	}
	identity := networkexecutor.OwnedNamespaceIdentity{UID: ids.HelperUID, GID: ids.IPCGID, Namespace: m.GatewayNamespace, Host: m.HostNamespace, BootID: m.BootID, RunID: m.RunID}
	if o.Store == nil || o.Auth == nil || o.Runtime.Integrity != nil || o.Runtime.Routed != nil || o.Runtime.RoutedIdentity != (networkexecutor.OwnedNamespaceIdentity{}) || o.Runtime.BootID != m.BootID || !o.Runtime.GuardDeadlines || o.Runtime.SharedReader == nil || o.Runtime.SharedReader.OwnerUID != ids.APIUID || o.Runtime.SharedReader.CheckDirectory(o.Store) != nil || o.Runtime.Pools.Admission == nil || o.Runtime.Pools.Plan == nil || o.Runtime.Pools.Emergency == nil {
		return fail()
	}
	host, e := namespaceID("/proc/self/ns/net")
	if e != nil || host != m.HostNamespace {
		return fail()
	}
	return connectRoutedOperationsModeV3(ctx, m, ids, routed, legacy, routedPID, legacyPID, identity, o, integrity)
}

func connectRoutedOperationsV3(ctx context.Context, m Metadata, ids Identities, routed, legacy *net.UnixConn, routedPID, legacyPID int32, identity networkexecutor.OwnedNamespaceIdentity, o OperationsRuntimeOptionsV2) (*RoutedOperationsRuntimeV3, error) {
	return connectRoutedOperationsModeV3(ctx, m, ids, routed, legacy, routedPID, legacyPID, identity, o, false)
}
func connectRoutedOperationsModeV3(ctx context.Context, m Metadata, ids Identities, routed, legacy *net.UnixConn, routedPID, legacyPID int32, identity networkexecutor.OwnedNamespaceIdentity, o OperationsRuntimeOptionsV2, integrity bool) (*RoutedOperationsRuntimeV3, error) {
	connect := ConnectInheritedRoutedV3
	if integrity {
		connect = ConnectInheritedRoutedIntegrityV3
	}
	if o.RoutedInventory {
		if !integrity || o.NetworkInventory != nil {
			if routed != nil {
				_ = routed.Close()
			}
			if legacy != nil {
				_ = legacy.Close()
			}
			return nil, ErrIdentity
		}
		connect = ConnectInheritedRoutedInventoryV3
	}
	client, e := connect(ctx, routed, ids.HelperUID, ids.IPCGID, routedPID, m.RunID, m.GatewayNamespace)
	if e != nil {
		if legacy != nil {
			_ = legacy.Close()
		}
		return nil, e
	}
	compatibility, e := ConnectInheritedV2(ctx, legacy, ids.HelperUID, ids.IPCGID, legacyPID, m.RunID, m.GatewayNamespace, "firewall", artifactDigest)
	if e != nil {
		_ = client.Close()
		return nil, e
	}
	return assembleRoutedOperationsV3(ctx, client, compatibility, identity, o)
}

func assembleRoutedOperationsV3(ctx context.Context, client *firewallipc.RoutedClientV3, legacy *firewallipc.ClientV2, identity networkexecutor.OwnedNamespaceIdentity, o OperationsRuntimeOptionsV2) (result *RoutedOperationsRuntimeV3, err error) {
	// Entry requires a completed v3 handshake. From here both channels belong to
	// this assembly, including every failed initialization path.
	defer func() {
		if err != nil {
			if client != nil {
				_ = client.Close()
			}
			if legacy != nil {
				_ = legacy.Close()
			}
		}
	}()
	if ctx == nil || client == nil || (client.InventoryEnabled() != o.RoutedInventory) || (o.RoutedInventory && o.NetworkInventory != nil) || legacy == nil || o.Store == nil || o.Auth == nil || o.Runtime.Integrity != nil || o.Runtime.Routed != nil || o.Runtime.RoutedIdentity != (networkexecutor.OwnedNamespaceIdentity{}) || o.Runtime.SharedReader == nil || !o.Runtime.GuardDeadlines || o.Runtime.BootID != identity.BootID || o.Runtime.Pools.Admission == nil || o.Runtime.Pools.Plan == nil || o.Runtime.Pools.Emergency == nil {
		return nil, ErrIdentity
	}
	authority, e := NewRoutedRemoteAuthority(client, identity)
	if e != nil {
		return nil, e
	}
	observed, e := legacy.Snapshot(ctx)
	if e != nil {
		return nil, e
	}
	if e = legacy.AttachObserved(ctx, observed); e != nil {
		return nil, e
	}
	guard, e := firewalladmin.NewPreparedAbsoluteGuardedEngine(legacy, firewallipc.AuthorityV2{Client: legacy})
	if e != nil {
		return nil, e
	}
	runtimeOptions := o.Runtime
	if client.IntegrityEnabled() {
		runtimeOptions.Integrity, e = NewRoutedRemoteIntegrityV3(client)
		if e != nil {
			return nil, e
		}
	}
	runtimeOptions.Routed, runtimeOptions.RoutedIdentity = authority, identity
	service, e := configpoc.OpenRuntimeServiceV2(ctx, o.Store, o.Budget, o.Auth, []configpoc.Engine{guard}, o.Local, runtimeOptions)
	if e != nil {
		return nil, e
	}
	if client.InventoryEnabled() {
		o.NetworkInventory = client.Inventory
	}
	handler, e := adminapi.NewOperationsV2(adminapi.Options{Origin: o.Origin, Auth: o.Auth, Static: o.Static, FirewallRuleState: true, NetworkInventory: o.NetworkInventory}, service)
	if e != nil {
		return nil, errors.Join(e, service.Close())
	}
	result = &RoutedOperationsRuntimeV3{Handler: handler, Service: service, routed: client, legacy: legacy}
	if client.IntegrityEnabled() {
		result.integrityScheduler = startRoutedIntegritySchedulerV3(service)
	}
	return result, nil
}

// Duplicated descriptors do not constitute two independently framed channels.
func distinctRoutedChannelsV3(a, b *net.UnixConn) bool {
	if a == nil || b == nil || a == b {
		return false
	}
	identity := func(c *net.UnixConn) (syscall.Stat_t, error) {
		var st syscall.Stat_t
		raw, e := c.SyscallConn()
		if e != nil {
			return st, e
		}
		var inner error
		e = raw.Control(func(fd uintptr) { inner = syscall.Fstat(int(fd), &st) })
		if e != nil {
			return st, e
		}
		if inner != nil {
			return st, inner
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
			return st, ErrIdentity
		}
		return st, nil
	}
	x, e := identity(a)
	if e != nil {
		return false
	}
	y, e := identity(b)
	return e == nil && (x.Dev != y.Dev || x.Ino != y.Ino)
}
