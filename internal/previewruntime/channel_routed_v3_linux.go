//go:build linux

package previewruntime

import (
	"context"
	"net"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

// Peer identity and PID come from the authenticated supervisor launch, never
// from a request. These wrappers do not expose a listener or enable the runtime.
func ConnectInheritedRoutedV3(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, runtimeRun string, namespace uint64) (*firewallipc.RoutedClientV3, error) {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ErrIdentity
	}
	return firewallipc.ConnectRoutedV3(ctx, c, runtimeRun, namespace)
}
func (s *RoutedSessionV3) ServeInheritedRoutedV3(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, runtimeRun string) error {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return ErrIdentity
	}
	return s.ServeRoutedV3(ctx, c, runtimeRun)
}

func ConnectInheritedRoutedIntegrityV3(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, runtimeRun string, namespace uint64) (*firewallipc.RoutedClientV3, error) {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ErrIdentity
	}
	return firewallipc.ConnectRoutedIntegrityV3(ctx, c, runtimeRun, namespace)
}

func ConnectInheritedRoutedInventoryV3(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, runtimeRun string, namespace uint64) (*firewallipc.RoutedClientV3, error) {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ErrIdentity
	}
	return firewallipc.ConnectRoutedInventoryV3(ctx, c, runtimeRun, namespace)
}

func ConnectInheritedRoutedDHCPV3(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, runtimeRun string, namespace uint64) (*firewallipc.RoutedClientV3, error) {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ErrIdentity
	}
	return firewallipc.ConnectRoutedDHCPV3(ctx, c, runtimeRun, namespace)
}

func ConnectInheritedRoutedFreshScopeV3(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, run string, namespace uint64, dhcp bool) (*firewallipc.RoutedClientV3, error) {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ErrIdentity
	}
	return firewallipc.ConnectRoutedFreshScopeV3(ctx, c, run, namespace, dhcp)
}

func ConnectInheritedRoutedRebootScopeV4(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, run string, namespace uint64, dhcp bool) (*firewallipc.RoutedClientV3, error) {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ErrIdentity
	}
	return firewallipc.ConnectRoutedRebootScopeV4(ctx, c, run, namespace, dhcp)
}
