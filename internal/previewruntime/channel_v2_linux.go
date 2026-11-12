//go:build linux

package previewruntime

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
)

// connectHelperV2 is deliberately not called by the deployed v1 runtime.
func connectHelperV2(ctx context.Context, m Metadata, ids Identities) (*firewallipc.ClientV2, error) {
	if socketInfo(HelperSocket, ids.HelperUID, ids.IPCGID) != nil {
		return nil, ErrIdentity
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, e := d.DialContext(ctx, "unix", HelperSocket)
	if e != nil {
		return nil, ErrUnavailable
	}
	c, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, ErrIdentity
	}
	if peer(c, ids.HelperUID, ids.IPCGID) != nil || socketInfo(HelperSocket, ids.HelperUID, ids.IPCGID) != nil {
		_ = c.Close()
		return nil, ErrIdentity
	}
	return firewallipc.ConnectV2(ctx, c, m.RunID, m.GatewayNamespace, "firewall", artifactDigest)
}

// serveControllerV2 selects v2 for the lifetime of this helper instance. Its
// SessionV2 owns the single-controller gate and monotonic epoch across reconnects.
func serveControllerV2(ctx context.Context, l *net.UnixListener, m Metadata, ids Identities, s *SessionV2) error {
	if ctx == nil || l == nil || s == nil || s.base == nil || s.base.namespace != m.GatewayNamespace || !ValidRun(m.RunID) {
		return ErrIdentity
	}
	var workers sync.WaitGroup
	var mu sync.Mutex
	var active *net.UnixConn
	done := make(chan struct{})
	defer close(done)
	closeActive := func() {
		mu.Lock()
		if active != nil {
			_ = active.Close()
		}
		mu.Unlock()
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
			closeActive()
		case <-done:
		}
	}()
	defer func() { closeActive(); workers.Wait() }()
	for {
		c, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return ErrUnavailable
		}
		if peer(c, ids.APIUID, ids.APIGID) != nil {
			_ = c.Close()
			continue
		}
		mu.Lock()
		if active != nil {
			mu.Unlock()
			_ = c.Close()
			continue
		}
		active = c
		mu.Unlock()
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() {
				_ = c.Close()
				mu.Lock()
				if active == c {
					active = nil
				}
				mu.Unlock()
			}()
			_ = s.ServeV2(ctx, c, m.RunID)
		}()
	}
}

func inheritedPeerV2(c *net.UnixConn, uid, gid uint32, pid int32) error {
	if c == nil || pid <= 1 || peer(c, uid, gid) != nil {
		return ErrIdentity
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return ErrIdentity
	}
	var inner error
	var got *syscall.Ucred
	e = raw.Control(func(fd uintptr) {
		got, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if e != nil || inner != nil || got == nil || got.Pid != pid {
		return ErrIdentity
	}
	return nil
}

// ConnectInheritedV2 adds the same explicit handshake after the existing launch
// receiver has validated FD provenance, parent, aliases, namespaces and caps.
// Peer parameters come from that trusted launch, never an administrative request.
func ConnectInheritedV2(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, runtimeRun string, namespace uint64, domain string, compile firewallipc.Compiler) (*firewallipc.ClientV2, error) {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, ErrIdentity
	}
	return firewallipc.ConnectV2(ctx, c, runtimeRun, namespace, domain, compile)
}
func (s *SessionV2) ServeInheritedV2(ctx context.Context, c *net.UnixConn, uid, gid uint32, pid int32, runtimeRun string) error {
	if inheritedPeerV2(c, uid, gid, pid) != nil {
		if c != nil {
			_ = c.Close()
		}
		return ErrIdentity
	}
	return s.ServeV2(ctx, c, runtimeRun)
}
