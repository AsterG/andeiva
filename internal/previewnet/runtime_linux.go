package previewnet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/AsterG/andeiva/internal/nftfixture"
)

func checkFixture(ctx context.Context, f fixture) error {
	if e := f.CheckHost(ctx); e != nil {
		return e
	}
	return f.CheckSentinel(ctx)
}

// Run holds an isolated fixture until cancellation. It has no stdin dependency,
// session lifetime or in-memory event history. systemd owns the service lifetime.
func Run(ctx context.Context, o Options) (result error) {
	if os.Geteuid() != 0 || o.UID == 0 || o.GID == 0 || !filepath.IsAbs(o.Executable) {
		return ErrRuntime
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	emit := func(event string, m Metadata, extra any) error {
		return json.NewEncoder(o.Log).Encode(struct {
			Event string    `json:"event"`
			At    time.Time `json:"at"`
			RunID string    `json:"run_id,omitempty"`
			Data  any       `json:"data,omitempty"`
		}{event, time.Now().UTC(), m.RunID, extra})
	}
	if secureDirectory(RuntimeDir, true) != nil || secureDirectory(RuntimeDir+"/netns", true) != nil {
		return ErrRuntime
	}
	lock, e := lockRuntime()
	if e != nil {
		return ErrRuntime
	}
	defer lock.Close()
	if e = recoverRuntime(); e != nil {
		return e
	}
	boot, e := kernelBootID()
	if e != nil {
		return e
	}
	host, e := namespaceInode("/proc/self/ns/net")
	if e != nil {
		return e
	}
	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f, e := nftfixture.NewOwned(childCtx, o.Executable, o.UID, o.GID)
	if e != nil {
		return e
	}
	var m Metadata
	published := false
	defer func() {
		cleanup := unpinGateway(m)
		cleanup = errors.Join(cleanup, f.CloseOwned())
		if published {
			current, e := readMetadataPath(MetadataPath)
			if e == nil && current == m {
				cleanup = errors.Join(cleanup, removeOwnedSocket(ControlPath))
				if cleanup == nil {
					cleanup = os.Remove(MetadataPath)
				}
			} else {
				cleanup = errors.Join(cleanup, ErrRuntime)
			}
		}
		result = errors.Join(result, cleanup)
		_ = emit("stopped", m, map[string]bool{"cleanup": cleanup == nil, "healthy": result == nil, "owned_resources_only": true})
	}()
	if e = f.StartReverseListener(childCtx); e != nil {
		return e
	}
	if e = f.SealAdminDeny(childCtx); e != nil {
		return e
	}
	ids := f.NamespaceIDs()
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		return e
	}
	m = Metadata{SchemaVersion: 1, RunID: hex.EncodeToString(random[:]), BootID: boot, HostNamespace: host, GatewayNamespace: ids["gateway"], SourceNamespace: ids["source"], SinkNamespace: ids["sink"]}
	if e = writeMetadata(m); e != nil {
		return e
	}
	published = true
	if e = f.PinPreviewGateway(); e != nil {
		return e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: ControlPath, Net: "unix"})
	if e != nil {
		return e
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if e = os.Chmod(ControlPath, 0600); e != nil {
		return e
	}
	if e = checkFixture(childCtx, f); e != nil {
		return e
	}
	if e = notifyReady(); e != nil {
		return e
	}
	if e = emit("ready", m, m); e != nil {
		return e
	}
	nextCheck := time.Now().Add(30 * time.Second)
	for {
		if ctx.Err() != nil {
			return nil
		}
		if e = listener.SetDeadline(time.Now().Add(time.Second)); e != nil {
			return e
		}
		conn, e := listener.AcceptUnix()
		if e != nil {
			var n net.Error
			if !errors.As(e, &n) || !n.Timeout() {
				return e
			}
		} else {
			reply, requestErr := handleControl(ctx, conn, f, m)
			if reply.Operation != "" {
				if e = emit("control", m, reply); e != nil {
					return e
				}
			}
			if requestErr != nil && reply.Error != "" {
				return requestErr
			}
		}
		if time.Now().After(nextCheck) {
			checkCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			e = checkFixture(checkCtx, f)
			if e == nil {
				e = f.CheckPreviewListeners(checkCtx)
			}
			stop()
			if e != nil {
				if ctx.Err() != nil {
					return nil
				}
				return e
			}
			nextCheck = time.Now().Add(30 * time.Second)
		}
	}
}
