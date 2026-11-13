//go:build linux

package previewruntime

import (
	"context"
	"io"
	"os"
	"runtime"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/localobserve"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"golang.org/x/sys/unix"
)

// This restricted adapter never manages listeners. It supports only disabled
// local services and verifies absence of TCP listeners and bound UDP sockets
// in the owned namespace. Established TCP connections are not listeners.
// Enabling a service requires the separate worker/collector assembly.
type routedEmptyListenersV3 struct{ kernel *routedKernelV3 }

func newRoutedEmptyListenersV3(m Metadata) (*routedEmptyListenersV3, error) {
	kernel, err := newRoutedKernelV3(m)
	if err != nil {
		return nil, err
	}
	return &routedEmptyListenersV3{kernel: kernel}, nil
}

func (l *routedEmptyListenersV3) Apply(ctx context.Context, revision configpoc.Revision) error {
	r, err := configpoc.Canonical(revision.Config)
	if err != nil || r.Hash != revision.Hash || r.Config.SchemaVersion != 3 || r.Config.LocalServices == nil {
		return ErrConfiguration
	}
	for _, service := range r.Config.LocalServices.Services {
		if service.Enabled {
			return ErrUnavailable
		}
	}
	_, err = l.Observe(ctx)
	return err
}

func (l *routedEmptyListenersV3) Observe(ctx context.Context) ([]localpolicy.Listener, error) {
	if l == nil || l.kernel == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for pass := 0; pass < 2; pass++ {
		if !l.kernel.bound() || ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		var tables [4][]byte
		for i, path := range []string{"/proc/thread-self/net/tcp", "/proc/thread-self/net/tcp6", "/proc/thread-self/net/udp", "/proc/thread-self/net/udp6"} {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
			if err != nil {
				return nil, ErrUnavailable
			}
			file := os.NewFile(uintptr(fd), "namespace-socket-table")
			var fs unix.Statfs_t
			if file == nil {
				_ = unix.Close(fd)
				return nil, ErrUnavailable
			}
			if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
				_ = file.Close()
				return nil, ErrUnavailable
			}
			tables[i], err = io.ReadAll(io.LimitReader(file, localobserve.MaxTableBytes+1))
			closeErr := file.Close()
			if err != nil || closeErr != nil || len(tables[i]) > localobserve.MaxTableBytes || ctx.Err() != nil || !l.kernel.bound() {
				return nil, ErrUnavailable
			}
		}
		if err := localobserve.VerifyNoTCPUDPListeners(tables[0], tables[1], tables[2], tables[3]); err != nil {
			return nil, ErrUnavailable
		}
	}
	return []localpolicy.Listener{}, nil
}

var _ localengine.Listeners = (*routedEmptyListenersV3)(nil)
