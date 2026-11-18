//go:build linux

package previewruntime

import (
	"context"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpsockets"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/localobserve"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"golang.org/x/sys/unix"
)

// This restricted adapter never manages listeners. It supports only disabled
// local services. The only additional resource view is an authenticated DHCP
// acquisition service; all other TCP/UDP and packet sockets remain forbidden.
// Enabling a service requires the separate worker/collector assembly.
type routedEmptyListenersV3 struct {
	mu      sync.Mutex
	kernel  *routedKernelV3
	service *routedDHCPServiceObservationV1
}

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
		firewallipc.RecordRoutedDHCPFailureV1("listener_initial", ErrUnavailable, ctx)
		return nil, ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.service
	var fact RoutedDHCPOwnerFactV3
	phase := routedDHCPServicePhaseV1{}
	if s != nil {
		if s.validate(ctx, true) != nil {
			firewallipc.RecordRoutedDHCPFailureV1("listener_source_guard", ErrUnavailable, ctx)
			return nil, ErrUnavailable
		}
	}
	active := s
	if s != nil && !s.activated {
		active = nil
	}
	if active != nil {
		var err error
		fact, phase, err = active.fact(ctx)
		if err != nil {
			firewallipc.RecordRoutedDHCPFailureV1("listener_fact_before", ErrUnavailable, ctx)
			return nil, err
		}
	}
	var first routedDHCPSocketCaptureV1
	for pass := 0; pass < 2; pass++ {
		capture, err := l.capture(ctx, active, fact)
		if err != nil {
			firewallipc.RecordRoutedDHCPFailureV1("listener_capture", ErrUnavailable, ctx)
			return nil, err
		}
		if active == nil {
			if len(capture.tables) != 0 || len(capture.packet) != 0 {
				firewallipc.RecordRoutedDHCPFailureV1("listener_foreign", ErrUnavailable, ctx)
				return nil, ErrUnavailable
			}
		} else if matchRoutedDHCPSocketsV1(capture, active.identity, active.packet, fact, phase.withoutLease()) != nil {
			firewallipc.RecordRoutedDHCPFailureV1("listener_socket_match", ErrUnavailable, ctx)
			return nil, ErrUnavailable
		}
		if pass == 0 {
			first = capture
		} else if !sameRoutedDHCPSocketsV1(first, capture) {
			firewallipc.RecordRoutedDHCPFailureV1("listener_socket_changed", ErrUnavailable, ctx)
			return nil, ErrUnavailable
		}
	}
	if active != nil {
		after, afterPhase, err := active.fact(ctx)
		if err != nil || !sameRoutedDHCPListenerAssociationV4(fact, phase, after, afterPhase) {
			firewallipc.RecordRoutedDHCPFailureV1("listener_fact_after", ErrUnavailable, ctx)
			return nil, ErrUnavailable
		}
	}
	if s != nil && s.validate(ctx, true) != nil {
		firewallipc.RecordRoutedDHCPFailureV1("listener_final_guard", ErrUnavailable, ctx)
		return nil, ErrUnavailable
	}
	if ctx.Err() != nil || !l.kernel.bound() {
		firewallipc.RecordRoutedDHCPFailureV1("listener_final_context", ErrUnavailable, ctx)
		return nil, ErrUnavailable
	}
	return []localpolicy.Listener{}, nil
}

// Both samples have already passed fact(), including live-source validation.
// A lease version is not socket ownership: after two complete matching captures,
// genuine progress may retain the exact same physical service association. This
// comparison returns no lease or authority and cannot replace Current or the gate.
func sameRoutedDHCPListenerAssociationV4(before RoutedDHCPOwnerFactV3, phase routedDHCPServicePhaseV1, after RoutedDHCPOwnerFactV3, afterPhase routedDHCPServicePhaseV1) bool {
	if afterPhase != phase {
		return false
	}
	if after == before {
		return true
	}
	if phase != (routedDHCPServicePhaseV1{}) || before.Epoch == 0 || after.Epoch <= before.Epoch || before.Fact.Sequence == 0 || after.Fact.Sequence <= before.Fact.Sequence || before.Fact.Revoked || after.Fact.Revoked || before.Fact.DeadlineBootNS <= 0 || after.Fact.DeadlineBootNS <= 0 {
		return false
	}
	association := after.Fact
	association.Sequence = before.Fact.Sequence
	association.DeadlineBootNS = before.Fact.DeadlineBootNS
	return association == before.Fact
}

func (l *routedEmptyListenersV3) capture(ctx context.Context, s *routedDHCPServiceObservationV1, fact RoutedDHCPOwnerFactV3) (routedDHCPSocketCaptureV1, error) {
	var out routedDHCPSocketCaptureV1
	if !l.kernel.bound() || ctx.Err() != nil {
		return out, ErrUnavailable
	}
	if s != nil {
		var err error
		out.wanIndex, out.addressOnWAN, err = routedDHCPPhysicalWANV1(ctx, s.wan, fact.Fact.Address)
		if err != nil {
			return out, err
		}
	}
	var tables [4][]byte
	for i, path := range []string{"/proc/thread-self/net/tcp", "/proc/thread-self/net/tcp6", "/proc/thread-self/net/udp", "/proc/thread-self/net/udp6"} {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return out, ErrUnavailable
		}
		file := os.NewFile(uintptr(fd), "namespace-socket-table")
		var fs unix.Statfs_t
		if file == nil {
			_ = unix.Close(fd)
			return out, ErrUnavailable
		}
		if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
			_ = file.Close()
			return out, ErrUnavailable
		}
		tables[i], err = io.ReadAll(io.LimitReader(file, localobserve.MaxTableBytes+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || len(tables[i]) > localobserve.MaxTableBytes || ctx.Err() != nil || !l.kernel.bound() {
			return out, ErrUnavailable
		}
	}
	var err error
	out.tables, err = localobserve.ParseSocketTables(tables[0], tables[1], tables[2], tables[3])
	if err != nil {
		return out, ErrUnavailable
	}
	out.packet, err = dhcpsockets.CapturePacket(ctx)
	if err != nil {
		return out, ErrUnavailable
	}
	if s != nil {
		out.udp, err = dhcpsockets.CaptureIPv4UDP(ctx)
		if err != nil {
			return out, ErrUnavailable
		}
		index, present, e := routedDHCPPhysicalWANV1(ctx, s.wan, fact.Fact.Address)
		if e != nil || index != out.wanIndex || present != out.addressOnWAN {
			return out, ErrUnavailable
		}
	}
	if ctx.Err() != nil || !l.kernel.bound() {
		return out, ErrUnavailable
	}
	return out, nil
}

func (l *routedEmptyListenersV3) installService(ctx context.Context, s *routedDHCPServiceObservationV1) error {
	if l == nil || l.kernel == nil || s == nil {
		return ErrIdentity
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.service != nil || s.binding.Owner.Namespace != l.kernel.namespace || s.validate(ctx, true) != nil {
		return ErrIdentity
	}
	l.service = s
	return nil
}

func (l *routedEmptyListenersV3) revokeService() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.service != nil {
		l.service.retiring = true
	}
}

// Standby is installed before acquisition. Holding this listener lock across
// the fixed root RPC prevents observers from consuming an unconfirmed Current
// frame. The root broker does not call back into helper authority or runtime.
func (l *routedEmptyListenersV3) activateService(ctx context.Context, client *routedDHCPJobClientV4, work configpoc.RoutedWorkReferenceV1) error {
	if l == nil || l.kernel == nil || ctx == nil || client == nil {
		return ErrIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.service
	if s == nil || s.activated || s.validate(ctx, true) != nil {
		return ErrUnavailable
	}
	for range 2 {
		c, err := l.capture(ctx, nil, RoutedDHCPOwnerFactV3{})
		if err != nil || len(c.tables) != 0 || len(c.packet) != 0 || s.validate(ctx, true) != nil {
			return ErrUnavailable
		}
	}
	if _, _, err := client.call(ctx, "activate", work); err != nil || ctx.Err() != nil || s.validate(ctx, true) != nil {
		s.retiring = true
		return ErrUnavailable
	}
	s.activated = true
	return nil
}

// The stop acknowledgement attests process drainage, never socket absence.
// Keep the old pin and deny observations until both complete captures are empty.
func (l *routedEmptyListenersV3) releaseService(ctx context.Context) error {
	if l == nil || l.kernel == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.service
	if s == nil {
		return nil
	}
	if !s.retiring || s.validate(ctx, false) != nil || !s.producerExited() {
		return ErrUnavailable
	}
	err := releaseRoutedDHCPSocketPinsV1(ctx, func() error { return s.validate(ctx, false) }, s.producerExited, func() (routedDHCPSocketCaptureV1, error) { return l.capture(ctx, nil, RoutedDHCPOwnerFactV3{}) }, s.closePins)
	if err != nil {
		return err
	}
	l.service = nil
	return nil
}

var _ localengine.Listeners = (*routedEmptyListenersV3)(nil)
