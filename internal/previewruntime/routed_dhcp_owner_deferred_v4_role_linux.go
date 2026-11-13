//go:build linux

package previewruntime

import (
	"context"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpclient"
)

type routedDHCPDeferredAcquisitionV4 struct {
	identity RoutedDHCPAcquisitionIdentityV4
	source   routedDHCPOwnerSourceV3
	alive    func() bool
	stop     func()
	close    func()
}
type routedDHCPDeferredStateV4 struct {
	mu                  sync.Mutex
	acquisition         *routedDHCPDeferredAcquisitionV4
	confirmed, terminal bool
}

func (s *routedDHCPDeferredStateV4) current() (routedDHCPOwnerLeaseV3, RoutedDHCPAcquisitionIdentityV4, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var l routedDHCPOwnerLeaseV3
	var id RoutedDHCPAcquisitionIdentityV4
	if s.terminal {
		return l, id, true, ErrUnavailable
	}
	a := s.acquisition
	if a == nil {
		return l, id, false, ErrUnavailable
	}
	if !a.alive() {
		s.terminal = true
		return l, id, true, ErrUnavailable
	}
	if !s.confirmed {
		return l, id, false, ErrUnavailable
	}
	l, err := a.source.Current()
	if !a.alive() || err == nil && l.Event.PID != int(a.identity.PID) {
		s.terminal = true
		return routedDHCPOwnerLeaseV3{}, id, true, ErrIdentity
	}
	if err != nil {
		return routedDHCPOwnerLeaseV3{}, id, false, ErrUnavailable
	}
	return l, a.identity, false, nil
}
func (s *routedDHCPDeferredStateV4) live() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal {
		return false
	}
	if s.acquisition != nil && !s.acquisition.alive() {
		s.terminal = true
		return false
	}
	return true
}
func (s *routedDHCPDeferredStateV4) confirm(id RoutedDHCPAcquisitionIdentityV4) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal || s.confirmed || s.acquisition == nil || s.acquisition.identity != id || !s.acquisition.alive() {
		return ErrIdentity
	}
	s.confirmed = true
	return nil
}

func runRoutedDHCPDeferredRoleV4(parent context.Context, b routedDHCPOwnerBootstrapV3, files [8]*os.File, scope dhcpclient.Scope) error {
	producerPID := os.Getpid()
	start, ppid, err := routedDHCPOwnerProcessV3(producerPID)
	if err != nil || ppid != b.ParentPID || producerPID <= 1 || producerPID > math.MaxInt32 {
		return ErrIdentity
	}
	event := routedDHCPDeferredEventV4{Version: 4, Incarnation: b.Incarnation, ProducerPID: int32(producerPID), ProducerStartTicks: start, Phase: "prepared"}
	acquire := func(ctx context.Context) (*routedDHCPDeferredAcquisitionV4, error) {
		client, e := dhcpclient.StartIsolated(ctx, scope)
		if e != nil {
			return nil, ErrUnavailable
		}
		parsedPID, e := strconv.ParseInt(client.PID(), 10, 32)
		if e != nil || parsedPID <= 1 {
			client.Stop()
			return nil, ErrIdentity
		}
		pid := int(parsedPID)
		fd, ticks, e := routedDHCPOwnerPinV3(pid, os.Getpid(), b.Metadata.GatewayNamespace, b.MountNamespace)
		if e != nil {
			client.Stop()
			return nil, e
		}
		return &routedDHCPDeferredAcquisitionV4{identity: RoutedDHCPAcquisitionIdentityV4{int32(parsedPID), ticks}, source: routedDHCPOwnerClientV3{client}, alive: func() bool { return routedDHCPOwnerPIDFDAliveV3(fd, pid) }, stop: client.Stop, close: func() { _ = fd.Close() }}, nil
	}
	return serveRoutedDHCPDeferredRoleV4(parent, files[7], files[4], files[5], files[6], event, acquire, routedDHCPOwnerDrainV3)
}

// acquire/drain are local lifecycle operations selected by the fixed role.
// They are never serialized, exported or supplied by a Current caller.
func serveRoutedDHCPDeferredRoleV4(parent context.Context, control, events, request, reply *os.File, event routedDHCPDeferredEventV4, acquire func(context.Context) (*routedDHCPDeferredAcquisitionV4, error), drain func() error) (result error) {
	if parent == nil || control == nil || events == nil || request == nil || reply == nil || event.Version != 4 || event.Phase != "prepared" || event.ProducerPID <= 1 || event.ProducerStartTicks == 0 || event.Acquisition != nil || !ValidRun(event.Incarnation) || acquire == nil || drain == nil {
		return ErrIdentity
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	s := &routedDHCPDeferredStateV4{}
	stopPipes := context.AfterFunc(ctx, func() { _ = control.Close(); _ = request.Close(); _ = reply.Close() })
	defer stopPipes()
	var cleanupOnce sync.Once
	var cleanupErr error
	cleanup := func() {
		cleanupOnce.Do(func() {
			s.mu.Lock()
			s.terminal = true
			a := s.acquisition
			s.mu.Unlock()
			if a != nil {
				a.stop()
				defer a.close()
			}
			cleanupErr = drain()
		})
	}
	defer func() {
		cleanup()
		if cleanupErr != nil {
			result = cleanupErr
		}
	}()
	if events.SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPOwnerWriteV3(events, event) != nil {
		return ErrUnavailable
	}
	controlDone := make(chan bool, 1)
	go func() {
		controlDone <- routedDHCPDeferredControlLoopV4(ctx, control, events, event, s, acquire)
		cancel()
	}()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if !s.live() {
					cancel()
					return
				}
			}
		}
	}()
	result = serveRoutedDHCPDeferredCurrentV4(ctx, request, reply, event.Incarnation, s)
	cancel()
	_ = control.Close()
	validStop := <-controlDone
	<-watchDone
	cleanup()
	if cleanupErr != nil {
		return cleanupErr
	}
	if !validStop {
		return ErrUnavailable
	}
	event.Phase = "stopped"
	event.Acquisition = nil
	if events.SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPOwnerWriteV3(events, event) != nil {
		return ErrUnavailable
	}
	return nil
}

func routedDHCPDeferredControlLoopV4(ctx context.Context, control, events *os.File, event routedDHCPDeferredEventV4, s *routedDHCPDeferredStateV4, acquire func(context.Context) (*routedDHCPDeferredAcquisitionV4, error)) bool {
	scan := routedDHCPOwnerScannerV3(control)
	phase := "prepared"
	sequence := uint64(0)
	for scan.Scan() {
		var q routedDHCPDeferredControlV4
		if routedDHCPOwnerDecodeV3(scan.Bytes(), &q) != nil || q.Version != 4 || q.Incarnation != event.Incarnation || q.Sequence != sequence+1 || ctx.Err() != nil {
			return false
		}
		sequence = q.Sequence
		switch {
		case q.Operation == "stop" && q.Acquisition == nil && (phase == "prepared" || phase == "active"):
			return true
		case q.Operation == "activate" && q.Acquisition == nil && phase == "prepared":
			a, err := acquire(ctx)
			if err != nil {
				return false
			}
			if a == nil || a.source == nil || a.alive == nil || a.stop == nil || a.close == nil || !a.identity.valid(int64(event.ProducerPID)) {
				if a != nil && a.stop != nil {
					a.stop()
				}
				if a != nil && a.close != nil {
					a.close()
				}
				return false
			}
			s.mu.Lock()
			s.acquisition = a
			s.mu.Unlock()
			if !s.live() {
				return false
			}
			phase = "acquiring"
			event.Phase = phase
			event.Acquisition = &a.identity
			if control.SetReadDeadline(time.Now().Add(10*time.Second)) != nil || events.SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPOwnerWriteV3(events, event) != nil {
				return false
			}
		case q.Operation == "confirm" && q.Acquisition != nil && phase == "acquiring":
			if s.confirm(*q.Acquisition) != nil {
				return false
			}
			phase = "active"
			event.Phase = phase
			if control.SetReadDeadline(time.Time{}) != nil || events.SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPOwnerWriteV3(events, event) != nil {
				return false
			}
		default:
			return false
		}
	}
	return false
}
func serveRoutedDHCPDeferredCurrentV4(ctx context.Context, request, reply *os.File, incarnation string, s *routedDHCPDeferredStateV4) error {
	scan := routedDHCPOwnerScannerV3(request)
	sequence := uint64(0)
	for scan.Scan() {
		var q routedDHCPOwnerRequestV3
		if sequence == math.MaxUint64 || routedDHCPOwnerDecodeV3(scan.Bytes(), &q) != nil || q.Version != 4 || q.Incarnation != incarnation || q.Sequence != sequence+1 || q.Operation != "current" || ctx.Err() != nil {
			return ErrIdentity
		}
		sequence = q.Sequence
		l, id, fatal, err := s.current()
		if fatal {
			return ErrUnavailable
		}
		r := routedDHCPDeferredReplyV4{Version: 4, Incarnation: incarnation, Sequence: sequence, Unavailable: err != nil}
		if err == nil {
			r.Lease = &l
			r.Acquisition = &id
		}
		if reply.SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPOwnerWriteV3(reply, r) != nil {
			return ErrUnavailable
		}
	}
	return ErrUnavailable
}
