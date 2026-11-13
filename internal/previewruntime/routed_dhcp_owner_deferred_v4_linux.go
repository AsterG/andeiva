//go:build linux

package previewruntime

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type RoutedDHCPDeferredOwnerV4 struct{ owner *RoutedDHCPOwnerV3 }

// Prepare creates only the trusted producer, private mounts and channels for a
// root-selected DHCP plan. It neither starts dhcpcd nor authorizes R2. Static or
// NoNetwork profiles must never invoke this constructor and are rejected.
func PrepareRoutedDHCPDeferredOwnerV4(ctx context.Context, o RoutedDHCPOwnerOptionsV3) (*RoutedDHCPDeferredOwnerV4, error) {
	s, err := startRoutedDHCPOwnerProfileV3(ctx, o, 4)
	if err != nil {
		return nil, err
	}
	registerNativeDHCPDiagnosticV4(s)
	return &RoutedDHCPDeferredOwnerV4{s}, nil
}
func RunRoutedDHCPDeferredOwnerRoleV4(ctx context.Context) error {
	return runRoutedDHCPOwnerProfileV3(ctx, 4)
}
func NewRoutedDHCPDeferredReaderV4(f RoutedDHCPDeferredFilesV4, b RoutedDHCPDeferredBindingV4) (*RoutedDHCPDeferredReaderV4, error) {
	if !routedDHCPDeferredBindingValidV4(b) || !routedDHCPOwnerPipeV3(f.Request, unix.O_WRONLY) || !routedDHCPOwnerPipeV3(f.Reply, unix.O_RDONLY) || !routedDHCPOwnerPIDFDAliveV3(f.ProducerPIDFD, int(b.Owner.PID)) {
		return nil, ErrIdentity
	}
	return newRoutedDHCPDeferredReaderV4(f, b, func() bool { return routedDHCPOwnerPIDFDAliveV3(f.ProducerPIDFD, int(b.Owner.PID)) }, routedDHCPOwnerBootNowV3)
}
func (s *RoutedDHCPDeferredOwnerV4) TakeReaderFiles() (RoutedDHCPDeferredFilesV4, RoutedDHCPDeferredBindingV4, error) {
	if s == nil || s.owner == nil {
		return RoutedDHCPDeferredFilesV4{}, RoutedDHCPDeferredBindingV4{}, ErrIdentity
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.profile != 4 || o.closed || o.transferred || !routedDHCPOwnerPIDFDAliveV3(o.files.RolePIDFD, int(o.deferred.Owner.PID)) {
		return RoutedDHCPDeferredFilesV4{}, RoutedDHCPDeferredBindingV4{}, ErrUnavailable
	}
	b, err := cloneRoutedDHCPDeferredBindingV4(o.deferred)
	if err != nil {
		return RoutedDHCPDeferredFilesV4{}, RoutedDHCPDeferredBindingV4{}, err
	}
	f := RoutedDHCPDeferredFilesV4{o.files.Request, o.files.Reply, o.files.RolePIDFD}
	o.files = RoutedDHCPOwnerFilesV3{}
	o.transferred = true
	return f, b, nil
}
func (s *RoutedDHCPDeferredOwnerV4) Done() <-chan struct{} {
	if s == nil {
		return (*RoutedDHCPOwnerV3)(nil).Done()
	}
	return s.owner.Done()
}
func (s *RoutedDHCPDeferredOwnerV4) Close() error {
	if s == nil {
		return nil
	}
	return s.owner.Close()
}

// Activate is root-only and one-shot. The supervisor MUST first prove selected
// revision, helper integrity readiness, LAN/readback and EmptyListeners. No API
// boolean or helper request can supply this authority. Successful activation is
// not a lease grant; it only permits later confirmed DHCP evidence to be read.
func (s *RoutedDHCPDeferredOwnerV4) Activate(parent context.Context) error {
	if s == nil || s.owner == nil || parent == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	o := s.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.profile != 4 || o.closed || o.activated || parent.Err() != nil || !routedDHCPOwnerPIDFDAliveV3(o.producerFD, int(o.deferred.Owner.PID)) {
		return ErrUnavailable
	}
	o.activated = true // Failure cannot retry acquisition in this incarnation.
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if o.control.SetWriteDeadline(deadline) != nil || o.events.SetReadDeadline(deadline) != nil {
		return o.failDeferredLockedV4()
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(callbackDone)
		_ = o.control.SetWriteDeadline(time.Now())
		_ = o.events.SetReadDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-callbackDone
		}
	}()
	q := routedDHCPDeferredControlV4{Version: 4, Incarnation: o.deferred.Owner.Incarnation, Sequence: 1, Operation: "activate"}
	if routedDHCPOwnerWriteV3(o.control, q) != nil {
		return o.failDeferredLockedV4()
	}
	event, err := o.deferredEventV4("acquiring")
	if err != nil || event.Acquisition == nil || !event.Acquisition.valid(int64(o.deferred.Owner.PID)) {
		return o.failDeferredLockedV4()
	}
	fd, start, err := routedDHCPOwnerPinV3(int(event.Acquisition.PID), int(o.deferred.Owner.PID), o.deferred.Owner.Namespace, o.deferred.MountNamespace)
	if err != nil {
		return o.failDeferredLockedV4()
	}
	o.acquisitionFD = fd
	if start != event.Acquisition.StartTicks || ctx.Err() != nil || !routedDHCPOwnerPIDFDAliveV3(o.producerFD, int(o.deferred.Owner.PID)) {
		return o.failDeferredLockedV4()
	}
	o.acquisition = *event.Acquisition
	q.Sequence, q.Operation, q.Acquisition = 2, "confirm", &o.acquisition
	if routedDHCPOwnerWriteV3(o.control, q) != nil {
		return o.failDeferredLockedV4()
	}
	event, err = o.deferredEventV4("active")
	if err != nil || event.Acquisition == nil || *event.Acquisition != o.acquisition || ctx.Err() != nil || !routedDHCPOwnerPIDFDAliveV3(o.producerFD, int(o.deferred.Owner.PID)) || !routedDHCPOwnerPIDFDAliveV3(o.acquisitionFD, int(o.acquisition.PID)) {
		return o.failDeferredLockedV4()
	}
	return nil
}
func (o *RoutedDHCPOwnerV3) deferredEventV4(phase string) (routedDHCPDeferredEventV4, error) {
	var event routedDHCPDeferredEventV4
	if !o.scanner.Scan() || routedDHCPOwnerDecodeV3(o.scanner.Bytes(), &event) != nil || event.Version != 4 || event.Incarnation != o.deferred.Owner.Incarnation || int64(event.ProducerPID) != int64(o.deferred.Owner.PID) || event.ProducerStartTicks != o.deferred.Owner.StartTicks || event.Phase != phase {
		return event, ErrIdentity
	}
	return event, nil
}
func (o *RoutedDHCPOwnerV3) failDeferredLockedV4() error {
	o.closeErr = ErrUnavailable
	_ = o.cmd.Process.Kill()
	return o.closeErr
}
func (o *RoutedDHCPOwnerV3) closeDeferredLockedV4() error {
	if o.closed {
		return o.closeErr
	}
	o.closed = true
	defer func() {
		_ = o.control.Close()
		_ = o.events.Close()
		_ = o.mount.Close()
		_ = o.files.Close()
		if o.producerFD != nil {
			_ = o.producerFD.Close()
		}
		if o.acquisitionFD != nil {
			_ = o.acquisitionFD.Close()
		}
	}()
	sequence := uint64(1)
	if o.activated {
		sequence = 3
	}
	deadline := time.Now().Add(5 * time.Second)
	if o.closeErr != nil || o.control.SetWriteDeadline(deadline) != nil || o.events.SetReadDeadline(deadline) != nil || routedDHCPOwnerWriteV3(o.control, routedDHCPDeferredControlV4{Version: 4, Incarnation: o.deferred.Owner.Incarnation, Sequence: sequence, Operation: "stop"}) != nil {
		_ = o.failDeferredLockedV4()
	} else {
		event, err := o.deferredEventV4("stopped")
		if err != nil || event.Acquisition != nil {
			_ = o.failDeferredLockedV4()
		}
	}
	select {
	case <-o.done:
	case <-time.After(5 * time.Second):
		_ = o.failDeferredLockedV4()
	}
	return o.closeErr
}
