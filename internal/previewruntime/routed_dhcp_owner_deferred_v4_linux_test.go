//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type routedDeferredTestV4 struct {
	reader                    *RoutedDHCPDeferredReaderV4
	control, events           *os.File
	scanEvent                 *bufio.Scanner
	binding                   RoutedDHCPDeferredBindingV4
	source                    *routedOwnerTestSourceV3
	childAlive, producerAlive atomic.Bool
	starts, stops, drains     atomic.Int32
	now                       atomic.Int64
	done                      chan error
	cancel                    context.CancelFunc
}

func newRoutedDeferredTestV4(t *testing.T) *routedDeferredTestV4 {
	t.Helper()
	b, l := routedDeferredFixtureV4(t)
	x := &routedDeferredTestV4{binding: b, source: &routedOwnerTestSourceV3{lease: l}, done: make(chan error, 1)}
	x.childAlive.Store(true)
	x.producerAlive.Store(true)
	x.now.Store(int64(11 * time.Second))
	qR, qW := routedOwnerPipeV3(t)
	rR, rW := routedOwnerPipeV3(t)
	cR, cW := routedOwnerPipeV3(t)
	eR, eW := routedOwnerPipeV3(t)
	x.control, x.events = cW, eR
	x.scanEvent = routedDHCPOwnerScannerV3(eR)
	var err error
	x.reader, err = newRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4{Request: qW, Reply: rR}, b, x.producerAlive.Load, func() (int64, error) { return x.now.Load(), nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	x.cancel = cancel
	go func() {
		x.done <- serveRoutedDHCPDeferredRoleV4(ctx, cR, eW, qR, rW, routedDHCPDeferredEventV4{Version: 4, Incarnation: b.Owner.Incarnation, ProducerPID: int32(b.Owner.PID), ProducerStartTicks: b.Owner.StartTicks, Phase: "prepared"}, func(context.Context) (*routedDHCPDeferredAcquisitionV4, error) {
			x.starts.Add(1)
			return &routedDHCPDeferredAcquisitionV4{identity: RoutedDHCPAcquisitionIdentityV4{50, 124}, source: x.source, alive: x.childAlive.Load, stop: func() { x.stops.Add(1) }, close: func() {}}, nil
		}, func() error { x.drains.Add(1); return nil })
		x.producerAlive.Store(false)
	}()
	t.Cleanup(func() { cancel(); _ = x.reader.Close() })
	x.event(t, "prepared")
	return x
}
func (x *routedDeferredTestV4) event(t *testing.T, phase string) routedDHCPDeferredEventV4 {
	t.Helper()
	_ = x.events.SetReadDeadline(time.Now().Add(time.Second))
	if !x.scanEvent.Scan() {
		t.Fatal("missing lifecycle event", phase)
	}
	var e routedDHCPDeferredEventV4
	if routedDHCPOwnerDecodeV3(x.scanEvent.Bytes(), &e) != nil || e.Phase != phase {
		t.Fatal("invalid lifecycle phase", phase)
	}
	return e
}
func (x *routedDeferredTestV4) send(t *testing.T, sequence uint64, op string, id *RoutedDHCPAcquisitionIdentityV4) {
	t.Helper()
	if routedDHCPOwnerWriteV3(x.control, routedDHCPDeferredControlV4{4, x.binding.Owner.Incarnation, sequence, op, id}) != nil {
		t.Fatal("control write failed")
	}
}
func (x *routedDeferredTestV4) finish(t *testing.T, success bool) {
	t.Helper()
	select {
	case err := <-x.done:
		if (err == nil) != success {
			t.Fatalf("role success=%v: %v", success, err)
		}
	case <-time.After(time.Second):
		t.Fatal("role did not terminate")
	}
}

func TestRoutedDHCPDeferredV4NoAcquisitionOrGrantBeforeRootConfirmation(t *testing.T) {
	x := newRoutedDeferredTestV4(t)
	ctx := context.Background()
	for range 3 {
		if _, err := x.reader.Current(ctx); err == nil {
			t.Fatal("standby granted a lease")
		}
	}
	if x.starts.Load() != 0 {
		t.Fatal("standby started acquisition")
	}
	x.send(t, 1, "activate", nil)
	e := x.event(t, "acquiring")
	if e.Acquisition == nil || e.Acquisition.PID != 50 || x.starts.Load() != 1 {
		t.Fatal("real acquisition identity missing")
	}
	if _, err := x.reader.Current(ctx); err == nil {
		t.Fatal("unconfirmed acquisition granted lease")
	}
	x.source.mu.Lock()
	calls := x.source.calls
	x.source.mu.Unlock()
	if calls != 0 {
		t.Fatal("unconfirmed grant source read")
	}
	x.send(t, 2, "confirm", e.Acquisition)
	x.event(t, "active")
	first, err := x.reader.Current(ctx)
	if err != nil || first.Fact.Owner != x.binding.Owner || first.Fact.Owner.PID == uint32(e.Acquisition.PID) {
		t.Fatal("producer identity mismatch", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for range 12 {
		wg.Go(func() {
			f, e := x.reader.Current(ctx)
			if e != nil {
				errs <- e
			} else if f != first {
				errs <- ErrIdentity
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	x.send(t, 3, "stop", nil)
	x.event(t, "stopped")
	if x.stops.Load() != 1 || x.drains.Load() != 1 {
		t.Fatal("stop acknowledgment preceded drainage")
	}
	x.finish(t, true)
	if _, err = x.reader.Current(ctx); err == nil {
		t.Fatal("stopped owner returned cached authority")
	}
}
func TestRoutedDHCPDeferredV4StandbyStopStartsNoClient(t *testing.T) {
	x := newRoutedDeferredTestV4(t)
	x.send(t, 1, "stop", nil)
	x.event(t, "stopped")
	x.finish(t, true)
	if x.starts.Load() != 0 || x.stops.Load() != 0 || x.drains.Load() != 1 {
		t.Fatal("disabled acquisition has side effects")
	}
}
func TestRoutedDHCPDeferredV4RejectsControlReplayAndCrossProfile(t *testing.T) {
	for _, kind := range []string{"confirm-before-start", "wrong-child", "wrong-start", "duplicate-activate", "v3", "unknown", "duplicate-json", "oversized", "eof", "sequence"} {
		t.Run(kind, func(t *testing.T) {
			x := newRoutedDeferredTestV4(t)
			switch kind {
			case "wrong-child", "wrong-start", "duplicate-activate":
				x.send(t, 1, "activate", nil)
				e := x.event(t, "acquiring")
				if kind == "duplicate-activate" {
					x.send(t, 2, "activate", nil)
				} else {
					if kind == "wrong-child" {
						e.Acquisition.PID++
					} else {
						e.Acquisition.StartTicks++
					}
					x.send(t, 2, "confirm", e.Acquisition)
				}
			case "confirm-before-start":
				x.send(t, 1, "confirm", &RoutedDHCPAcquisitionIdentityV4{50, 124})
			case "v3":
				_ = routedDHCPOwnerWriteV3(x.control, routedDHCPOwnerRequestV3{3, x.binding.Owner.Incarnation, 1, "activate"})
			case "unknown":
				x.send(t, 1, "renew", nil)
			case "sequence":
				x.send(t, 2, "activate", nil)
			case "duplicate-json":
				_, _ = x.control.Write([]byte("{\"version\":4,\"version\":4}\n"))
			case "oversized":
				_, _ = x.control.Write([]byte(strings.Repeat("x", routedDHCPOwnerFrameV3+1) + "\n"))
			case "eof":
				_ = x.control.Close()
			}
			x.finish(t, false)
			if _, err := x.reader.Current(context.Background()); err == nil {
				t.Fatal("invalid control left lease authority")
			}
		})
	}
}
func TestRoutedDHCPDeferredV4DeathCancelsIncarnationWithoutReattach(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-confirm", true: "after-confirm"}[confirmed], func(t *testing.T) {
			x := newRoutedDeferredTestV4(t)
			x.send(t, 1, "activate", nil)
			e := x.event(t, "acquiring")
			if confirmed {
				x.send(t, 2, "confirm", e.Acquisition)
				x.event(t, "active")
				if _, err := x.reader.Current(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			x.childAlive.Store(false)
			x.finish(t, false)
			x.childAlive.Store(true)
			if _, err := x.reader.Current(context.Background()); err == nil {
				t.Fatal("dead acquisition revived")
			}
			if x.starts.Load() != 1 || x.stops.Load() != 1 {
				t.Fatal("acquisition reattached or not stopped")
			}
		})
	}
}
func TestRoutedDHCPDeferredV4OwnerCancellationAndExpiredGrant(t *testing.T) {
	x := newRoutedDeferredTestV4(t)
	x.send(t, 1, "activate", nil)
	e := x.event(t, "acquiring")
	x.send(t, 2, "confirm", e.Acquisition)
	x.event(t, "active")
	first, err := x.reader.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	x.now.Store(first.Fact.DeadlineBootNS)
	if _, err = x.reader.Current(context.Background()); err == nil {
		t.Fatal("expired grant accepted")
	}
	x.cancel()
	x.finish(t, false)
	if x.stops.Load() != 1 || x.drains.Load() != 1 {
		t.Fatal("cancel did not drain")
	}
}
func TestRoutedDHCPDeferredV4RejectsUnsafePrepareWithoutEffects(t *testing.T) {
	if owner, err := PrepareRoutedDHCPDeferredOwnerV4(context.Background(), RoutedDHCPOwnerOptionsV3{}); err == nil {
		_ = owner.Close()
		t.Fatal("empty profile prepared")
	}
	if os.Geteuid() != 0 {
		if RunRoutedDHCPDeferredOwnerRoleV4(context.Background()) == nil {
			t.Fatal("unprivileged role accepted")
		}
		if (&RoutedDHCPDeferredOwnerV4{owner: &RoutedDHCPOwnerV3{}}).Activate(context.Background()) == nil {
			t.Fatal("unprivileged activate accepted")
		}
	}
}

type routedDeferredSourceFuncV4 func() (routedDHCPOwnerLeaseV3, error)

func (f routedDeferredSourceFuncV4) Current() (routedDHCPOwnerLeaseV3, error) { return f() }

func TestRoutedDHCPDeferredV4ChecksActualPIDAndDeathAcrossSourceRead(t *testing.T) {
	for _, kind := range []string{"producer-pid-in-hook", "death-during-read"} {
		t.Run(kind, func(t *testing.T) {
			_, lease := routedDeferredFixtureV4(t)
			live := true
			s := &routedDHCPDeferredStateV4{confirmed: true, acquisition: &routedDHCPDeferredAcquisitionV4{identity: RoutedDHCPAcquisitionIdentityV4{50, 124}, alive: func() bool { return live }, source: routedDeferredSourceFuncV4(func() (routedDHCPOwnerLeaseV3, error) {
				if kind == "producer-pid-in-hook" {
					lease.Event.PID = 40
				} else {
					live = false
				}
				return lease, nil
			})}}
			if _, _, fatal, err := s.current(); err == nil || !fatal {
				t.Fatal("unverified actual acquisition accepted")
			}
			live = true
			lease.Event.PID = 50
			if _, _, fatal, err := s.current(); err == nil || !fatal {
				t.Fatal("terminal incarnation revived")
			}
		})
	}
}

func TestRoutedDHCPDeferredV4ReaderRejectsAcquisitionReplacementAndV3Reply(t *testing.T) {
	for _, kind := range []string{"pid-replacement", "start-replacement", "v3"} {
		t.Run(kind, func(t *testing.T) {
			b, lease := routedDeferredFixtureV4(t)
			qR, qW := routedOwnerPipeV3(t)
			rR, rW := routedOwnerPipeV3(t)
			r, err := newRoutedDHCPDeferredReaderV4(RoutedDHCPDeferredFilesV4{Request: qW, Reply: rR}, b, func() bool { return true }, func() (int64, error) { return int64(11 * time.Second), nil })
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer rW.Close()
				scan := routedDHCPOwnerScannerV3(qR)
				for sequence := uint64(1); sequence <= 2; sequence++ {
					if !scan.Scan() {
						return
					}
					if kind == "v3" {
						_ = routedDHCPOwnerWriteV3(rW, routedDHCPOwnerReplyV3{Version: 3, Incarnation: b.Owner.Incarnation, Sequence: sequence, Lease: &lease})
						return
					}
					id := RoutedDHCPAcquisitionIdentityV4{50, 124}
					if sequence == 2 {
						lease.Epoch++
						lease.Event.BootNS++
						if kind == "pid-replacement" {
							id.PID++
							lease.Event.PID++
						} else {
							id.StartTicks++
						}
					}
					_ = routedDHCPOwnerWriteV3(rW, routedDHCPDeferredReplyV4{Version: 4, Incarnation: b.Owner.Incarnation, Sequence: sequence, Acquisition: &id, Lease: &lease})
				}
			}()
			if kind != "v3" {
				if _, err = r.Current(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = r.Current(context.Background()); err == nil {
				t.Fatal("replacement acquisition or v3 profile accepted")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("reply producer blocked")
			}
		})
	}
}

func TestRoutedDHCPDeferredV4CurrentCannotControlAcquisition(t *testing.T) {
	for _, op := range []string{"v3-current", "activate", "confirm", "stop"} {
		t.Run(op, func(t *testing.T) {
			x := newRoutedDeferredTestV4(t)
			version := 4
			operation := op
			if op == "v3-current" {
				version = 3
				operation = "current"
			}
			if routedDHCPOwnerWriteV3(x.reader.reader.files.Request, routedDHCPOwnerRequestV3{version, x.binding.Owner.Incarnation, 1, operation}) != nil {
				t.Fatal("request write failed")
			}
			x.finish(t, false)
			if x.starts.Load() != 0 {
				t.Fatal("Current channel started acquisition")
			}
		})
	}
}
