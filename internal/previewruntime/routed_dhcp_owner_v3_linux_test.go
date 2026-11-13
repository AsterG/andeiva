//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type routedOwnerTestSourceV3 struct {
	mu    sync.Mutex
	lease routedDHCPOwnerLeaseV3
	err   error
	calls int
}

func (s *routedOwnerTestSourceV3) Current() (routedDHCPOwnerLeaseV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.lease, s.err
}
func (s *routedOwnerTestSourceV3) set(l routedDHCPOwnerLeaseV3, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lease, s.err = l, err
}
func routedOwnerPipeV3(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

// Only this transport fixture replaces liveness/clock. Production construction
// checks the two root-created pidfds and never exposes these callbacks.
func routedOwnerReaderFixtureV3(t *testing.T) (*RoutedDHCPOwnerReaderV3, *os.File, *os.File, *atomic.Bool, *atomic.Int64) {
	t.Helper()
	b, _ := routedOwnerFixtureV3(t)
	qR, qW := routedOwnerPipeV3(t)
	rR, rW := routedOwnerPipeV3(t)
	alive := &atomic.Bool{}
	alive.Store(true)
	now := &atomic.Int64{}
	now.Store(int64(11 * time.Second))
	r := &RoutedDHCPOwnerReaderV3{gate: make(chan struct{}, 1), files: RoutedDHCPOwnerFilesV3{Request: qW, Reply: rR}, scanner: routedDHCPOwnerScannerV3(rR), facts: routedDHCPOwnerFactsV3{binding: b}, alive: alive.Load, now: func() (int64, error) { return now.Load(), nil }}
	t.Cleanup(func() { _ = r.Close() })
	return r, qR, rW, alive, now
}

func TestRoutedDHCPOwnerV3LiveRPCStableIdentityAndRevocation(t *testing.T) {
	r, q, reply, _, now := routedOwnerReaderFixtureV3(t)
	_, l := routedOwnerFixtureV3(t)
	source := &routedOwnerTestSourceV3{lease: l}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveRoutedDHCPOwnerV3(ctx, q, reply, r.facts.binding.Owner.Incarnation, source) }()
	first, err := r.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			fact, e := r.Current(ctx)
			if e != nil {
				errs <- e
			} else if fact != first {
				errs <- errors.New("poll changed grant")
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	source.mu.Lock()
	calls := source.calls
	source.mu.Unlock()
	if calls != 17 {
		t.Fatalf("cached authority: %d live requests", calls)
	}
	source.set(l, ErrUnavailable)
	if _, err = r.Current(ctx); err == nil {
		t.Fatal("source outage returned cached grant")
	}
	l.Epoch++
	l.Event.Reason = "RENEW"
	l.Event.BootNS = int64(12 * time.Second)
	l.DeadlineBootNS = int64(130 * time.Second)
	now.Store(int64(13 * time.Second))
	source.set(l, nil)
	next, err := r.Current(ctx)
	if err != nil || next.Epoch == first.Epoch || next.Fact.Sequence <= first.Fact.Sequence {
		t.Fatal("confirmed renewal missing", err)
	}
	now.Store(l.DeadlineBootNS)
	if _, err = r.Current(ctx); err == nil {
		t.Fatal("expired grant accepted")
	}
	_ = r.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("EOF did not stop source server")
	}
}

func TestRoutedDHCPOwnerV3ReaderFencesInvalidResponses(t *testing.T) {
	for _, kind := range []string{"replayed-sequence", "foreign-incarnation", "unknown", "duplicate", "oversized", "eof", "dead-after-query", "both-lease-and-unavailable", "mutated-epoch", "expired"} {
		t.Run(kind, func(t *testing.T) {
			r, q, reply, alive, _ := routedOwnerReaderFixtureV3(t)
			_, l := routedOwnerFixtureV3(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer reply.Close()
				scan := routedDHCPOwnerScannerV3(q)
				if !scan.Scan() {
					return
				}
				var request routedDHCPOwnerRequestV3
				if routedDHCPOwnerDecodeV3(scan.Bytes(), &request) != nil {
					return
				}
				response := routedDHCPOwnerReplyV3{Version: 3, Incarnation: request.Incarnation, Sequence: request.Sequence, Lease: &l}
				switch kind {
				case "replayed-sequence":
					response.Sequence++
				case "foreign-incarnation":
					response.Incarnation = strings.Repeat("c", 32)
				case "unknown":
					_, _ = reply.Write([]byte("{\"unknown\":true}\n"))
					return
				case "duplicate":
					_, _ = reply.Write([]byte("{\"version\":3,\"version\":3}\n"))
					return
				case "oversized":
					_, _ = reply.Write([]byte(strings.Repeat("x", routedDHCPOwnerFrameV3+1) + "\n"))
					return
				case "eof":
					return
				case "dead-after-query":
					alive.Store(false)
				case "both-lease-and-unavailable":
					response.Unavailable = true
				case "mutated-epoch":
					l.Epoch = 0
				case "expired":
					l.DeadlineBootNS = int64(10 * time.Second)
				}
				_ = routedDHCPOwnerWriteV3(reply, response)
			}()
			if _, err := r.Current(context.Background()); err == nil {
				t.Fatal("invalid response granted authority")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("writer blocked")
			}
			if _, err := r.Current(context.Background()); err == nil {
				t.Fatal("closed stream revived authority")
			}
		})
	}
}

func TestRoutedDHCPOwnerV3CancellationCloseAndDeadOwner(t *testing.T) {
	for _, kind := range []string{"cancel", "close", "dead-before-query", "blocked-gate"} {
		t.Run(kind, func(t *testing.T) {
			r, q, _, alive, _ := routedOwnerReaderFixtureV3(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "dead-before-query" {
				alive.Store(false)
				if _, err := r.Current(ctx); err == nil {
					t.Fatal("dead owner accepted")
				}
				return
			}
			if kind == "blocked-gate" {
				r.gate <- struct{}{}
				cancel()
				if _, err := r.Current(ctx); err == nil {
					t.Fatal("canceled waiter accepted")
				}
				<-r.gate
				return
			}
			done := make(chan error, 1)
			go func() { _, err := r.Current(ctx); done <- err }()
			_ = q.SetReadDeadline(time.Now().Add(time.Second))
			scan := routedDHCPOwnerScannerV3(q)
			if !scan.Scan() {
				t.Fatal("missing query")
			}
			if kind == "cancel" {
				cancel()
			} else {
				_ = r.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("interrupted query granted authority")
				}
			case <-time.After(time.Second):
				t.Fatal("interruption did not bound read")
			}
		})
	}
}

func TestRoutedDHCPOwnerV3ServerRejectsReplayAndUnknownOperations(t *testing.T) {
	for _, operation := range []string{"stop", "renew", "current"} {
		t.Run(operation, func(t *testing.T) {
			b, l := routedOwnerFixtureV3(t)
			qR, qW := routedOwnerPipeV3(t)
			rR, rW := routedOwnerPipeV3(t)
			source := &routedOwnerTestSourceV3{lease: l}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- serveRoutedDHCPOwnerV3(ctx, qR, rW, b.Owner.Incarnation, source) }()
			if operation == "current" {
				_ = routedDHCPOwnerWriteV3(qW, routedDHCPOwnerRequestV3{3, b.Owner.Incarnation, 1, "current"})
				_ = rR.SetReadDeadline(time.Now().Add(time.Second))
				if !routedDHCPOwnerScannerV3(rR).Scan() {
					t.Fatal("initial request failed")
				}
			}
			_ = routedDHCPOwnerWriteV3(qW, routedDHCPOwnerRequestV3{3, b.Owner.Incarnation, 1, operation})
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid request accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("server did not reject request")
			}
		})
	}
}

func TestRoutedDHCPOwnerV3PIDFDIdentityAndProcessDeath(t *testing.T) {
	// Fixed unprivileged process; no DHCP, mounts or namespace mutation.
	cmd := exec.Command("/bin/cat")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	netNS, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	mntNS, err := namespaceID("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	fd, start, err := routedDHCPOwnerPinV3(cmd.Process.Pid, os.Getpid(), netNS, mntNS)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	if start == 0 || !routedDHCPOwnerPIDFDAliveV3(fd, cmd.Process.Pid) || routedDHCPOwnerPIDFDAliveV3(fd, os.Getpid()) {
		t.Fatal("pidfd identity not verified")
	}
	if bad, _, e := routedDHCPOwnerPinV3(cmd.Process.Pid, os.Getpid()+1, netNS, mntNS); e == nil {
		_ = bad.Close()
		t.Fatal("foreign parent accepted")
	}
	if bad, _, e := routedDHCPOwnerPinV3(cmd.Process.Pid, os.Getpid(), netNS+1, mntNS); e == nil {
		_ = bad.Close()
		t.Fatal("foreign namespace accepted")
	}
	_ = input.Close()
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if routedDHCPOwnerPIDFDAliveV3(fd, cmd.Process.Pid) {
		t.Fatal("dead process remained live")
	}
	b, _ := routedOwnerFixtureV3(t)
	if r, e := NewRoutedDHCPOwnerReaderV3(RoutedDHCPOwnerFilesV3{RolePIDFD: fd, LeasePIDFD: fd}, b); e == nil {
		_ = r.Close()
		t.Fatal("untrusted descriptors accepted")
	}
}

func TestRoutedDHCPOwnerV3RejectsUnsafeLaunchWithoutEffects(t *testing.T) {
	if owner, err := StartRoutedDHCPOwnerV3(context.Background(), RoutedDHCPOwnerOptionsV3{}); err == nil {
		_ = owner.Close()
		t.Fatal("empty bootstrap started owner")
	}
	if os.Geteuid() != 0 {
		if err := RunRoutedDHCPOwnerRoleV3(context.Background()); err == nil {
			t.Fatal("unprivileged role accepted")
		}
	}
	for _, raw := range []string{"", "12 broken", "12 (a) Z 1", strings.Repeat("x", 8193)} {
		if _, _, err := routedDHCPOwnerStatV3([]byte(raw), 12); err == nil {
			t.Fatal("invalid proc identity accepted")
		}
	}
}
