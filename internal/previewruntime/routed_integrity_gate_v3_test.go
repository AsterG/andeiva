package previewruntime

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
)

type integrityReaderFixtureV3 struct {
	ref                   configpoc.SelectionReferenceV2
	state                 configpoc.IntegrityStateV1
	entered, release      chan struct{}
	captureErr, errorFull error
	calls                 int
	remaining             time.Duration
}

func (f *integrityReaderFixtureV3) CaptureReferenceV1(context.Context) (configpoc.SelectionReferenceV2, error) {
	return f.ref, f.captureErr
}
func (f *integrityReaderFixtureV3) InspectQuiescentV1(ctx context.Context, ref configpoc.SelectionReferenceV2) (configpoc.IntegrityResultV1, error) {
	f.calls++
	if deadline, ok := ctx.Deadline(); ok {
		f.remaining = time.Until(deadline)
	}
	if f.entered != nil {
		close(f.entered)
	}
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return configpoc.IntegrityResultV1{Selection: f.ref, State: configpoc.IntegrityCancelledV1}, ctx.Err()
		}
	}
	return configpoc.IntegrityResultV1{Selection: f.ref, State: f.state}, f.errorFull
}

type integrityMarkerFixtureV3 struct {
	mu        sync.Mutex
	blocked   bool
	markCalls int
	markErr   error
}

func (f *integrityMarkerFixtureV3) Check() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blocked {
		return configpoc.ErrRecovery
	}
	return nil
}
func (f *integrityMarkerFixtureV3) MarkBlocked() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked = true
	f.markCalls++
	return f.markErr
}
func integrityRefFixtureV3() configpoc.SelectionReferenceV2 {
	return configpoc.SelectionReferenceV2{Selection: strings.Repeat("1", 64), Previous: strings.Repeat("2", 64), State: strings.Repeat("3", 64), Lineage: "lineage", Sequence: 3, Generation: 2, Mode: "prepare"}
}
func integritySessionFixtureV3(t *testing.T) (*RoutedSessionV3, *integrityReaderFixtureV3, *integrityMarkerFixtureV3) {
	t.Helper()
	reader := &integrityReaderFixtureV3{ref: integrityRefFixtureV3(), state: configpoc.IntegrityCompleteV1}
	fence := &integrityMarkerFixtureV3{}
	session, err := NewRoutedIntegritySessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{}, reader, fence)
	if err != nil {
		t.Fatal(err)
	}
	return session, reader, fence
}
func connectIntegrityFixtureV3(t *testing.T, s *RoutedSessionV3) (*firewallipc.RoutedClientV3, <-chan error) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.ServeRoutedV3(context.Background(), b, strings.Repeat("a", 32)) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := firewallipc.ConnectRoutedIntegrityV3(ctx, a, strings.Repeat("a", 32), 22)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}
func TestRoutedIntegrityV3AttachIsNotReadiness(t *testing.T) {
	s, reader, _ := integritySessionFixtureV3(t)
	client, _ := connectIntegrityFixtureV3(t, s)
	remote, err := NewRoutedRemoteIntegrityV3(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Attach(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	if !remote.IntegrityClosingAllowedV1() || remote.IntegrityPublicationAllowedV1() {
		t.Fatal("Attach publication/closing capabilities conflated")
	}
	if s.integrity.phase != routedIntegrityReconcilingV3 || reader.calls != 0 {
		t.Fatal("Attach fabricated full qualification")
	}
	if _, err := s.integrity.resolve(context.Background(), s.source, firewallipc.RoutedReferenceV3{}, "arm"); err == nil {
		t.Fatal("cold effect without durable continuation")
	}
	result, err := remote.Inspect(context.Background(), reader.ref)
	if err != nil || result.State != configpoc.IntegrityCompleteV1 {
		t.Fatal(result, err)
	}
	if !remote.IntegrityPublicationAllowedV1() {
		t.Fatal("complete scan did not permit publication")
	}
	if s.integrity.phase != routedIntegrityReadyV3 || reader.calls != 1 || reader.remaining < 25*time.Second {
		t.Fatal("inspection did not use separate 30s context", s.integrity.phase, reader.calls, reader.remaining)
	}
	if _, err := s.integrity.resolve(context.Background(), s.source, firewallipc.RoutedReferenceV3{}, "arm"); err != nil {
		t.Fatal(err)
	}
}
func TestRoutedIntegrityV3RejectsCapabilityFallback(t *testing.T) {
	for _, integrityServer := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-server", true: "old-client"}[integrityServer], func(t *testing.T) {
			s, _, _ := integritySessionFixtureV3(t)
			if !integrityServer {
				s.integrity = nil
			}
			a, b := net.Pipe()
			defer a.Close()
			done := make(chan error, 1)
			go func() { done <- s.ServeRoutedV3(context.Background(), b, strings.Repeat("a", 32)) }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var err error
			if integrityServer {
				_, err = firewallipc.ConnectRoutedV3(ctx, a, strings.Repeat("a", 32), 22)
			} else {
				_, err = firewallipc.ConnectRoutedIntegrityV3(ctx, a, strings.Repeat("a", 32), 22)
			}
			if err == nil {
				t.Fatal("capability mismatch silently accepted")
			}
			<-done
		})
	}
}
func TestRoutedIntegrityV3IncompleteNeverReady(t *testing.T) {
	for _, state := range []configpoc.IntegrityStateV1{configpoc.IntegrityCancelledV1, configpoc.IntegrityStaleV1, configpoc.IntegrityUnavailableV1, "unknown"} {
		t.Run(string(state), func(t *testing.T) {
			s, reader, _ := integritySessionFixtureV3(t)
			reader.state = state
			if _, err := s.integrity.attach(context.Background(), reader.ref); err != nil {
				t.Fatal(err)
			}
			result, err := s.integrity.inspect(context.Background(), reader.ref, s.authority)
			if err != nil {
				t.Fatal(err)
			}
			if result.State == configpoc.IntegrityCompleteV1 || s.integrity.phase == routedIntegrityReadyV3 {
				t.Fatal("incomplete inspection qualified")
			}
		})
	}
}
func TestRoutedIntegrityV3PersistFailureRemainsFenced(t *testing.T) {
	s, reader, fence := integritySessionFixtureV3(t)
	reader.state = configpoc.IntegrityFencedV1
	fence.markErr = ErrUnavailable
	if _, err := s.integrity.attach(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	result, err := s.integrity.inspect(context.Background(), reader.ref, s.authority)
	if err != nil || result.State != configpoc.IntegrityFencedV1 || !fence.blocked || fence.markCalls != 1 {
		t.Fatal(result, err)
	}
	if _, err := s.integrity.attach(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	if s.integrity.phase != routedIntegrityFencedV3 {
		t.Fatal("reconnect cleared fence")
	}
	if _, err := s.integrity.resolve(context.Background(), s.source, firewallipc.RoutedReferenceV3{}, "recover"); err == nil {
		t.Fatal("fenced recovery authorized without durable capability")
	}
}
func TestRoutedIntegrityV3InspectionDispatchDrainsBeforeHandover(t *testing.T) {
	s, reader, _ := integritySessionFixtureV3(t)
	reader.entered = make(chan struct{})
	reader.release = make(chan struct{})
	client, serverDone := connectIntegrityFixtureV3(t, s)
	remote, _ := NewRoutedRemoteIntegrityV3(client)
	if err := remote.Attach(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	callDone := make(chan error, 1)
	callCtx, cancelCall := context.WithCancel(context.Background())
	defer cancelCall()
	go func() {
		result, err := remote.Inspect(callCtx, reader.ref)
		if err != nil && result.State != "" {
			t.Error("lost acknowledgement fabricated a typed result")
		}
		callDone <- err
	}()
	<-reader.entered
	if _, err := s.integrity.resolve(context.Background(), s.source, firewallipc.RoutedReferenceV3{}, "arm"); err == nil {
		t.Fatal("checking allowed effect")
	}
	cancelCall()
	if err := <-callDone; err == nil {
		t.Fatal("lost reply reported as success")
	}
	// Closing the wire must not acknowledge transfer while full inspection runs.
	a, b := net.Pipe()
	defer a.Close()
	replacement := make(chan error, 1)
	go func() { replacement <- s.ServeRoutedV3(context.Background(), b, strings.Repeat("a", 32)) }()
	if err := <-replacement; err == nil {
		t.Fatal("replacement acquired in-flight controller")
	}
	close(reader.release)
	_ = client.Close()
	<-serverDone
	next, _ := connectIntegrityFixtureV3(t, s)
	nextRemote, _ := NewRoutedRemoteIntegrityV3(next)
	if err := nextRemote.Attach(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	if s.integrity.phase != routedIntegrityReadyV3 || s.integrity.lastComplete != reader.ref {
		t.Fatal("handover reset surviving helper qualification")
	}
}
func TestRoutedIntegrityV3EffectErrorRevokesPublication(t *testing.T) {
	s, reader, _ := integritySessionFixtureV3(t)
	client, _ := connectIntegrityFixtureV3(t, s)
	remote, _ := NewRoutedRemoteIntegrityV3(client)
	if err := remote.Attach(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Inspect(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	if !remote.IntegrityPublicationAllowedV1() {
		t.Fatal("qualification missing")
	}
	ref := firewallipc.RoutedReferenceV3{Work: strings.Repeat("a", 64), Lineage: "lineage", Generation: "1"}
	// The trusted fixture source returns no valid plan. No effect occurs, and the
	// authenticated failed effect RPC must still revoke publication immediately.
	if _, err := client.Call(context.Background(), "arm", firewallipc.RoutedSelectedV3{Reference: ref}); err == nil {
		t.Fatal("invalid plan accepted")
	}
	if remote.IntegrityPublicationAllowedV1() || remote.IntegrityClosingAllowedV1() {
		t.Fatal("effect failure left mutation admission available")
	}
	if _, err := remote.Inspect(context.Background(), reader.ref); err != nil {
		t.Fatal(err)
	}
	if !remote.IntegrityPublicationAllowedV1() {
		t.Fatal("new complete inspection did not restore publication")
	}
	_ = client.Close()
	if remote.IntegrityPublicationAllowedV1() || remote.IntegrityClosingAllowedV1() {
		t.Fatal("closed channel retained authority")
	}
}
func TestRoutedIntegrityV3CaptureFailureCannotAttach(t *testing.T) {
	s, reader, _ := integritySessionFixtureV3(t)
	reader.captureErr = ErrUnavailable
	client, _ := connectIntegrityFixtureV3(t, s)
	remote, _ := NewRoutedRemoteIntegrityV3(client)
	if err := remote.Attach(context.Background(), reader.ref); err == nil {
		t.Fatal("failed independent capture acknowledged")
	}
	if remote.IntegrityClosingAllowedV1() || remote.IntegrityPublicationAllowedV1() {
		t.Fatal("failed capture granted capability")
	}
}
