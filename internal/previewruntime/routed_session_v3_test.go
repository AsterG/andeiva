package previewruntime

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type routedTransportAuthorityV3 struct {
	configpoc.RoutedAuthorityV1
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (a *routedTransportAuthorityV3) Identity() networkexecutor.OwnedNamespaceIdentity {
	return networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Namespace: 22, Host: 11, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}
}
func (a *routedTransportAuthorityV3) Observe(ctx context.Context) (configpoc.RoutedReceiptV1, string, error) {
	if a.calls.Add(1) == 1 && a.entered != nil {
		close(a.entered)
		select {
		case <-a.release:
		case <-ctx.Done():
			return configpoc.RoutedReceiptV1{}, "", ctx.Err()
		}
	}
	return configpoc.RoutedReceiptV1{Phase: "bootstrap"}, "", nil
}

type routedTransportReaderV3 struct{}

func (routedTransportReaderV3) Resolve(context.Context, firewallipc.RoutedReferenceV3, string) (configpoc.RoutedSelectedPlanV1, error) {
	return configpoc.RoutedSelectedPlanV1{}, nil
}
func (routedTransportReaderV3) PrepareView(context.Context) (RoutedPreparationViewV3, error) {
	return RoutedPreparationViewV3{}, configpoc.ErrRecovery
}

func routedTransportConnectV3(t *testing.T, ctx context.Context, s *RoutedSessionV3) (*firewallipc.RoutedClientV3, <-chan error, error) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- s.ServeRoutedV3(ctx, b, strings.Repeat("a", 32)) }()
	call, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	client, e := firewallipc.ConnectRoutedV3(call, a, strings.Repeat("a", 32), 22)
	return client, done, e
}
func TestRoutedSessionV3RejectsUnverifiedPlansWithoutEffects(t *testing.T) {
	authority := &routedTransportAuthorityV3{}
	session, e := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, done, e := routedTransportConnectV3(t, ctx, session)
	if e != nil {
		t.Fatal(e)
	}
	payload := firewallipc.RoutedSelectedV3{Reference: firewallipc.RoutedReferenceV3{Work: strings.Repeat("b", 64), Lineage: "fixture-lineage", Generation: "2"}}
	for _, verb := range []string{"arm", "apply", "confirm", "recover", "bootstrap", "resume"} {
		if _, e = client.Call(ctx, verb, payload); e == nil {
			t.Fatal("unverified plan accepted", verb)
		}
	}
	value, e := client.Call(ctx, "observe", struct{}{})
	if e != nil || value.Observed.Receipt.Phase != "bootstrap" {
		t.Fatal(e)
	}
	if authority.calls.Load() != 1 {
		t.Fatal("unexpected authority calls")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("controller did not exit")
	}
}
func TestRoutedSessionV3DisconnectFencesAnInflightController(t *testing.T) {
	authority := &routedTransportAuthorityV3{entered: make(chan struct{}), release: make(chan struct{})}
	session, e := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, finished, e := routedTransportConnectV3(t, ctx, session)
	if e != nil {
		t.Fatal(e)
	}
	call, cancelCall := context.WithCancel(ctx)
	outcome := make(chan error, 1)
	go func() { _, e := first.Call(call, "observe", struct{}{}); outcome <- e }()
	select {
	case <-authority.entered:
	case <-time.After(time.Second):
		t.Fatal("first call did not enter")
	}
	cancelCall()
	if e = <-outcome; e == nil {
		t.Fatal("lost controller reported success")
	}
	next, denied, e := routedTransportConnectV3(t, ctx, session)
	if e == nil {
		_ = next.Close()
		t.Fatal("new controller bypassed an inflight call")
	}
	<-denied
	close(authority.release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("inflight controller did not finish")
	}
	last, done, e := routedTransportConnectV3(t, ctx, session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = last.Call(ctx, "observe", struct{}{}); e != nil {
		t.Fatal(e)
	}
	_ = last.Close()
	<-done
}
