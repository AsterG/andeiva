package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

func TestRoutedSessionV3RejectsUnsupportedRenewalProfile(t *testing.T) {
	for _, profile := range []bool{true, false} {
		t.Run(map[bool]string{true: "unsupported-profile", false: "unnegotiated-verb"}[profile], func(t *testing.T) {
			authority := &routedTransportAuthorityV3{}
			session, err := NewRoutedSessionV3(authority, routedTransportReaderV3{})
			if err != nil {
				t.Fatal(err)
			}
			// Satisfy the existing V3 assembly shape so those independent guards
			// cannot hide a missing V4 support/verb guard in this regression.
			session.integrity = &routedIntegrityGateV3{}
			session.inventory = func(context.Context) (networkinventory.Snapshot, error) {
				t.Error("unexpected inventory effect")
				return networkinventory.Snapshot{}, ErrUnavailable
			}
			session.dhcp = &RoutedDHCPRuntimeV3{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, peer := net.Pipe()
			done := make(chan error, 1)
			go func() { done <- session.ServeRoutedV3(ctx, peer, strings.Repeat("a", 32)) }()
			defer client.Close()
			hello := firewallipc.NewRoutedHelloV3(strings.Repeat("a", 32), 22)
			hello.RequiredFeatures = append(hello.RequiredFeatures, firewallipc.RoutedIntegrityCapabilityV3, firewallipc.RoutedInventoryCapabilityV3, firewallipc.RoutedDHCPCapabilityV3)
			if profile {
				hello.RequiredFeatures = append(hello.RequiredFeatures, firewallipc.RoutedDHCPRenewalCapabilityV4)
			}
			if err = json.NewEncoder(client).Encode(hello); err != nil {
				t.Fatal(err)
			}
			scan := bufio.NewScanner(client)
			if !profile {
				if !scan.Scan() {
					t.Fatal("legacy hello was not accepted")
				}
				var accepted firewallipc.RoutedHelloV3
				if json.Unmarshal(scan.Bytes(), &accepted) != nil || accepted.HasCapability(firewallipc.RoutedDHCPRenewalCapabilityV4) {
					t.Fatal("invalid legacy agreement")
				}
				request := firewallipc.RoutedRequestV3{ProtocolVersion: firewallipc.RoutedProtocolV3, Run: strings.Repeat("a", 32), Sequence: accepted.Epoch<<32 | 1, Namespace: 22, Domain: "routed", Verb: "dhcp_renew", Payload: json.RawMessage(`{"work":"` + strings.Repeat("b", 64) + `","snapshot":"` + strings.Repeat("c", 64) + `"}`)}
				if err = json.NewEncoder(client).Encode(request); err != nil {
					t.Fatal(err)
				}
			}
			if scan.Scan() {
				t.Fatal("unsupported renewal was acknowledged")
			}
			if err = <-done; !errors.Is(err, ErrIdentity) || authority.calls.Load() != 0 {
				t.Fatal("unsupported renewal reached dispatch", err)
			}
		})
	}
}

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
