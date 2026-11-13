package previewruntime

import (
	"context"
	"errors"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"net"
	"testing"
	"time"
)

func TestRoutedDHCPInitialWaitingV1MissingLeaseHasNoEffects(t *testing.T) {
	r, k, _, _ := dhcpRuntimeFixtureV3(t)
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) { return RoutedDHCPOwnerFactV3{}, ErrUnavailable }
	grant, err := r.begin(context.Background())
	if err == nil || grant.Epoch != 0 {
		t.Fatal("missing lease granted authority", err)
	}
	if len(k.events) != 0 || r.gate != nil || r.lease != nil || r.work != "" || r.opened {
		t.Fatalf("missing lease caused pre-grant effects: events=%v gate=%t lease=%t", k.events, r.gate != nil, r.lease != nil)
	}
}

func TestRoutedDHCPInitialWaitingV1PreservesQualifiedSession(t *testing.T) {
	r, k, _, fact := dhcpRuntimeFixtureV3(t)
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
		return RoutedDHCPOwnerFactV3{}, errRoutedDHCPInitialWaitingV1
	}
	s, inspection, _ := integritySessionFixtureV3(t)
	s.dhcp = r
	s.inventory = func(context.Context) (networkinventory.Snapshot, error) {
		return networkinventory.Snapshot{}, ErrUnavailable
	}
	a, b := net.Pipe()
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { done <- s.ServeRoutedV3(ctx, b, r.identity.RunID) }()
	c, err := firewallipc.ConnectRoutedDHCPV3(ctx, a, r.identity.RunID, r.identity.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(); <-done }()
	remote, err := NewRoutedRemoteIntegrityV3(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = remote.Attach(ctx, inspection.ref); err != nil {
		t.Fatal(err)
	}
	if _, err = remote.Inspect(ctx, inspection.ref); err != nil {
		t.Fatal(err)
	}
	controller := &RoutedDHCPControllerV3{remote: &routedDHCPRemoteV3{client: c}}
	for range 2 {
		if err = controller.Reconcile(ctx); err != firewallipc.ErrRoutedDHCPWaitingV1 {
			t.Fatal("initial wait", err)
		}
		if !c.IntegrityPublicationAllowedV1() || !c.IntegrityClosingAllowedV1() || controller.work != "" || controller.grant.Epoch != 0 || len(k.events) != 0 {
			t.Fatal("waiting changed readiness or produced effects")
		}
	}
	r.mu.Lock()
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) { return *fact, nil }
	r.mu.Unlock()
	out, err := c.Call(ctx, "dhcp_begin", firewallipc.RoutedDHCPRequestV3{})
	if err != nil || out.DHCP.Epoch != fact.Epoch || !c.IntegrityPublicationAllowedV1() {
		t.Fatal("fresh grant after waiting", err)
	}
}

func TestRoutedDHCPInitialWaitingV1NeverCoversUncertainty(t *testing.T) {
	for _, kind := range []string{"generic", "revoked", "cancel", "forward-open", "not-ready", "selected", "late-wait"} {
		t.Run(kind, func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
				return RoutedDHCPOwnerFactV3{}, errRoutedDHCPInitialWaitingV1
			}
			switch kind {
			case "generic":
				r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) { return RoutedDHCPOwnerFactV3{}, ErrUnavailable }
			case "revoked":
				r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) { x := *fact; x.Fact.Revoked = true; return x, nil }
			case "cancel":
				cancel()
			case "forward-open":
				k.forward = true
			case "not-ready":
				r.ready = func() error { return configpoc.ErrRecovery }
			case "selected":
				reader.denied = true
			case "late-wait":
				calls := 0
				r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
					calls++
					if calls == 1 {
						return *fact, nil
					}
					return RoutedDHCPOwnerFactV3{}, errRoutedDHCPInitialWaitingV1
				}
			}
			g, err := r.begin(ctx)
			if !errors.Is(err, configpoc.ErrRecovery) || g.Epoch != 0 {
				t.Fatal("uncertainty became waiting or grant", kind, err)
			}
			if kind != "late-wait" && len(k.events) != 0 {
				t.Fatal("preflight mutated kernel", k.events)
			}
			if kind == "late-wait" && len(k.events) == 0 {
				t.Fatal("did not exercise post-effect failure")
			}
		})
	}
}
