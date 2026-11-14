package previewruntime

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

// Actual runtime, private session/codec/client and the publication predicate
// consumed by SelectedStore.Prepare; selected-store/kernel I/O are doubles.
func TestRoutedDHCPNoLeaseV1ExpireThenBoundPreservesAdmission(t *testing.T) {
	r, k, _, fact := dhcpRuntimeFixtureV3(t)
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
		return RoutedDHCPOwnerFactV3{}, routedDHCPNoLeaseV1{2}
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
	if err != nil || remote.Attach(ctx, inspection.ref) != nil {
		t.Fatal("attach", err)
	}
	if _, err = remote.Inspect(ctx, inspection.ref); err != nil {
		t.Fatal(err)
	}
	controller := &RoutedDHCPControllerV3{remote: &routedDHCPRemoteV3{client: c}}
	if err = controller.Reconcile(ctx); err == nil || controller.work != "" || controller.grant.Epoch != 0 || len(k.events) != 0 {
		t.Fatal("no-lease preflight performed effects or returned a grant", err)
	}
	if err != firewallipc.ErrRoutedDHCPNoLeaseV1 {
		t.Fatal("no-lease state lost its distinct versioned result", err)
	}
	if !c.IntegrityPublicationAllowedV1() || !c.IntegrityClosingAllowedV1() {
		t.Fatal("EXPIRE no-effect preflight fenced subsequent BOUND admission", err)
	}
	r.mu.Lock()
	fact.Epoch = 3
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) { return *fact, nil }
	r.mu.Unlock()
	out, err := c.Call(ctx, "dhcp_begin", firewallipc.RoutedDHCPRequestV3{})
	if err != nil || out.DHCP.Epoch != 3 || !c.IntegrityPublicationAllowedV1() {
		t.Fatal("BOUND3 lost selected-store publication eligibility", err)
	}
}

func TestRoutedDHCPNoLeaseV1BeginRejectsUncertainty(t *testing.T) {
	for _, mode := range []string{"generic", "mixed-fact", "work", "lease", "opened", "forwarding", "baseline", "not-ready", "selected", "death-after-proof", "epoch-regression", "initial-revival", "cancel-after-proof", "after-effects"} {
		t.Run(mode, func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
				calls++
				if mode == "generic" || mode == "death-after-proof" && calls > 1 {
					return RoutedDHCPOwnerFactV3{}, ErrUnavailable
				}
				if mode == "mixed-fact" || mode == "after-effects" && calls == 1 {
					if mode == "after-effects" {
						return *fact, nil
					}
					return *fact, routedDHCPNoLeaseV1{2}
				}
				if mode == "epoch-regression" && calls > 1 {
					return RoutedDHCPOwnerFactV3{}, routedDHCPNoLeaseV1{1}
				}
				if mode == "initial-revival" && calls > 1 {
					return RoutedDHCPOwnerFactV3{}, errRoutedDHCPInitialWaitingV1
				}
				return RoutedDHCPOwnerFactV3{}, routedDHCPNoLeaseV1{2}
			}
			switch mode {
			case "work":
				r.work = "selected"
			case "lease":
				r.lease = dhcpRuntimeLeaseV3{k}
			case "opened":
				r.opened = true
			case "forwarding":
				k.forward = true
			case "baseline":
				k.target = true
			case "not-ready":
				r.ready = func() error { return configpoc.ErrRecovery }
			case "selected":
				reader.denied = true
			case "cancel-after-proof":
				r.baseline = func(context.Context) error { cancel(); return nil }
			}
			grant, err := r.begin(ctx)
			if _, noLease := routedDHCPNoLeaseEpochV1(err); err == nil || noLease || grant.Epoch != 0 || err == errRoutedDHCPInitialWaitingV1 {
				t.Fatal("uncertain operation became normal no-lease", mode, err)
			}
		})
	}
}

func TestRoutedDHCPNoLeaseV1BoundDuringBaselineUsesAtomicGrant(t *testing.T) {
	r, _, _, fact := dhcpRuntimeFixtureV3(t)
	calls := 0
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
		calls++
		if calls == 1 {
			return RoutedDHCPOwnerFactV3{}, routedDHCPNoLeaseV1{2}
		}
		f := *fact
		f.Epoch = 3
		return f, nil
	}
	g, err := r.begin(context.Background())
	if err != nil || g.Epoch != 3 {
		t.Fatal("BOUND during preflight mixed snapshots", err)
	}
}
