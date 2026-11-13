package routedactivation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func TestDHCPColdBootV3SelectedBeforeLANAndExpiryRestoresActualBaseline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		before, deps, target := artifactFixture(t)
		n := deps.Network.Config
		for i := range n.Interfaces {
			if n.Interfaces[i].Role == networkplan.WAN {
				n.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "dhcp"}
			}
		}
		network, err := networkplan.Canonical(n)
		if err != nil {
			t.Fatal(err)
		}
		fw := target.Firewall.Config
		fw.Routed.Network = network
		firewall, err := configpoc.CanonicalRouted(fw)
		if err != nil {
			t.Fatal(err)
		}
		localConfig := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{deps.LocalInterfaces[0]}, Services: []localpolicy.Service{}}
		local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localConfig})
		if err != nil {
			t.Fatal(err)
		}
		target, err = configpoc.NewRoutedActivationBundleV1(firewall, local)
		if err != nil {
			t.Fatal(err)
		}
		saved, err := configpoc.NewRoutedActivationBundleV1(*before.LegacyFirewall.Revision, local)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := before.Network
		snapshot.PlanHash, snapshot.Hash = network.Hash, ""
		raw, _ := json.Marshal(snapshot)
		snapshot.Hash = artifactDigest(raw)
		k := &kernelFixture{objects: map[Table][]map[string]any{}}
		net := &networkFixture{snapshot: snapshot}
		listeners := &listenersFixture{}
		plan := configpoc.RoutedTransitionV1{Version: 1, Operation: "dhcp-boot", Previous: strings.Repeat("1", 64), Target: strings.Repeat("2", 64), BeforeOwned: strings.Repeat("3", 64), TargetOwned: strings.Repeat("4", 64), Dependencies: strings.Repeat("5", 64)}
		var p PreparationV1
		selected := false
		e, err := New(k, net, listeners, Options{Legacy: saved.Firewall, ResolvePlan: func(_ context.Context, got configpoc.RoutedTransitionV1, _ *configpoc.RoutedActivationBundleV1, _ configpoc.RoutedActivationBundleV1, _ time.Time) (PreparationV1, error) {
			if !selected || got != plan {
				return PreparationV1{}, ErrState
			}
			return p, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		p, err = e.PrepareColdBoot(context.Background(), target, saved)
		if err != nil || p.Before.Version != 3 || p.Target.Version != 3 || p.Dependencies.NetworkMode != "dhcp-lan" || net.calls != 0 || len(k.batches) != 0 {
			t.Fatal("read-only DHCP boot", err)
		}
		g, err := nftguardian.NewGroup(e)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		if g.BootstrapStartup(context.Background(), plan, target, time.Now().UTC()) == nil || net.calls != 0 || len(k.batches) != 0 {
			t.Fatal("effects before selected Boot")
		}
		selected = true
		net.before = func() error {
			deny, err := denyTablesFor(target, p.Dependencies)
			if err != nil {
				return err
			}
			for table, state := range deny {
				if !e.tableMatches(context.Background(), Table(table), state, p.Dependencies) {
					return ErrState
				}
			}
			return nil
		}
		if err = g.BootstrapStartup(context.Background(), plan, target, time.Now().UTC()); err != nil {
			t.Fatal("selected DHCP boot", err)
		}
		e.mu.Lock()
		active, calls, listenerCount := net.active, net.calls, len(listeners.actual)
		e.mu.Unlock()
		if !active || calls != 1 || listenerCount != 0 {
			t.Fatal("LAN bootstrap result")
		}
		time.Sleep(11 * time.Second)
		synctest.Wait()
		state, hash, err := g.SnapshotObserved()
		e.mu.Lock()
		active, tables := net.active, len(k.objects)
		e.mu.Unlock()
		if err != nil || state.Phase != "expired" || hash != "" || active || tables != 0 {
			t.Fatal("unconfirmed LAN did not return to actual absence", state, err)
		}
	})
}
