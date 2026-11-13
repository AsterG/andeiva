//go:build linux

package configpoc

import (
	"context"
	"reflect"
	"testing"
)

// Real selected history and canonical dependencies; authority responses are modeled.
// This proves metadata admission, not physical absence of listeners or native boot.
func TestRoutedBootNoServicesV3PreservesSavedAndChecksHistory(t *testing.T) {
	for _, dhcp := range []bool{false, true} {
		name := "static"
		if dhcp {
			name = "dhcp"
		}
		t.Run(name, func(t *testing.T) {
			c, a, _, _ := noServicesCoordinatorFixtureV3(t)
			previous := clone(*c.store.state.Configuration)
			saved, err := bundleFromConfigurationV2(previous)
			if err != nil {
				t.Fatal(err)
			}
			cfg := clone(previous)
			cfg.Firewall.Running = noServicesFirewallFixtureV3(t, dhcp)
			cfg.LocalServices.Running, err = noServicesInventoryV3(cfg.Firewall.Running)
			if err != nil {
				t.Fatal(err)
			}
			if err = cfg.refresh(); err != nil {
				t.Fatal(err)
			}
			target, err := bundleFromConfigurationV2(cfg)
			if err != nil {
				t.Fatal(err)
			}
			a.prepared.PlanHash = target.Firewall.Config.Routed.Network.Hash
			a.prepared.Hash = ""
			_, a.prepared.Hash, err = v2Canonical(a.prepared)
			if err != nil {
				t.Fatal(err)
			}
			prep, err := a.PrepareBoot(context.Background(), target, saved)
			if err != nil {
				t.Fatal(err)
			}
			planned := clone(prep.Before)
			planned.LegacyFirewall = TableStateV1{Presence: Present, Revision: &saved.Firewall}
			baseline := RoutedBaselineV1{Saved: saved, Owned: planned, Dependencies: prep.Dependencies}
			retained := clone(baseline)
			if saved.LocalServices.Hash == target.LocalServices.Hash {
				t.Fatal("fixture lacks metadata transition")
			}
			if _, err = routedBootPreparationV2(prep, baseline, target, previous, c.store.readObject); err != nil {
				t.Fatal("exact derived inventory refused", err)
			}
			if !reflect.DeepEqual(baseline, retained) || a.applies != 0 || a.bootstraps != 0 {
				t.Fatal("preparation changed saved state or applied effects")
			}
			for name, mutate := range map[string]func(*RoutedPreparationV1, *RoutedBaselineV1, *RoutedActivationBundleV1, *v2Configuration){
				"missing_history": func(_ *RoutedPreparationV1, _ *RoutedBaselineV1, _ *RoutedActivationBundleV1, s *v2Configuration) {
					s.AuditTip = checkpointDigest([]byte("missing"))
				},
				"caller_inventory": func(_ *RoutedPreparationV1, _ *RoutedBaselineV1, target *RoutedActivationBundleV1, _ *v2Configuration) {
					target.LocalServices.Config.LocalServices.Interfaces[0].Addresses[0] = "198.18.0.99"
				},
				"saved_replaced": func(_ *RoutedPreparationV1, b *RoutedBaselineV1, target *RoutedActivationBundleV1, _ *v2Configuration) {
					b.Saved.LocalServices = target.LocalServices
				},
				"unexpected_before_table": func(p *RoutedPreparationV1, _ *RoutedBaselineV1, _ *RoutedActivationBundleV1, _ *v2Configuration) {
					p.Before.LocalServices = clone(p.Target.LocalServices)
				},
			} {
				t.Run(name, func(t *testing.T) {
					p, b, target, state := clone(prep), clone(baseline), clone(target), clone(previous)
					mutate(&p, &b, &target, &state)
					if _, err := routedBootPreparationV2(p, b, target, state, c.store.readObject); err == nil {
						t.Fatal("invalid boot admitted")
					}
				})
			}
		})
	}
}
