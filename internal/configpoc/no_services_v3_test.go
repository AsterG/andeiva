package configpoc

import (
	"reflect"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkplan"
)

func noServicesFirewallFixtureV3(t testing.TB, dhcp bool) Revision {
	t.Helper()
	doc, objects := compositeRoutedFixture(t, true)
	fw := objects[doc.Domains.Firewall.Revision]
	if dhcp {
		for i := range fw.Config.Routed.Network.Config.Interfaces {
			iface := &fw.Config.Routed.Network.Config.Interfaces[i]
			if iface.Role == networkplan.WAN {
				iface.IPv4 = networkplan.IPv4{Mode: "dhcp"}
			}
		}
	}
	return noServicesCanonicalFirewallV3(t, fw.Config)
}

func noServicesCanonicalFirewallV3(t testing.TB, cfg Config) Revision {
	t.Helper()
	n, err := networkplan.Canonical(cfg.Routed.Network.Config)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Routed.Network = n
	fw, err := CanonicalRouted(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fw
}

func noServicesEmptyFixtureV3(t testing.TB) (Revision, Revision) {
	t.Helper()
	doc, objects := compositeRoutedFixture(t, false)
	return objects[doc.Domains.Firewall.Revision], objects[doc.Domains.LocalServices.Revision]
}

func TestNoServicesV3DerivesOnlyCanonicalNetworkInventory(t *testing.T) {
	previous, local := noServicesEmptyFixtureV3(t)
	for _, dhcp := range []bool{false, true} {
		fw := noServicesFirewallFixtureV3(t, dhcp)
		original := clone(fw)
		derived, err := noServicesCandidateV3(previous, local, fw)
		if err != nil || !RoutedNoServicesTransitionV3(previous, local, fw, derived) {
			t.Fatal("initial empty-service derivation", err)
		}
		want := []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}}
		if !dhcp {
			want = append(want, localpolicy.Interface{Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}})
		}
		if !reflect.DeepEqual(derived.Config.LocalServices.Interfaces, want) || len(derived.Config.LocalServices.Services) != 0 || derived.Config.DefaultAction != "deny" || len(derived.Config.Rules) != 0 || !reflect.DeepEqual(fw, original) {
			t.Fatal("inventory modified policy or fabricated WAN address", derived)
		}
		reordered := clone(fw.Config)
		reordered.Routed.Network.Config.Interfaces[0], reordered.Routed.Network.Config.Interfaces[1] = reordered.Routed.Network.Config.Interfaces[1], reordered.Routed.Network.Config.Interfaces[0]
		reordered.Routed.Network.Config.Zones[0], reordered.Routed.Network.Config.Zones[1] = reordered.Routed.Network.Config.Zones[1], reordered.Routed.Network.Config.Zones[0]
		again, err := noServicesCandidateV3(previous, local, noServicesCanonicalFirewallV3(t, reordered))
		if err != nil || again.Hash != derived.Hash {
			t.Fatal("order changed derived identity", err)
		}
		if !RoutedNoServicesTransitionV3(fw, derived, previous, local) {
			t.Fatal("exact empty historical rollback rejected")
		}
		derived.Config.LocalServices.Interfaces[0].Addresses[0] = "198.18.0.99"
		if len(local.Config.LocalServices.Interfaces) != 0 || !reflect.DeepEqual(fw, original) {
			t.Fatal("derived inventory aliases selected source")
		}
	}
}

func TestNoServicesV3RejectsServicesForeignInventoryAndTamperedRevisions(t *testing.T) {
	previous, empty := noServicesEmptyFixtureV3(t)
	targetFW := noServicesFirewallFixtureV3(t, true)
	target, err := noServicesInventoryV3(targetFW)
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true} {
		cfg := localSample(t, 9443)
		for i := range cfg.LocalServices.Services {
			cfg.LocalServices.Services[i].Enabled = enabled
		}
		services, err := Canonical(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if RoutedNoServicesTransitionV3(previous, services, targetFW, target) || RoutedNoServicesTransitionV3(previous, empty, targetFW, services) {
			t.Fatal("service definition gained inventory exception", enabled)
		}
		unchanged, err := noServicesCandidateV3(previous, services, targetFW)
		if err != nil || !reflect.DeepEqual(unchanged, services) {
			t.Fatal("service policy was silently rewritten", err)
		}
	}
	foreignConfig := clone(target.Config)
	foreignConfig.LocalServices.Interfaces[0].Addresses[0] = "198.18.0.99"
	foreign, err := Canonical(foreignConfig)
	if err != nil {
		t.Fatal(err)
	}
	if RoutedNoServicesTransitionV3(targetFW, foreign, targetFW, target) || RoutedNoServicesTransitionV3(previous, empty, targetFW, foreign) {
		t.Fatal("foreign inventory accepted")
	}
	if _, err = noServicesCandidateV3(targetFW, foreign, targetFW); err == nil {
		t.Fatal("foreign source inventory silently overwritten")
	}
	for _, which := range []string{"previous-firewall", "previous-local", "target-firewall", "target-local"} {
		fw1, ls1, fw2, ls2 := clone(previous), clone(empty), clone(targetFW), clone(target)
		switch which {
		case "previous-firewall":
			fw1.Hash = targetFW.Hash
		case "previous-local":
			ls1.Hash = target.Hash
		case "target-firewall":
			fw2.Hash = previous.Hash
		case "target-local":
			ls2.Hash = empty.Hash
		}
		if RoutedNoServicesTransitionV3(fw1, ls1, fw2, ls2) {
			t.Fatal("unbound revision accepted", which)
		}
	}
}
