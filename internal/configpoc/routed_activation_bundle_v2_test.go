package configpoc

import (
	"errors"
	"strings"
	"testing"
)

func TestRoutedActivationBundleCanonicalAndDetached(t *testing.T) {
	for _, routed := range []bool{false, true} {
		doc, objects := compositeRoutedFixture(t, routed)
		firewall, local := objects[doc.Domains.Firewall.Revision], objects[doc.Domains.LocalServices.Revision]
		bundle, err := NewRoutedActivationBundleV1(firewall, local)
		if err != nil {
			t.Fatal(err)
		}
		again, err := CanonicalRoutedActivationBundleV1(bundle)
		if err != nil || again.Composite.Hash != bundle.Composite.Hash {
			t.Fatal("unstable activation unit", err)
		}
		local.Config.LocalServices.SchemaVersion = 999
		if bundle.LocalServices.Config.LocalServices.SchemaVersion == 999 {
			t.Fatal("bundle aliases input component")
		}
		if routed {
			firewall.Config.Routed.Network.Config.Interfaces[0].IPv4.Address = "192.0.2.1/24"
			if _, err := CanonicalRoutedActivationBundleV1(bundle); err != nil {
				t.Fatal("caller mutation changed bundle", err)
			}
		}
	}
}

func TestRoutedActivationBundleRejectsForgedReferences(t *testing.T) {
	for name, edit := range map[string]func(*RoutedActivationBundleV1){
		"version":   func(b *RoutedActivationBundleV1) { b.Version = 0 },
		"composite": func(b *RoutedActivationBundleV1) { b.Composite.Hash = strings.Repeat("0", 64) },
		"component": func(b *RoutedActivationBundleV1) { b.LocalServices.Hash = strings.Repeat("0", 64) },
		"network": func(b *RoutedActivationBundleV1) {
			b.Composite.Config.Domains.Network.Revision = strings.Repeat("0", 64)
		},
		"payload": func(b *RoutedActivationBundleV1) { b.Firewall.Config.DefaultAction = "allow" },
	} {
		t.Run(name, func(t *testing.T) {
			doc, objects := compositeRoutedFixture(t, true)
			bundle, err := NewRoutedActivationBundleV1(objects[doc.Domains.Firewall.Revision], objects[doc.Domains.LocalServices.Revision])
			if err != nil {
				t.Fatal(err)
			}
			edit(&bundle)
			if _, err := CanonicalRoutedActivationBundleV1(bundle); !errors.Is(err, ErrInvalid) {
				t.Fatal("forged activation unit accepted", err)
			}
		})
	}
}

func TestRoutedTransitionRejectsArbitraryPaths(t *testing.T) {
	hash := strings.Repeat("a", 64)
	transition := RoutedTransitionV1{Version: 1, Operation: "v2.op.1.random", Previous: hash, Target: hash, BeforeOwned: hash, TargetOwned: hash, Dependencies: hash}
	if !transition.ValidShape() {
		t.Fatal("bounded reference rejected")
	}
	for _, path := range []string{"", "../selected.json", "/etc/config", strings.Repeat("a", 65)} {
		bad := transition
		bad.BeforeOwned = path
		if bad.ValidShape() {
			t.Fatal("arbitrary path accepted")
		}
	}
}
