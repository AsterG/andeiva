package configpoc_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localengine"
	"github.com/AsterG/andeiva/internal/routedmodel"
	"github.com/AsterG/andeiva/internal/routednft"
)

func TestRoutedEnvelopeCanonicalAndCompilerIdentity(t *testing.T) {
	p := routednft.LabPolicy()
	before, _ := json.Marshal(p)
	r, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &p})
	if err != nil || r.Config.Routed == nil {
		t.Fatal(err)
	}
	a, err := routednft.Compile(*r.Config.Routed)
	if err != nil {
		t.Fatal(err)
	}
	m, err := routedmodel.Canonical(p)
	if err != nil || a.Revision.Hash != m.Hash {
		t.Fatal("compiler/model identity changed", err)
	}
	// Captured from the already qualified pre-extraction compiler on main.
	if a.Revision.Hash != "86f008cc6a8d501983ca289ca92fc1057cf611de7d4c0cf4a92ced9bba0ab3ed" ||
		fmt.Sprintf("%x", sha256.Sum256(a.Create)) != "76f09bb692894965a0a8f1498063a12f960f2ba65125ead2631b4c9d69cebfdb" ||
		fmt.Sprintf("%x", sha256.Sum256(a.Batch)) != "4ecab61519ab2b03f9834e28865403333df3ebccdebd7b45930bb052a02b626f" {
		t.Fatal("existing compiler bytes or identities changed")
	}
	again, err := configpoc.CanonicalRouted(r.Config)
	if err != nil || again.Hash != r.Hash {
		t.Fatal("envelope not idempotent", err)
	}
	after, _ := json.Marshal(p)
	if string(before) != string(after) {
		t.Fatal("caller mutated")
	}
	r.Config.Routed.Rules[0].Source = "192.0.2.0/24"
	if p.Rules[0].Source == "192.0.2.0/24" {
		t.Fatal("revision aliases input")
	}
}

func TestRoutedEnvelopeRejectedByExistingConsumers(t *testing.T) {
	p := routednft.LabPolicy()
	r, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &p})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = configpoc.Canonical(r.Config); err == nil {
		t.Fatal("legacy canonical accepted routed schema")
	}
	if _, err = firewallnft.Compile(r.Config); err == nil {
		t.Fatal("legacy firewall compiler accepted routed schema")
	}
	if err = new(localengine.Engine).Validate(r.Config); err == nil {
		t.Fatal("local engine interpreted routed schema as disabled services")
	}
	if err = configpoc.NewSimEngine("legacy").Validate(r.Config); err == nil {
		t.Fatal("legacy coordinator engine accepted routed schema")
	}
}

func TestRoutedEnvelopeCannotLeakIntoLegacySchemas(t *testing.T) {
	p := routednft.LabPolicy()
	for _, schema := range []int{1, 2, 3, 4, 5} {
		if _, err := configpoc.Canonical(configpoc.Config{SchemaVersion: schema, DefaultAction: "deny", Routed: &p}); err == nil {
			t.Fatalf("legacy schema %d accepted new payload", schema)
		}
	}
	r, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny"})
	if err != nil || r.Hash != "2918f3f865544487ca86aaeca877ddd9f3ea8ddf7aed6122d6bd1a471ae57f88" {
		t.Fatalf("legacy hash changed: %s %v", r.Hash, err)
	}
	b, _ := json.Marshal(r.Config)
	if string(b) != `{"schema_version":4,"default_action":"deny","rules":[]}` {
		t.Fatalf("legacy bytes changed: %s", b)
	}
}

func TestRoutedEnvelopeRejectsAmbiguousOrUnsafePayloads(t *testing.T) {
	p := routednft.LabPolicy()
	cases := []configpoc.Config{
		{SchemaVersion: 6, DefaultAction: "deny"},
		{SchemaVersion: 6, DefaultAction: "allow", Routed: &p},
		{SchemaVersion: 6, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "mixed", Action: "allow"}}, Routed: &p},
	}
	for i, c := range cases {
		if _, err := configpoc.CanonicalRouted(c); err == nil {
			t.Fatalf("accepted ambiguity %d", i)
		}
	}
	for _, edit := range []func(*routedmodel.Policy){
		func(p *routedmodel.Policy) { p.LabOnly = false },
		func(p *routedmodel.Policy) { p.RequireInspection = true },
		func(p *routedmodel.Policy) { p.Rules[0].Enabled = nil },
		func(p *routedmodel.Policy) { p.Rules[0].Protocol = "all" },
		func(p *routedmodel.Policy) { p.NAT[0].Source = "0.0.0.0/0" },
	} {
		p := routednft.LabPolicy()
		edit(&p)
		if _, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &p}); err == nil {
			t.Fatal("unsafe routed payload accepted")
		}
	}
}
