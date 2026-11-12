package configpoc

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

func compositeRoutedFixture(t testing.TB, routed bool) (v2CompositeConfig, map[string]Revision) {
	t.Helper()
	config := Config{SchemaVersion: 4, DefaultAction: "deny"}
	firewall, err := Canonical(config)
	if routed {
		network, networkErr := networkplan.Canonical(networkplan.Config{SchemaVersion: 1, IPv6Forwarding: "deny", Interfaces: []networkplan.Interface{
			{ID: "lan", Role: networkplan.LAN, Zone: "inside", Binding: networkplan.Binding{Name: "lan0", HardwareAddress: "02:00:00:00:01:01"}, IPv4: networkplan.IPv4{Mode: "static", Address: "198.18.0.1/24"}},
			{ID: "wan", Role: networkplan.WAN, Zone: "outside", Binding: networkplan.Binding{Name: "wan0", HardwareAddress: "02:00:00:00:02:01"}, IPv4: networkplan.IPv4{Mode: "static", Address: "198.19.0.1/24", Gateway: "198.19.0.2"}},
		}, Zones: []networkplan.Zone{{ID: "inside", Kind: networkplan.LAN}, {ID: "outside", Kind: networkplan.WAN}}, DefaultRoute: networkplan.DefaultRoute{InterfaceID: "wan", Metric: 10}, DNS: networkplan.DNS{Mode: "none", Servers: []string{}}})
		if networkErr != nil {
			t.Fatal(networkErr)
		}
		policy := routedmodel.Policy{SchemaVersion: 1, LabOnly: true, Network: network, Rules: []routedmodel.Rule{}, NAT: []routedmodel.Masquerade{}}
		firewall, err = CanonicalRouted(Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	}
	if err != nil {
		t.Fatal(err)
	}
	local, err := Canonical(Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	doc := v2CompositeConfig{SchemaVersion: 7, Domains: v2CompositeDomains{
		Firewall:      v2ComponentReference{Schema: firewall.Config.SchemaVersion, Revision: firewall.Hash},
		LocalServices: v2ComponentReference{Schema: 3, Revision: local.Hash},
	}}
	if routed {
		doc.Domains.Network = &v2ComponentReference{Schema: 1, Revision: firewall.Config.Routed.Network.Hash}
	}
	return doc, map[string]Revision{firewall.Hash: firewall, local.Hash: local}
}

func compositeRoutedReader(objects map[string]Revision, count *int) func(string, any) error {
	return func(hash string, value any) error {
		(*count)++
		revision, ok := objects[hash]
		if !ok {
			return ErrStorage
		}
		data, err := json.Marshal(revision)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, value)
	}
}

func TestRoutedCompositeContextAndLegacyIsolation(t *testing.T) {
	for _, routed := range []bool{false, true} {
		doc, objects := compositeRoutedFixture(t, routed)
		count := 0
		resolved, err := resolveRoutedCompositeV1(doc, compositeRoutedReader(objects, &count))
		if err != nil || count != 2 || !validHash(resolved.Hash) {
			t.Fatalf("resolution: reads=%d err=%v", count, err)
		}
		again, err := resolveRoutedCompositeV1(resolved.Config, compositeRoutedReader(objects, &count))
		if err != nil || again.Hash != resolved.Hash {
			t.Fatal("unstable composite", err)
		}
		if _, err := CanonicalComposite(doc); !errors.Is(err, ErrInvalid) {
			t.Fatal("legacy resolver accepted schema7")
		}
		if routed {
			doc.Domains.Network.Revision = strings.Repeat("0", 64)
			if resolved.Config.Domains.Network.Revision == doc.Domains.Network.Revision {
				t.Fatal("hashed result aliases caller")
			}
		}
	}
}

func TestRoutedCompositeRejectsUnboundReferences(t *testing.T) {
	for name, edit := range map[string]func(*v2CompositeConfig){
		"schema":          func(c *v2CompositeConfig) { c.SchemaVersion = 5 },
		"missing-network": func(c *v2CompositeConfig) { c.Domains.Network = nil },
		"network-schema":  func(c *v2CompositeConfig) { c.Domains.Network.Schema = 3 },
		"foreign-network": func(c *v2CompositeConfig) { c.Domains.Network.Revision = strings.Repeat("0", 64) },
		"bad-hash":        func(c *v2CompositeConfig) { c.Domains.Firewall.Revision = "../object" },
		"local-schema":    func(c *v2CompositeConfig) { c.Domains.LocalServices.Schema = 6 },
	} {
		t.Run(name, func(t *testing.T) {
			doc, objects := compositeRoutedFixture(t, true)
			edit(&doc)
			count := 0
			if _, err := resolveRoutedCompositeV1(doc, compositeRoutedReader(objects, &count)); !errors.Is(err, ErrInvalid) || count > 2 {
				t.Fatalf("accepted invalid document: reads=%d err=%v", count, err)
			}
		})
	}
	doc, objects := compositeRoutedFixture(t, false)
	doc.Domains.Network = &v2ComponentReference{Schema: 1, Revision: strings.Repeat("0", 64)}
	count := 0
	if _, err := resolveRoutedCompositeV1(doc, compositeRoutedReader(objects, &count)); !errors.Is(err, ErrInvalid) || count != 0 {
		t.Fatal("legacy firewall accepted network projection", err)
	}
}

func TestRoutedCompositeRejectsTamperedPayloadsAndPreservesStorageFailure(t *testing.T) {
	for _, field := range []string{"hash", "schema", "payload", "canonical"} {
		t.Run(field, func(t *testing.T) {
			doc, objects := compositeRoutedFixture(t, true)
			key := doc.Domains.Firewall.Revision
			revision := objects[key]
			switch field {
			case "hash":
				revision.Hash = strings.Repeat("0", 64)
			case "schema":
				revision.Config.SchemaVersion = 4
			case "payload":
				revision.Config.DefaultAction = "allow"
			case "canonical":
				revision.Config.Rules = nil
			}
			objects[key] = revision
			count := 0
			if _, err := resolveRoutedCompositeV1(doc, compositeRoutedReader(objects, &count)); !errors.Is(err, ErrInvalid) {
				t.Fatal("accepted altered payload", err)
			}
		})
	}
	doc, objects := compositeRoutedFixture(t, true)
	delete(objects, doc.Domains.LocalServices.Revision)
	count := 0
	if _, err := resolveRoutedCompositeV1(doc, compositeRoutedReader(objects, &count)); !errors.Is(err, ErrStorage) || count != 2 {
		t.Fatal("storage failure lost", err)
	}
	if _, err := resolveRoutedCompositeV1(doc, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil reader accepted")
	}
}

func BenchmarkRoutedCompositeMemoryReader(b *testing.B) {
	doc, objects := compositeRoutedFixture(b, true)
	count := 0
	read := compositeRoutedReader(objects, &count)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := resolveRoutedCompositeV1(doc, read); err != nil {
			b.Fatal(err)
		}
	}
}
