package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/routednft"
)

func TestCurrentAndInventoryV2UseVerifiedTransportWithoutDowngrade(t *testing.T) {
	operation, _ := wireFixtureV2(t)
	current := struct {
		SchemaVersion int `json:"schema_version"`
		Current       any `json:"current"`
	}{2, operation.Current}
	for _, mode := range []string{"current", "inventory", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.TLS == nil || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
					t.Error("authenticated HTTPS required")
				}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "current":
					if r.URL.Path != "/api/v2/config/current" {
						t.Error("unexpected path", r.URL.Path)
					}
					_ = json.NewEncoder(w).Encode(current)
				case "inventory":
					if r.URL.Path != "/api/v2/network/interfaces" {
						t.Error("unexpected path", r.URL.Path)
					}
					_, _ = w.Write([]byte(`{"schema_version":1,"interfaces":[{"name":"lan0","hardware_address":"02:00:00:00:00:01","mtu":1500,"admin_up":true,"running":false,"kind":"virtual","addresses":[{"ip":"192.0.2.1","prefix":"192.0.2.1/24"}]}]}`))
				case "unavailable":
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"code":"ANDEIVA_NOT_FOUND","request_id":"bounded-id"}`))
				}
			}))
			client.token = strings.Repeat("a", 64)
			if mode == "inventory" {
				out, err := client.NetworkInterfacesV2(context.Background())
				if err != nil || out.Interfaces[0].Addresses[0].IP != "192.0.2.1" || out.Interfaces[0].Running {
					t.Fatal("observation changed", err)
				}
			} else {
				out, err := client.CurrentConfigurationV2(context.Background())
				if mode == "current" && (err != nil || out.Global.Generation != operation.Current.Global.Generation) {
					t.Fatal("current unavailable", err)
				}
				if mode == "unavailable" && err == nil {
					t.Fatal("v2 refusal silently downgraded")
				}
			}
			if calls != 1 {
				t.Fatal("unexpected retry or downgrade", calls)
			}
		})
	}
}

func TestRoutedCurrentClientChecksComponentAndCompositeCorrelation(t *testing.T) {
	base, _ := wireFixtureV2(t)
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := configpoc.NewRoutedActivationBundleV1(base.Current.Snapshot.Running, local)
	if err != nil {
		t.Fatal(err)
	}
	current := base.Current
	current.Domain = "routed"
	current.Global.Generation = adminapi.DecimalV2(^uint64(0))
	current.Global.Running, current.Global.Startup = bundle.Composite.Hash, bundle.Composite.Hash
	current.DomainGenerations = &adminapi.DomainGenerationsV2{Firewall: 17, Network: 17, LocalServices: 19}
	current.Routed = &adminapi.RoutedCurrentV2{SchemaVersion: 7, LocalServices: adminapi.SnapshotV2{Generation: 19, Running: local, Startup: local, LastGood: local, Revoked: []string{}}, Running: bundle.Composite, Startup: bundle.Composite, LastGood: bundle.Composite}
	if !validCurrentV2(current) {
		t.Fatal("selected pre-routing components rejected")
	}
	for name, edit := range map[string]func(*adminapi.CurrentV2){
		"global-component-confusion": func(c *adminapi.CurrentV2) { c.Global.Running = c.Snapshot.Running.Hash },
		"foreign-component": func(c *adminapi.CurrentV2) {
			c.Routed.Startup.Config.Domains.Firewall.Revision = strings.Repeat("0", 64)
		},
		"network-generation":   func(c *adminapi.CurrentV2) { c.DomainGenerations.Network++ },
		"local-generation":     func(c *adminapi.CurrentV2) { c.DomainGenerations.LocalServices++ },
		"missing-routed":       func(c *adminapi.CurrentV2) { c.Routed = nil },
		"unexpected-downgrade": func(c *adminapi.CurrentV2) { c.Domain = "firewall" },
		"unbound-candidate":    func(c *adminapi.CurrentV2) { c.Routed.Candidate = &bundle.Composite },
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			var invalid adminapi.CurrentV2
			if json.Unmarshal(data, &invalid) != nil {
				t.Fatal("fixture encoding")
			}
			edit(&invalid)
			if validCurrentV2(invalid) {
				t.Fatal("inconsistent selected view accepted")
			}
		})
	}
}

func TestInventoryV2ClientRejectsMalformedOrPrivateData(t *testing.T) {
	for _, payload := range []string{
		`{"schema_version":1,"interfaces":null}`,
		`{"schema_version":1,"interfaces":[],"namespace":123}`,
		`{"schema_version":1,"interfaces":[{"name":"lan0","index":7,"hardware_address":"","mtu":1500,"admin_up":true,"running":true,"kind":"virtual","addresses":[]}]}`,
		`{"schema_version":1,"interfaces":[{"name":"lan0","hardware_address":"","mtu":1500,"admin_up":true,"running":true,"kind":"virtual","addresses":[{"ip":"192.0.2.1","prefix":"192.0.2.0/24"}]}]}`,
	} {
		client, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(payload))
		}))
		client.token = strings.Repeat("a", 64)
		if _, err := client.NetworkInterfacesV2(context.Background()); !errors.Is(err, ErrResponse) {
			t.Fatal("invalid inventory accepted", err)
		}
	}
}

func TestRoutedCurrentPreservesReadableHistoricalCandidate(t *testing.T) {
	base, _ := wireFixtureV2(t)
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	policy := routednft.LabPolicy()
	oldFirewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		t.Fatal(err)
	}
	old, err := configpoc.NewRoutedActivationBundleV1(oldFirewall, local)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := configpoc.NewRoutedActivationBundleV1(base.Current.Snapshot.Running, local)
	if err != nil {
		t.Fatal(err)
	}
	current := base.Current
	current.Domain = "routed"
	current.Global.Running, current.Global.Startup = boot.Composite.Hash, boot.Composite.Hash
	current.DomainGenerations = &adminapi.DomainGenerationsV2{Firewall: 17, Network: 17, LocalServices: 19}
	current.Snapshot.Candidate = &configpoc.Candidate{Owner: "subject", Base: oldFirewall.Hash, Revision: oldFirewall}
	current.Routed = &adminapi.RoutedCurrentV2{SchemaVersion: 7, Running: boot.Composite, Startup: boot.Composite, LastGood: boot.Composite, Candidate: &old.Composite, CandidateGroup: &configpoc.CandidateGroupV2{Operation: "stage-original", Owner: "subject", Base: old.Composite.Hash, Domains: []string{"firewall", "local_services"}}, LocalServices: adminapi.SnapshotV2{Generation: 19, Running: local, Startup: local, LastGood: local, Candidate: &configpoc.Candidate{Owner: "subject", Base: local.Hash, Revision: local}}}
	if !validCurrentV2(current) {
		t.Fatal("historical Candidate made valid Boot state unreadable")
	}
	if current.Snapshot.Candidate.Base != oldFirewall.Hash || current.Routed.CandidateGroup.Base != old.Composite.Hash {
		t.Fatal("reader rebased Candidate")
	}
	t.Run("policy4_candidate_has_no_network_plan", func(t *testing.T) {
		data, _ := json.Marshal(current)
		var policyOnly adminapi.CurrentV2
		if json.Unmarshal(data, &policyOnly) != nil {
			t.Fatal("fixture")
		}
		policyOnly.Snapshot.Candidate.Revision = base.Current.Snapshot.Running
		policyOnly.Snapshot.Candidate.Base = base.Current.Snapshot.Running.Hash
		policyOnly.Routed.Candidate = &boot.Composite
		policyOnly.Routed.CandidateGroup.Base = boot.Composite.Hash
		if !validCurrentV2(policyOnly) || policyOnly.Routed.Candidate.Config.Domains.Network != nil {
			t.Fatal("valid policy4 candidate rejected or acquired a network plan")
		}
		policyOnly.Snapshot.Candidate.Revision.Config.SchemaVersion = 3
		if validCurrentV2(policyOnly) {
			t.Fatal("wrong candidate domain accepted")
		}
	})
	for _, mutate := range []func(*adminapi.CurrentV2){
		func(c *adminapi.CurrentV2) { c.Snapshot.Candidate.Base = "../../invalid" },
		func(c *adminapi.CurrentV2) { c.Routed.CandidateGroup.Base = "invalid" },
		func(c *adminapi.CurrentV2) { c.Routed.CandidateGroup.Owner = "foreign" },
		func(c *adminapi.CurrentV2) { c.Routed.LocalServices.Candidate.Owner = "foreign" },
		func(c *adminapi.CurrentV2) {
			c.Routed.Candidate.Config.Domains.Firewall.Revision = strings.Repeat("0", 64)
		},
	} {
		data, err := json.Marshal(current)
		if err != nil {
			t.Fatal(err)
		}
		var invalid adminapi.CurrentV2
		if json.Unmarshal(data, &invalid) != nil {
			t.Fatal("fixture")
		}
		mutate(&invalid)
		if validCurrentV2(invalid) {
			t.Fatal("corrupt historical Candidate accepted")
		}
	}
}
