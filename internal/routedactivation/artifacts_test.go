package routedactivation

import (
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routednft"
)

func artifactFixture(t testing.TB) (OwnedV1, DependenciesV1, configpoc.RoutedActivationBundleV1) {
	t.Helper()
	policy := routednft.LabPolicy()
	snapshot := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: policy.Network.Hash,
		Links: []networkexecutor.SnapshotLink{
			{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}},
			{Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}},
		}, Routes: []networkexecutor.SnapshotRoute{}}
	data, _ := json.Marshal(snapshot)
	snapshot.Hash = artifactDigest(data)
	legacy, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	localConfig := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{
		{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}},
		{Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}},
	}, Services: []localpolicy.Service{}}
	service, err := localpolicy.DefaultManagement("management", "https", localConfig.Interfaces[0], "198.18.0.1", []string{"198.18.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	service.Endpoints[0].FirstPort, service.Endpoints[0].LastPort = 18443, 18443
	localConfig.Services = []localpolicy.Service{service}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localConfig})
	if err != nil {
		t.Fatal(err)
	}
	firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := configpoc.NewRoutedActivationBundleV1(firewall, local)
	if err != nil {
		t.Fatal(err)
	}
	before := OwnedV1{Version: 1, Network: snapshot, NetworkState: Baseline, LegacyFirewall: TableStateV1{Presence: Present, Revision: &legacy}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}}
	deps := DependenciesV1{Version: 1, Network: policy.Network, Prepared: snapshot, LocalInterfaces: localConfig.Interfaces}
	return before, deps, bundle
}

func TestCanonicalOwnedAndDependenciesDetachAndCrossBind(t *testing.T) {
	before, deps, _ := artifactFixture(t)
	canonical, err := CanonicalOwned(before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OwnedBytes(canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := DependenciesBytes(deps); err != nil {
		t.Fatal(err)
	}
	before.Network.Links[0].Flags[0] = "foreign"
	before.LegacyFirewall.Revision.Config.DefaultAction = "allow"
	if canonical.Network.Links[0].Flags[0] != "UP" || canonical.LegacyFirewall.Revision.Config.DefaultAction != "deny" {
		t.Fatal("aliases mutable input")
	}
	deps.LocalInterfaces[0].Addresses[0] = "198.18.0.9"
	if _, err := CanonicalDependencies(deps); err == nil {
		t.Fatal("foreign local inventory accepted")
	}
}

func TestOwnedPresenceAndSchemaAreExplicit(t *testing.T) {
	for _, mutate := range []func(*OwnedV1){
		func(s *OwnedV1) { s.LocalServices.Presence = "missing" },
		func(s *OwnedV1) { s.LegacyFirewall.Revision = nil },
		func(s *OwnedV1) { s.LegacyFirewall.Presence = Absent },
		func(s *OwnedV1) { s.RoutedFirewall = s.LegacyFirewall },
		func(s *OwnedV1) { s.NetworkState = "unknown" },
		func(s *OwnedV1) { s.Network.Links[0].Index++ },
	} {
		before, _, _ := artifactFixture(t)
		mutate(&before)
		if _, err := CanonicalOwned(before); err == nil {
			t.Fatal("invalid owned artifact admitted")
		}
	}
}
