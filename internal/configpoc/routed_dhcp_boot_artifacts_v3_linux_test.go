//go:build linux

package configpoc

import (
	"encoding/json"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func dhcpBootArtifactsFixtureV3(t *testing.T) (OwnedV1, DependenciesV1) {
	t.Helper()
	lease := dhcpSnapshotFixtureV3(t)
	s := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: lease.Desired.Hash, Links: lease.Links, Routes: []networkexecutor.SnapshotRoute{}}
	for i := range s.Links {
		s.Links[i].Addresses = []networkexecutor.SnapshotAddress{}
	}
	_, s.Hash, _ = v2Canonical(s)
	owned := OwnedV1{Version: 3, Network: s, NetworkState: Baseline, LegacyFirewall: TableStateV1{Presence: Absent}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}}
	deps := DependenciesV1{Version: 3, NetworkMode: "dhcp-lan", Network: lease.Desired, Prepared: s, LocalInterfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}}}
	return owned, deps
}

func TestRoutedDHCPBootArtifactsV3RequireExplicitProfileAndEmptyWAN(t *testing.T) {
	o, d := dhcpBootArtifactsFixtureV3(t)
	if _, err := CanonicalOwned(o); err != nil {
		t.Fatal(err)
	}
	if _, err := CanonicalDependencies(d); err != nil {
		t.Fatal(err)
	}
	if !RoutedOwnershipMatchesDependencies(o, d) {
		t.Fatal("profile not bound")
	}
	static := o
	static.Version = 1
	if RoutedOwnershipMatchesDependencies(static, d) {
		t.Fatal("static ownership confused with DHCP bootstrap")
	}
	for _, mode := range []string{"static-version", "empty-mode", "wan-local-address", "wrong-lan", "occupied-wan", "replaced-link"} {
		t.Run(mode, func(t *testing.T) {
			_, deps := dhcpBootArtifactsFixtureV3(t)
			switch mode {
			case "static-version":
				deps.Version, deps.NetworkMode = 1, ""
			case "empty-mode":
				deps.NetworkMode = ""
			case "wan-local-address":
				deps.LocalInterfaces = append(deps.LocalInterfaces, localpolicy.Interface{Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}})
			case "wrong-lan":
				deps.LocalInterfaces[0].Addresses[0] = "198.18.0.9"
			case "occupied-wan":
				deps.Prepared.Links[1].Addresses = []networkexecutor.SnapshotAddress{{Family: "inet", Local: "198.19.0.1", Bits: 24}}
				deps.Prepared.Hash = ""
				_, deps.Prepared.Hash, _ = v2Canonical(deps.Prepared)
			case "replaced-link":
				deps.Prepared.Links[1].MAC = "02:00:00:00:02:02"
				deps.Prepared.Hash = ""
				_, deps.Prepared.Hash, _ = v2Canonical(deps.Prepared)
			}
			if _, err := CanonicalDependencies(deps); err == nil {
				t.Fatal("invalid DHCP dependency accepted")
			}
		})
	}
	canonical, _ := CanonicalDependencies(d)
	d.LocalInterfaces[0].Addresses[0] = "198.18.0.9"
	if canonical.LocalInterfaces[0].Addresses[0] != "198.18.0.1" {
		t.Fatal("mutable input retained")
	}
	raw, _ := json.Marshal(canonical)
	var decoded DependenciesV1
	if json.Unmarshal(raw, &decoded) != nil || !RoutedOwnershipMatchesDependencies(o, decoded) {
		t.Fatal("canonical roundtrip")
	}
}
