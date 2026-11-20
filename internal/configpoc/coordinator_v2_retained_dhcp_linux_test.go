//go:build linux

package configpoc

import (
	"context"
	"reflect"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

func TestRoutedCoordinatorStagesRulesWithRetainedDHCPV4(t *testing.T) {
	reader, coordinator, authority, wan, dhcp := selectedDHCPReaderFixtureV3(t, func(cfg *Config) {
		lan, wan := cfg.Routed.Network.Config.Interfaces[0], cfg.Routed.Network.Config.Interfaces[1]
		enabled := true
		cfg.Routed.Rules = []routedmodel.Rule{{
			ID: "original-rule", Enabled: &enabled, Action: "allow", Protocol: "tcp",
			Path:   routedmodel.Path{FromZone: lan.Zone, ToZone: wan.Zone, FromInterface: lan.ID, ToInterface: wan.ID},
			Source: "198.18.0.0/24", Destination: "198.19.0.2/32",
			SourcePorts: routedmodel.Ports{From: 1024, To: 65535}, DestinationPorts: routedmodel.Ports{From: 18080, To: 18080},
		}}
	})
	ctx := context.Background()
	work, err := wan.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dhcp.state = networkexecutor.LeaseSelectedTargetV3
	if err = wan.Applied(ctx, work); err != nil {
		t.Fatal(err)
	}
	store := coordinator.store
	store.retainDHCPV4 = true
	principal := v2TrustedPrincipal{Subject: store.state.Subjects[0].ID, Role: RoleAdmin}
	original := clone(store.state.RoutedDHCP)
	running := store.state.Configuration.Running.Hash
	candidate := clone(store.state.Configuration.Firewall.Running.Config)
	candidate.Routed.Rules[0].ID = "updated-rule"
	stage, staged, err := routedRequestV2(t, coordinator, principal, v2Request{Kind: OpStage, Config: &candidate})
	if err != nil {
		t.Fatal("active-WAN rule staging", err)
	}
	if staged.Operation.State != "final" || staged.Current.CandidateGroup == nil || staged.Current.CandidateGroup.Operation != stage.ID || staged.Current.Running.Hash != running {
		t.Fatal("staging did not preserve running policy")
	}
	_, validated, err := routedRequestV2(t, coordinator, principal, v2Request{Kind: OpValidate})
	if err != nil || validated.Operation.State != "final" || validated.Current.Running.Hash != running {
		t.Fatal("active-WAN validation", err)
	}
	observed, current, err := authority.Observe(ctx)
	if err != nil || observed.Phase != "idle" || current != running || !reflect.DeepEqual(original, store.state.RoutedDHCP) || dhcp.withdrawCalls != 0 {
		t.Fatal("metadata changed runtime ownership", observed, current, err)
	}
	selected, err := reader.ResolveDHCPLeaseAuthorityV4(ctx, work)
	if err != nil || selected.Running() != running || selected.Snapshot().Hash != dhcp.grant.Snapshot.Hash {
		t.Fatal("independent reader rejected the unchanged WAN work", err)
	}
	if err = coordinator.validateReferencesLocked(); err != nil {
		t.Fatal("startup reference checks rejected the selected rule metadata", err)
	}
}
