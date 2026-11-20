//go:build linux

package configpoc

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

type retainedDHCPRuleAuthority struct {
	dhcpBootAuthorityTestV3
	original OwnedV1
}

func (a retainedDHCPRuleAuthority) Prepare(ctx context.Context, target RoutedActivationBundleV1, baseline *RoutedBaselineV1) (RoutedPreparationV1, error) {
	prepared, err := a.dhcpBootAuthorityTestV3.Prepare(ctx, target, baseline)
	prepared.Before = clone(a.original)
	return prepared, err
}

func TestRoutedCoordinatorStagesRulesWithRetainedDHCPV4(t *testing.T) {
	t.Run("confirm", func(t *testing.T) { testRoutedCoordinatorRetainedDHCP(t, true) })
	t.Run("timeout", func(t *testing.T) { testRoutedCoordinatorRetainedDHCP(t, false) })
}

func testRoutedCoordinatorRetainedDHCP(t *testing.T, confirm bool) {
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
	store := coordinator.store
	store.retainDHCPV4 = true
	work, err := wan.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dhcp.state = networkexecutor.LeaseSelectedTargetV3
	if err = wan.Applied(ctx, work); err != nil {
		t.Fatal(err)
	}
	bootstrap, err := reader.ResolveDHCPLeaseAuthorityV4(ctx, work)
	if err != nil || bootstrap.BaselineAdmissionMarksV4() == nil {
		t.Fatal("the first WAN Open has no selected mark assignment", err)
	}
	checkFullInspection := func(phase string) {
		t.Helper()
		reader.options.Policy = SelectionFullHistoryV2
		ref, err := selectedReferenceV2(store)
		if err != nil {
			t.Fatal(phase, err)
		}
		result, err := reader.InspectQuiescentV1(ctx, ref)
		if err != nil || result.State != IntegrityCompleteV1 || result.Selection != ref {
			t.Fatal(phase, result.State, err)
		}
	}
	checkFullInspection("initial admission marks")
	reads := 0
	verify := func() error { reads++; return nil }
	if err = wan.WithStableWorkV4(ctx, work, verify); err != nil || reads != 1 {
		t.Fatal("helper could not verify the selected WAN work", err)
	}
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
	currentBundle, err := bundleFromConfigurationV2(*store.state.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	adapter := dhcpBootAuthorityTestV3{authority}
	physical, err := adapter.Prepare(ctx, currentBundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.options.Routed = retainedDHCPRuleAuthority{adapter, physical.Target}
	seconds := uint64(30)
	var milestones []string
	coordinator.options.Hook = func(point string) error { milestones = append(milestones, point); return nil }
	admitted, committed, err := routedRequestV2(t, coordinator, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil || committed.Current.Pending == nil || committed.Current.Running.Hash == running {
		t.Fatalf("active-WAN Commit did not select joint results: admitted=%q state=%q blocked=%t intent=%+v checkpoints=%v err=%v",
			admitted.ID, committed.Operation.State, store.blocked, store.state.Configuration.Intent, milestones, err)
	}
	pending := committed.Current.Pending
	oldIntegrity := coordinator.options.Integrity
	coordinator.options.Integrity = &testIntegrityV1{inspect: func(context.Context, SelectionReferenceV2) (IntegrityResultV1, error) {
		t.Fatal("inspection dispatched while retained rules await Confirm")
		return IntegrityResultV1{}, ErrRecovery
	}}
	err = (&ServiceV2{coordinator: coordinator}).InspectRuntimeV1(ctx)
	coordinator.options.Integrity = oldIntegrity
	if !errors.Is(err, ErrRetainedDHCPInspectionDeferredV4) || !errors.Is(err, ErrRecovery) {
		t.Fatal("the pending transition should defer the inspection without dispatch", err)
	}
	if confirm {
		if _, _, err = routedRequestV2(t, coordinator, principal, v2Request{Kind: OpConfirm, Origin: pending.OriginCommit, Target: pending.Target}); err != nil {
			t.Fatal("active-WAN Confirm", err)
		}
		running = committed.Current.Running.Hash
	} else {
		after := pending.Deadline.Add(time.Second)
		coordinator.options.Now = func() time.Time { return after }
		store.mu.Lock()
		err = coordinator.tickLocked(ctx, after)
		store.mu.Unlock()
		if err != nil {
			t.Fatal("active-WAN timeout", err)
		}
	}
	if store.state.Configuration.Pending != nil || store.state.Configuration.Running.Hash != running ||
		!reflect.DeepEqual(store.state.RoutedDHCP, original) || dhcp.withdrawCalls != 0 {
		t.Fatal("closing the operation changed the retained WAN or the expected running policy")
	}
	if err = wan.WithStableWorkV4(ctx, running, verify); err == nil || reads != 1 {
		t.Fatal("different work reached the helper", err)
	}
	selected, err = reader.ResolveDHCPLeaseAuthorityV4(ctx, work)
	if err != nil || selected.Running() != running || selected.Snapshot().Hash != dhcp.grant.Snapshot.Hash {
		t.Fatal("independent reader rejected the terminal result", err)
	}
	checkFullInspection("terminal rule transition")
}
