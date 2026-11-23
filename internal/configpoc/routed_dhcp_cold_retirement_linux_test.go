//go:build linux

package configpoc

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

func retainedDHCPColdFixtureV1(t *testing.T, intent bool) (*RoutedSelectionReaderV2, *v2Coordinator, *boundaryAuthorityFixtureV2, string) {
	t.Helper()
	r, c, old, wan, dhcp := selectedDHCPReaderFixtureV3(t, func(cfg *Config) {
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
	c.store.retainDHCPV4 = true
	work, err := wan.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dhcp.state = networkexecutor.LeaseSelectedTargetV3
	if err = wan.Applied(ctx, work); err != nil {
		t.Fatal(err)
	}
	principal := v2TrustedPrincipal{Subject: c.store.state.Subjects[0].ID, Role: RoleAdmin}
	bundle, err := bundleFromConfigurationV2(*c.store.state.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	adapter := dhcpBootAuthorityTestV3{old}
	physical, err := adapter.Prepare(ctx, bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.options.Routed = retainedDHCPRuleAuthority{adapter, physical.Target}
	candidate := clone(c.store.state.Configuration.Firewall.Running.Config)
	candidate.Routed.Rules[0].ID = "updated-rule"
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &candidate}); err != nil {
		t.Fatal(err)
	}
	if intent {
		c.options.Hook = func(point string) error {
			if point == "after_intent" {
				return ErrInterrupted
			}
			return nil
		}
	}
	sec := uint64(60)
	_, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &sec})
	c.options.Hook = nil
	if intent && !errors.Is(err, ErrInterrupted) || !intent && err != nil ||
		!retainedDHCPInterruptedV1(c.store.state) || (c.store.state.Configuration.Intent != nil) != intent {
		t.Fatal("retained DHCP commit did not select the required phase", err)
	}
	return r, c, old, work
}

func TestRetainedDHCPColdRecoveryV1(t *testing.T) {
	for _, intent := range []bool{false, true} {
		name := "pending"
		if intent {
			name = "intent"
		}
		t.Run(name, func(t *testing.T) {
			oldReader, c, old, work := retainedDHCPColdFixtureV1(t, intent)
			startup := c.store.state.Configuration.Startup.Hash
			owner := reserveWorkV2(c.store.state.RoutedDHCP.Bundle)
			fresh, proof := rebootAuthorityFixtureV4(t, c, old)
			bootAttestedFixtureV4(proof)
			options := oldReader.options
			options.Identity = fresh.identity
			r, err := NewRoutedSelectionReaderV2(oldReader.area, options)
			if err != nil {
				t.Fatal(err)
			}
			anchor, err := r.CaptureColdAnchorV1(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			bootstrap := false
			c.options.Hook = func(point string) error {
				if point != "after_boot_intent" {
					return nil
				}
				cfg := c.store.state.Configuration
				p, err := loadRoutedWorkV2(cfg.Intent.RoutedWork, c.store.state.Lineage, c.store.readObject)
				if err != nil {
					return err
				}
				if _, err = r.ResolveColdContinuationV1(context.Background(), anchor, p.Reference(), SelectionBootstrapV2); err != nil {
					return err
				}
				bootstrap = true
				return nil
			}
			opened, err := reopenRebootHookFixtureV4(t, c, fresh, proof)
			if err != nil {
				t.Fatal("cold reboot:", err)
			}
			s := opened.store
			if s.state.RoutedDHCP != nil || s.state.RoutedDHCPConfiguration != nil ||
				s.state.Configuration.Intent != nil || s.state.Configuration.Pending != nil ||
				!hasFeatureV2(s.state, retainedDHCPColdRetirementFeatureV1) || fresh.recovers != 0 ||
				fresh.current != startup || fresh.bootstraps != 1 || !bootstrap {
				t.Fatal("cold reboot did not finish closed retirement and select Startup")
			}
			var terminal v3RoutedDHCPState
			if err = s.readObject(s.state.RoutedDHCPLast, &terminal); err != nil || terminal.ColdSource == "" || terminal.Work != work {
				t.Fatal("wrong DHCP terminal", err)
			}
			if count, _ := auditCountV4(t, opened, owner); count != 3 {
				t.Fatal("expected prepared, applied and retired once each", count)
			}
			plan, err := loadRoutedWorkV2(s.state.RoutedActive.Work, s.state.Lineage, s.readObject)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.ResolveColdContinuationV1(context.Background(), anchor, plan.Reference(), SelectionResumeV2); err != nil {
				t.Fatal("helper would reject its cold continuation:", err)
			}
		})
	}
}

func TestRetainedDHCPColdRejectsUnprovedScopeV1(t *testing.T) {
	for _, scenario := range []string{"same-boot", "absent", "failed", "wrong-old"} {
		t.Run(scenario, func(t *testing.T) {
			_, c, old, work := retainedDHCPColdFixtureV1(t, true)
			fresh, proof := rebootAuthorityFixtureV4(t, c, old)
			bootAttestedFixtureV4(proof)
			if scenario == "same-boot" {
				fresh.identity.BootID = old.identity.BootID
				proof.proof.New = fresh.identity
			}
			c.options.Routed, c.options.RoutedIdentity, c.options.RebootScope = fresh, fresh.identity, proof
			switch scenario {
			case "absent":
				c.options.RebootScope = nil
			case "failed":
				c.options.RebootScope = failingRetainedDHCPColdProofV1{}
			case "wrong-old":
				proof.proof.Old.RunID = "ffffffffffffffffffffffffffffffff"
			}
			boot := v2BootID(fresh.identity.BootID)
			c.options.BootID = &boot
			s := c.store
			before := s.selector
			want := clone(s.state)
			oldWork, err := loadRoutedDHCPWorkV3(work, s.state.Lineage, s.readObject)
			if err != nil {
				t.Fatal(err)
			}
			if err = c.retireRetainedDHCPOnColdBootV1(context.Background(), oldWork); !errors.Is(err, ErrRecovery) {
				t.Fatal("unproved scope retired", err)
			}
			if s.selector != before || !reflect.DeepEqual(s.state, want) || fresh.bootstraps != 0 || fresh.recovers != 0 {
				t.Fatal("failed proof changed the selection or caused effects")
			}
		})
	}
}

type failingRetainedDHCPColdProofV1 struct{}

func (failingRetainedDHCPColdProofV1) ProveRebootScope(context.Context, string) (RoutedRebootScopeEvidenceV4, error) {
	return RoutedRebootScopeEvidenceV4{}, ErrRecovery
}

func TestRetainedDHCPColdRepeatsPublicationsV1(t *testing.T) {
	points := []string{
		"before_cold_dhcp_retirement",
		"after_cold_dhcp_retirement",
		"after_recovery_intent",
		"before_boot_terminal_archive",
		"after_boot_terminal_archive",
		"before_cold_dhcp_audit",
		"after_cold_dhcp_audit",
		"reserve_archive_selected",
		"reserve_archive_anchored",
		"before_boot_intent",
		"after_boot_intent",
		"after_boot_readback",
		"before_boot_completion",
		"after_boot_completion",
	}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			_, c, old, work := retainedDHCPColdFixtureV1(t, point != "after_recovery_intent" && point != "after_cold_dhcp_retirement")
			startup := c.store.state.Configuration.Startup.Hash
			owner := reserveWorkV2(c.store.state.RoutedDHCP.Bundle)
			_, proof := rebootAuthorityFixtureV4(t, c, old)
			bootAttestedFixtureV4(proof)
			again := &bootAgainFixtureV4{f: bootTerminalFixtureV4{c: c, old: old, startup: startup}, template: proof.proof}
			first, firstScope, err := again.boot(t, point)
			if !errors.Is(err, ErrInterrupted) {
				t.Fatal("fault point was not reached", point, err)
			}
			if first != nil {
				first.close()
			}
			last, lastScope, err := again.boot(t, "")
			if err != nil {
				t.Fatal("next full boot:", err)
			}
			terminal := last.store.state
			if terminal.RoutedDHCP != nil || terminal.Configuration.Intent != nil || terminal.Configuration.Pending != nil ||
				lastScope.current != startup || lastScope.recovers != 0 || firstScope.recovers != 0 {
				t.Fatal("old lease, intent, or scope survived")
			}
			var dhcp v3RoutedDHCPState
			if err := last.store.readObject(terminal.RoutedDHCPLast, &dhcp); err != nil || dhcp.Work != work || dhcp.ColdAuditSource == "" {
				t.Fatal("missing DHCP terminal", err)
			}
			_, events := auditCountV4(t, last, owner)
			count := 0
			for _, event := range events {
				if event == "scope_retired" {
					count++
				}
			}
			if count != 1 {
				t.Fatal("the scope retirement event was lost or duplicated", events)
			}
		})
	}
}
