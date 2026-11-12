//go:build linux

package configpoc

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func TestRoutedNoNetworkStageRequiresFeatureAndCapturesCompleteGroup(t *testing.T) {
	c, engines, p := routedCoordinatorFixtureV2(t)
	config := clone(c.store.state.Configuration.Firewall.Running.Config)
	if config.SchemaVersion != 4 {
		t.Fatal("fixture must start from imported policy4")
	}
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); !errors.Is(err, errV2Invalid) {
		t.Fatal("unqualified policy4 stage accepted", err)
	}
	c.store.mu.Lock()
	state := clone(c.store.state)
	addFeatureV2(&state, v2RoutedBootFeature)
	addFeatureV2(&state, v2RoutedNoNetworkFeature)
	err := c.store.publish(state)
	c.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, engine := range engines {
		engine.reset()
	}
	_, result, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	if result.Current.CandidateGroup == nil || result.Current.Firewall.Candidate.Revision.Config.SchemaVersion != 4 || result.Current.Candidate.Config.Domains.Network != nil || result.Current.LocalServices.Candidate.Revision.Hash != result.Current.LocalServices.Running.Hash {
		t.Fatal("no-network candidate is not a complete group")
	}
	if _, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpValidate}); err != nil {
		t.Fatal("metadata validation", err)
	}
	seconds := uint64(30)
	if _, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); !errors.Is(err, ErrRecovery) {
		t.Fatal("store-only fixture activated an unassembled authority", err)
	}
	if c.store.state.Configuration.Intent != nil || c.store.state.Configuration.Pending != nil {
		t.Fatal("unsupported effect published an intent")
	}
}

func TestRoutedNoNetworkBootRequiresSavedWitnessAndExactObservedBaseline(t *testing.T) {
	c, _, _ := routedCoordinatorFixtureV2(t)
	previous := clone(*c.store.state.Configuration)
	localConfig := clone(previous.LocalServices.Running.Config)
	for i := range localConfig.LocalServices.Services {
		localConfig.LocalServices.Services[i].Enabled = false
	}
	local, err := Canonical(localConfig)
	if err != nil {
		t.Fatal(err)
	}
	previous.LocalServices.Running, previous.LocalServices.Startup, previous.LocalServices.LastGood = local, local, local
	if err = previous.refresh(); err != nil {
		t.Fatal(err)
	}
	var audit v2CoordinatorAudit
	if err = c.store.readObject(previous.AuditTip, &audit); err != nil {
		t.Fatal(err)
	}
	audit.Startup, audit.Running = previous.Startup.Hash, previous.Running.Hash
	previous.AuditTip, err = c.store.object(audit)
	if err != nil {
		t.Fatal(err)
	}
	target, err := bundleFromConfigurationV2(previous)
	if err != nil {
		t.Fatal(err)
	}
	work, _, load := routedWorkFixtureV2(t)
	var old v2RoutedDependencies
	if err = load(work.Transition.Dependencies, &old); err != nil {
		t.Fatal(err)
	}
	observed := networkexecutor.ObservedSnapshot{Version: 1, Links: old.Value.Prepared.Links, Routes: old.Value.Prepared.Routes}
	raw, _ := json.Marshal(observed)
	observed.Hash = checkpointDigest(raw)
	before := OwnedV1{Version: 2, NetworkState: NoNetwork, Observed: &observed, LegacyFirewall: TableStateV1{Presence: Absent}, RoutedFirewall: TableStateV1{Presence: Absent}, LocalServices: TableStateV1{Presence: Absent}}
	after := clone(before)
	after.LegacyFirewall = TableStateV1{Presence: Present, Revision: &target.Firewall}
	deps := DependenciesV1{Version: 2, NetworkMode: "none", Observed: &observed}
	preparation := RoutedPreparationV1{Before: before, Target: after, Dependencies: deps}
	baseline := RoutedBaselineV1{Saved: target, Owned: after, Dependencies: deps}
	if _, err := CanonicalOwned(before); err != nil {
		t.Fatal("before", err)
	}
	if _, err := CanonicalOwned(after); err != nil {
		t.Fatal("after", err)
	}
	if _, err := CanonicalDependencies(deps); err != nil {
		t.Fatal("deps", err)
	}
	if err := routedHistoricalWitnessV2(previous, target.Composite.Hash, c.store.readObject); err != nil {
		t.Fatal("witness", err)
	}
	if !RoutedOwnershipMatchesDependencies(before, deps) || !RoutedOwnershipMatchesDependencies(after, deps) {
		t.Fatal("ownership")
	}
	if _, err = routedBootPreparationV2(preparation, baseline, target, previous, c.store.readObject); err != nil {
		t.Fatal("exact saved boot rejected", err)
	}
	for name, mutate := range map[string]func(*RoutedPreparationV1, *RoutedBaselineV1, *v2Configuration){
		"missing_witness": func(_ *RoutedPreparationV1, _ *RoutedBaselineV1, s *v2Configuration) {
			s.AuditTip = checkpointDigest([]byte("missing"))
		},
		"effective_before_forged": func(p *RoutedPreparationV1, _ *RoutedBaselineV1, _ *v2Configuration) {
			p.Before.LegacyFirewall = clone(p.Target.LegacyFirewall)
		},
		"prospective_mismatch": func(_ *RoutedPreparationV1, b *RoutedBaselineV1, _ *v2Configuration) {
			b.Owned.LegacyFirewall = TableStateV1{Presence: Absent}
		},
		"observed_mismatch": func(p *RoutedPreparationV1, _ *RoutedBaselineV1, _ *v2Configuration) {
			p.Target.Observed.Links[0].MTU++
			p.Target.Observed.Hash = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, b, s := clone(preparation), clone(baseline), clone(previous)
			mutate(&p, &b, &s)
			if _, err := routedBootPreparationV2(p, b, target, s, c.store.readObject); err == nil {
				t.Fatal("invalid no-network boot accepted")
			}
		})
	}
}
