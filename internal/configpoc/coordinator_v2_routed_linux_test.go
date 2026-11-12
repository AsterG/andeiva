//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

func routedCoordinatorFixtureV2(t *testing.T) (*v2Coordinator, []*countedCoordinatorV2Engine, v2TrustedPrincipal) {
	t.Helper()
	c, _, engines, principal, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	before := clone(*c.store.state.Configuration)
	if err := c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); err != nil {
		t.Fatal(err)
	}
	after := c.store.state.Configuration
	if !reflect.DeepEqual(before.Firewall, after.Firewall) || !reflect.DeepEqual(before.LocalServices, after.LocalServices) || after.Running.Config.SchemaVersion != 7 || !hasFeatureV2(c.store.state, v2RoutedFeature) {
		t.Fatal("opt-in changed component configuration")
	}
	return c, engines, principal
}

func routedRequestV2(t *testing.T, c *v2Coordinator, principal v2TrustedPrincipal, request v2Request) (v2Operation, v2CoordinatorResult, error) {
	t.Helper()
	ns, err := c.store.namespace(principal.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		return v2Operation{}, v2CoordinatorResult{}, err
	}
	op, err := c.store.admit(principal.Subject, ns.ID, c.store.state.Generation, request, c.now())
	if err != nil {
		return op, v2CoordinatorResult{}, err
	}
	result, err := c.execute(context.Background(), principal, op.ID)
	return op, result, err
}

func TestRoutedCoordinatorStageCapturesLocalAndBlocksIndependentWork(t *testing.T) {
	c, engines, principal := routedCoordinatorFixtureV2(t)
	document, objects := compositeRoutedFixture(t, true)
	firewall := objects[document.Domains.Firewall.Revision].Config
	before := clone(*c.store.state.Configuration)
	for _, engine := range engines {
		engine.reset()
	}
	op, staged, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &firewall})
	if err != nil {
		t.Fatal(err)
	}
	state := staged.Current
	if state.CandidateGroup == nil || state.CandidateGroup.Operation != op.ID || state.CandidateGroup.Base != before.Running.Hash || state.LocalServices.Candidate == nil || state.LocalServices.Candidate.Revision.Hash != before.LocalServices.Running.Hash || state.Firewall.Candidate == nil || state.Candidate.Config.Domains.Network == nil {
		t.Fatal("joint candidate not captured")
	}
	if op.Request.LocalServicesConfig != nil {
		t.Fatal("captured local component changed the admitted fingerprint")
	}
	if err = validateCandidateGroupEvidenceV2(state, c.store.readObject); err != nil {
		t.Fatal("stage lacks durable audit correlation", err)
	}
	for _, corrupt := range []func(*v2Configuration){
		func(state *v2Configuration) { state.CandidateGroup.Operation = "foreign-stage" },
		func(state *v2Configuration) {
			state.CandidateGroup.Owner = "foreign"
			state.Firewall.Candidate.Owner = "foreign"
			state.LocalServices.Candidate.Owner = "foreign"
		},
	} {
		bad := clone(state)
		corrupt(&bad)
		if validateCandidateGroupEvidenceV2(bad, c.store.readObject) == nil {
			t.Fatal("forged stage identity accepted")
		}
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpValidate}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = coordinatorV2Request(t, c, principal, v2Request{Kind: OpStage, Config: ptrConfigV2(coordinatorV2Rule("unrelated"))}); !errors.Is(err, ErrConflict) {
		t.Fatalf("member overwrite accepted: %v", err)
	}
	seconds := uint64(30)
	accepted, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrRecovery) {
		t.Fatalf("missing joint authority accepted: %v", err)
	}
	retained, err := c.store.lookup(principal.Subject, accepted.ID)
	if err != nil || retained.State != "accepted" || c.store.state.Configuration.Intent != nil {
		t.Fatal("unsupported joint activation published intent")
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("metadata invoked an independent component apply")
		}
	}
	area := c.store.root
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("routed stage/archive closure incomplete", err, report)
	}
}

func ptrConfigV2(config Config) *Config { return &config }

func TestRoutedCoordinatorMigrationRefusesCandidatesAndRetainsLegacyBytes(t *testing.T) {
	c, _, _, principal, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	legacy := clone(*c.store.state.Configuration)
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || legacy.Running.Config.SchemaVersion != 5 {
		t.Fatal("invalid legacy fixture")
	}
	coordinatorV2Stage(t, c, principal, "pre-existing")
	selected, used := c.store.selector, c.store.used
	if err := c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); !errors.Is(err, ErrConflict) || c.store.selector != selected || c.store.used != used || hasFeatureV2(c.store.state, v2RoutedFeature) {
		t.Fatalf("opt-in consumed user work: %v", err)
	}
}

func TestRoutedRequestDomainsAndExactConfirmedContract(t *testing.T) {
	doc, objects := compositeRoutedFixture(t, true)
	config := objects[doc.Domains.Firewall.Revision].Config
	local := objects[doc.Domains.LocalServices.Revision].Config
	for _, domain := range []string{"firewall", "local_services"} {
		if v2RequestValid(domain, v2Request{Kind: OpStage, Config: &config, LocalServicesConfig: &local}) {
			t.Fatal("group field accepted by independent domain")
		}
	}
	for _, seconds := range []uint64{0, 29, 121} {
		for _, kind := range []string{OpCommit, OpRollback} {
			if v2RequestValid("routed", v2Request{Kind: kind, ConfirmSeconds: &seconds, Target: doc.Domains.Firewall.Revision}) {
				t.Fatal("unconfirmed routed effect accepted")
			}
		}
	}
	if !v2RequestValid("routed", v2Request{Kind: OpStage, Config: &config, LocalServicesConfig: &local}) {
		t.Fatal("canonical group request rejected")
	}
}

func TestRoutedCoordinatorFeatureAndGroupIntegrity(t *testing.T) {
	c, _, engines, principal, _ := coordinatorV2Fixture(t, false)
	if _, err := c.store.namespace(principal.Subject, "routed", c.now(), time.Hour); !errors.Is(err, errV2Invalid) {
		t.Fatal("routed namespace admitted before opt-in", err)
	}
	attachReserveManagerV2(t, c)
	if err := c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); err != nil {
		t.Fatal(err)
	}
	state := clone(c.store.state)
	state.RequiredFeatures = nil
	if v2ValidState(state) {
		t.Fatal("schema7 accepted without selected feature")
	}
	doc, objects := compositeRoutedFixture(t, true)
	config := objects[doc.Domains.Firewall.Revision].Config
	op := v2Operation{ID: "test-stage", Subject: principal.Subject, Domain: "routed", Request: v2Request{Kind: OpStage, Config: &config}}
	target, _, err := routedTargetV2(c.store, op, *c.store.state.Configuration, c.now(), "")
	if err != nil || !validV2Configuration(&target) {
		t.Fatal("canonical group invalid", err)
	}
	for _, corrupt := range []func(*v2Configuration){
		func(state *v2Configuration) { state.LocalServices.Candidate = nil },
		func(state *v2Configuration) { state.LocalServices.Candidate.Owner = "foreign" },
		func(state *v2Configuration) { state.CandidateGroup.Base = state.Startup.Hash + "f" },
		func(state *v2Configuration) { state.CandidateGroup.Domains = []string{"local_services", "firewall"} },
		func(state *v2Configuration) {
			state.Candidate.Config.Domains.Network.Revision = state.LocalServices.Running.Hash
		},
	} {
		bad := clone(target)
		corrupt(&bad)
		if validV2Configuration(&bad) {
			t.Fatal("forged group accepted")
		}
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("opt-in changed engine")
		}
	}
}

func TestRoutedCoordinatorLocalChangeRequiresRecoveryProofBeforeAdmission(t *testing.T) {
	c, _, principal := routedCoordinatorFixtureV2(t)
	ns, err := c.store.namespace(principal.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	doc, objects := compositeRoutedFixture(t, true)
	config := objects[doc.Domains.Firewall.Revision].Config
	local := clone(c.store.state.Configuration.LocalServices.Running.Config)
	local.LocalServices.Interfaces = append(local.LocalServices.Interfaces, localpolicy.Interface{Name: "test0", Zone: localpolicy.LAN, Addresses: []string{"198.18.10.1"}})
	if canonical, err := Canonical(local); err != nil || canonical.Hash == c.store.state.Configuration.LocalServices.Running.Hash {
		t.Fatal("invalid alternate local fixture", err)
	}
	selected, used, highWater := c.store.selector, c.store.used, c.store.state.HighWater
	_, err = c.store.admit(principal.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config, LocalServicesConfig: &local}, c.now())
	if !errors.Is(err, ErrDenied) || c.store.selector != selected || c.store.used != used || c.store.state.HighWater != highWater || len(c.store.state.ActiveReserves) != 0 {
		t.Fatal("local proof bypass or effects before denial", err)
	}
}

func TestRoutedServiceCurrentUsesSelectedGroupAndIndependentStartup(t *testing.T) {
	service, binding, _, _ := serviceV2Fixture(t, "admin")
	c := service.coordinator
	attachReserveManagerV2(t, c)
	if err := c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); err != nil {
		t.Fatal(err)
	}
	namespace, err := service.Namespace(binding, "routed", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := service.Current(binding, "")
	if err != nil || initial.Domain != "routed" || initial.Routed == nil || initial.DomainGenerations == nil || initial.DomainGenerations.Network != initial.DomainGenerations.Firewall {
		t.Fatal("selected mode/projection not exposed", err)
	}
	doc, objects := compositeRoutedFixture(t, true)
	config := objects[doc.Domains.Firewall.Revision].Config
	admitted, err := service.AdmitObserved(binding, namespace.ID, initial.Global.Generation, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := service.ExecuteObserved(context.Background(), binding, admitted.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	current := staged.Current
	if current.Domain != "routed" || current.Snapshot.Candidate == nil || current.Routed.CandidateGroup == nil || current.Routed.Candidate == nil || current.Routed.Startup.Hash != initial.Routed.Startup.Hash || current.Routed.Running.Hash != initial.Routed.Running.Hash || current.Routed.Candidate.Config.Domains.Network == nil || current.Routed.Startup.Config.Domains.Network != nil {
		t.Fatal("candidate/active/startup network projections mixed")
	}
	current.Routed.CandidateGroup.Owner = "foreign"
	current.Routed.Candidate.Config.Domains.Network.Revision = "foreign"
	read, err := service.Current(binding, "")
	if err != nil || read.Routed.CandidateGroup.Owner == "foreign" || read.Routed.Candidate.Config.Domains.Network.Revision == "foreign" {
		t.Fatal("response aliases selected configuration", err)
	}
}

func TestRoutedCoordinatorColdMigrationPublicationFailure(t *testing.T) {
	for _, point := range []string{"objects_durable", "after_select"} {
		t.Run(point, func(t *testing.T) {
			c, area, engines, _, _ := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			initial := clone(*c.store.state.Configuration)
			budget, options := c.store.budget, c.options
			fired := false
			c.store.hook = func(name string) error {
				if name == point && !fired {
					fired = true
					return ErrInterrupted
				}
				return nil
			}
			if err := c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); err == nil || !fired {
				t.Fatal("fault was not exercised", err)
			}
			c.close()
			if err := c.store.close(); err != nil {
				t.Fatal(err)
			}
			store, err := openV2(area, budget)
			if err != nil {
				t.Fatal("valid selected migration projection could not reopen", err)
			}
			defer store.close()
			if !reflect.DeepEqual(initial.Firewall, store.state.Configuration.Firewall) || !reflect.DeepEqual(initial.LocalServices, store.state.Configuration.LocalServices) {
				t.Fatal("partial component migration published")
			}
			if hasFeatureV2(store.state, v2RoutedFeature) != (point == "after_select") {
				t.Fatal("unselected feature adopted or selected feature lost")
			}
			reopened, err := openCoordinatorV2(context.Background(), store, []Engine{engines[0], engines[1]}, []Engine{engines[2]}, options)
			if err != nil {
				t.Fatal("selected migration did not reconcile", err)
			}
			defer reopened.close()
			for _, engine := range engines {
				if engine.applies.Load() != 0 {
					t.Fatal("metadata migration invoked engine effects")
				}
			}
		})
	}
}
