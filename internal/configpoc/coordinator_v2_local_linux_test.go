//go:build linux

package configpoc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
)

// This authority is deliberately a simulated evidence boundary for coordinator
// fault tests. localadmin's real book/auth integration is tested separately.
type localFaultPolicyV2 struct{}
type localFaultHandleV2 struct{}

func (localFaultHandleV2) LocalProofHandleV2() {}

type localFaultReservationV2 struct{}

func (localFaultReservationV2) Finish(bool)                            {}
func (localFaultPolicyV2) AuthenticationAuthority() *adminauth.Manager { return nil }
func (localFaultPolicyV2) Authenticate(adminauth.SessionBinding, LocalReceiverV2, LocalEvidenceV2) (LocalHandleV2, error) {
	return localFaultHandleV2{}, nil
}
func (localFaultPolicyV2) Validate(scope LocalProofScopeV2) error {
	if !scope.Valid() {
		return ErrInvalid
	}
	return nil
}
func (localFaultPolicyV2) Issue(LocalHandleV2, LocalProofScopeV2) (LocalTokenV2, error) {
	return LocalTokenV2{}, ErrDenied
}
func (localFaultPolicyV2) Reserve(LocalHandleV2, LocalProofScopeV2) (LocalReservationV2, error) {
	return localFaultReservationV2{}, nil
}
func (localFaultPolicyV2) PublishPending(LocalPendingViewV2) error { return nil }
func (localFaultPolicyV2) Invalidate()                             {}

func localFaultRequestV2(t *testing.T, c *v2Coordinator, p v2TrustedPrincipal, request v2Request) (v2Operation, v2CoordinatorResult, error) {
	t.Helper()
	ns, err := c.store.namespace(p.Subject, "local_services", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, request, c.now())
	if err != nil {
		t.Fatal(err)
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	out, err := c.executeLocalLocked(context.Background(), p, op.ID, localFaultHandleV2{})
	return op, out, err
}

func TestCoordinatorLocalV2PreservesForeignCandidateAndStickyFeature(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, false)
	c.options.LocalPolicy = localFaultPolicyV2{}
	coordinatorV2Stage(t, c, p, "foreign-candidate")
	before := clone(c.store.state.Configuration.Firewall)
	config := localSample(t, 18443)
	_, staged, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	if staged.Current.LocalServices.Candidate == nil || !reflect.DeepEqual(before, staged.Current.Firewall) || !hasFeatureV2(c.store.state, v2LocalFeature) {
		t.Fatal("candidate/feature lost")
	}
	seconds := uint64(30)
	_, committed, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, committed.Current.Firewall) || committed.Current.Firewall.Candidate == nil || committed.Current.LocalServices.Candidate != nil {
		t.Fatal("cross-domain commit")
	}
	pending := committed.Current.Pending
	_, confirmed, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpConfirm, Origin: pending.OriginCommit, Target: pending.Target})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, confirmed.Current.Firewall) || !hasFeatureV2(c.store.state, v2LocalFeature) {
		t.Fatal("confirm dropped foreign candidate/feature")
	}
	stripped := clone(c.store.state)
	stripped.RequiredFeatures = nil
	if preservesFeaturesV2(c.store.state, stripped) {
		t.Fatal("sticky feature stripped")
	}
}

func TestCoordinatorLocalV2FaultCompensation(t *testing.T) {
	for _, point := range []string{"before", "after"} {
		t.Run(point, func(t *testing.T) {
			c, _, engines, p, _ := coordinatorV2Fixture(t, false)
			c.options.LocalPolicy = localFaultPolicyV2{}
			initial := clone(*c.store.state.Configuration)
			config := localSample(t, 18443)
			if _, _, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
				t.Fatal(err)
			}
			engines[2].base.FailNext(point)
			seconds := uint64(30)
			_, out, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			if !errors.Is(err, ErrEngine) || out.Operation.State != "final" || out.Operation.Outcome.Code != "failed_rolled_back" || out.Current.LocalServices.Running.Hash != initial.LocalServices.Running.Hash || out.Current.Firewall.Running.Hash != initial.Firewall.Running.Hash || out.Current.Startup.Hash != initial.Startup.Hash || !c.readback(out.Current) {
				t.Fatal("unverified partial publication", out.Operation.State, err)
			}
		})
	}
}

func TestCoordinatorLocalV2ProcessExit(t *testing.T) {
	if os.Getenv("ANDEIVA_LOCAL_V2_CHILD") == "1" {
		area, err := os.OpenRoot(os.Getenv("ANDEIVA_LOCAL_V2_STATE"))
		if err != nil {
			os.Exit(75)
		}
		components, err := os.OpenRoot(os.Getenv("ANDEIVA_LOCAL_V2_COMPONENTS"))
		if err != nil {
			os.Exit(76)
		}
		store, err := openV2(area, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20})
		if err != nil {
			os.Exit(77)
		}
		fw, local := persistentCoordinatorV2Engines(components)
		c, err := openCoordinatorV2(context.Background(), store, fw, local, v2CoordinatorOptions{ManualTimeout: true, LocalPolicy: localFaultPolicyV2{}, Hook: func(point string) error {
			if point == os.Getenv("ANDEIVA_LOCAL_V2_POINT") {
				os.Exit(74)
			}
			return nil
		}})
		if err != nil {
			os.Exit(78)
		}
		store.mu.Lock()
		_, _ = c.executeLocalLocked(context.Background(), v2TrustedPrincipal{Subject: store.state.Subjects[0].ID, Role: RoleAdmin}, os.Getenv("ANDEIVA_LOCAL_V2_OPERATION"), localFaultHandleV2{})
		os.Exit(79)
	}
	for _, point := range []string{"after_intent", "after_component_apply", "after_readback"} {
		t.Run(point, func(t *testing.T) {
			seed, area, _, p, _ := coordinatorV2Fixture(t, false)
			initial := clone(*seed.store.state.Configuration)
			components, _ := checkpointFixtureArea(t)
			for _, name := range []string{"fw-first", "fw-second", "local-only"} {
				hash := initial.Firewall.Running.Hash
				if name == "local-only" {
					hash = initial.LocalServices.Running.Hash
				}
				if err := components.WriteFile(name+".hash", []byte(hash), 0600); err != nil {
					t.Fatal(err)
				}
			}
			seed.close()
			fw, local := persistentCoordinatorV2Engines(components)
			c, err := openCoordinatorV2(context.Background(), seed.store, fw, local, v2CoordinatorOptions{ManualTimeout: true, LocalPolicy: localFaultPolicyV2{}})
			if err != nil {
				t.Fatal(err)
			}
			config := localSample(t, 18443)
			if _, _, err = localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
				t.Fatal(err)
			}
			ns, err := c.store.namespace(p.Subject, "local_services", c.now(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			seconds := uint64(30)
			op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}, c.now())
			if err != nil {
				t.Fatal(err)
			}
			c.close()
			if err = c.store.close(); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestCoordinatorLocalV2ProcessExit$")
			command.Env = append(os.Environ(), "ANDEIVA_LOCAL_V2_CHILD=1", "ANDEIVA_LOCAL_V2_STATE="+area.Name(), "ANDEIVA_LOCAL_V2_COMPONENTS="+components.Name(), "ANDEIVA_LOCAL_V2_OPERATION="+op.ID, "ANDEIVA_LOCAL_V2_POINT="+point)
			output, err := command.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 74 {
				t.Fatalf("process boundary %v %s", err, output)
			}
			store, err := openV2(area, c.store.budget)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			resumed, err := openCoordinatorV2(context.Background(), store, fw, local, v2CoordinatorOptions{ManualTimeout: true, LocalPolicy: localFaultPolicyV2{}})
			if err != nil {
				t.Fatal(err)
			}
			defer resumed.close()
			if resumed.store.state.Configuration.Intent != nil || resumed.store.state.Configuration.LocalServices.Running.Hash != initial.LocalServices.Running.Hash || resumed.store.state.Configuration.Firewall.Running.Hash != initial.Firewall.Running.Hash || !resumed.readback(*resumed.store.state.Configuration) {
				t.Fatal("interrupted local transition published target")
			}
			result, err := resumed.store.lookup(p.Subject, op.ID)
			if err != nil || result.State != "final" || result.Outcome.Code != "failed_rolled_back" {
				t.Fatal("interrupted operation outcome", result.State, err)
			}
		})
	}
}

type metadataDriftEngineV2 struct {
	Engine
	base  *SimEngine
	reads atomic.Int64
}

func (e *metadataDriftEngineV2) Current() string {
	if e.reads.Add(1) == 2 {
		e.base.Drift(strings.Repeat("f", 64))
	}
	return e.Engine.Current()
}

func TestCoordinatorLocalV2MetadataDriftNeverApplies(t *testing.T) {
	for _, domain := range []string{"local_services", "firewall"} {
		for _, kind := range []string{OpStage, OpValidate, OpSave} {
			t.Run(domain+"/"+kind, func(t *testing.T) {
				c, _, engines, p, _ := coordinatorV2Fixture(t, false)
				c.options.LocalPolicy = localFaultPolicyV2{}
				config := coordinatorV2Rule("metadata-drift")
				if domain == "local_services" {
					config = localSample(t, 18443)
				}
				if kind == OpValidate {
					if domain == "local_services" {
						if _, _, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
							t.Fatal(err)
						}
					} else {
						coordinatorV2Stage(t, c, p, "metadata-drift")
					}
				}
				before := clone(c.store.state)
				for _, engine := range engines {
					engine.reset()
				}
				c.firewall[0] = &metadataDriftEngineV2{Engine: engines[0], base: engines[0].base}
				request := v2Request{Kind: kind}
				if kind == OpStage {
					request.Config = &config
				}
				var out v2CoordinatorResult
				var err error
				if domain == "local_services" {
					_, out, err = localFaultRequestV2(t, c, p, request)
				} else {
					_, out, err = coordinatorV2Request(t, c, p, request)
				}
				if !errors.Is(err, ErrRecovery) || out.Operation.State != "uncertain" || out.Operation.Outcome != nil || !out.Current.RecoveryRequired || out.GlobalGeneration != before.Generation || out.Current.Running.Hash != before.Configuration.Running.Hash || out.Current.Startup.Hash != before.Configuration.Startup.Hash {
					t.Fatal("metadata drift published success", out.Operation.State, err)
				}
				for _, engine := range engines {
					if engine.applies.Load() != 0 {
						t.Fatal("metadata operation applied a component", engine.Name(), engine.applies.Load())
					}
				}
			})
		}
	}
}

func TestCoordinatorLocalV2SelectedMetadataDriftNeverApplies(t *testing.T) {
	for _, domain := range []string{"local_services", "firewall"} {
		for _, kind := range []string{OpStage, OpValidate, OpSave} {
			t.Run(domain+"/"+kind, func(t *testing.T) {
				c, _, engines, p, _ := coordinatorV2Fixture(t, false)
				c.options.LocalPolicy = localFaultPolicyV2{}
				config := coordinatorV2Rule("selected-drift")
				if domain == "local_services" {
					config = localSample(t, 18443)
				}
				if kind == OpValidate {
					if domain == "local_services" {
						if _, _, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
							t.Fatal(err)
						}
					} else {
						coordinatorV2Stage(t, c, p, "selected-drift")
					}
				}
				request := v2Request{Kind: kind}
				if kind == OpStage {
					request.Config = &config
				}
				ns, err := c.store.namespace(p.Subject, domain, c.now(), time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, request, c.now())
				if err != nil {
					t.Fatal(err)
				}
				for _, engine := range engines {
					engine.reset()
				}
				selections := 0
				c.store.hook = func(point string) error {
					if point == "after_select" {
						selections++
						if selections == 2 {
							engines[0].base.Drift(strings.Repeat("f", 64))
							return ErrInterrupted
						}
					}
					return nil
				}
				if domain == "local_services" {
					c.store.mu.Lock()
					_, err = c.executeLocalLocked(context.Background(), p, op.ID, localFaultHandleV2{})
					c.store.mu.Unlock()
				} else {
					_, err = c.execute(context.Background(), p, op.ID)
				}
				if err == nil || selections != 2 {
					t.Fatal("did not reach selected final failure", err, selections)
				}
				for _, engine := range engines {
					if engine.applies.Load() != 0 {
						t.Fatal("selector reload lost metadata purpose", engine.Name(), engine.applies.Load())
					}
				}
				if !c.store.blocked || c.readback(*c.store.state.Configuration) {
					t.Fatal("post-selection drift was not fenced")
				}
			})
		}
	}
}

func TestCoordinatorLocalV2ExplicitFirewallRecoveryRepairsOnlyFirewall(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	c.options.LocalPolicy = localFaultPolicyV2{}
	local := localSample(t, 18443)
	if _, _, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &local}); err != nil {
		t.Fatal(err)
	}
	candidate := c.store.state.Configuration.LocalServices.Candidate.Revision.Hash
	coordinatorV2Stage(t, c, p, "explicit-recovery")
	zero := uint64(0)
	committed := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	for _, engine := range engines {
		engine.reset()
	}
	engines[0].base.Drift(strings.Repeat("f", 64))
	recovered := coordinatorV2Run(t, c, p, v2Request{Kind: OpRecover})
	if recovered.Current.Firewall.Running.Hash != committed.Current.Firewall.LastGood.Hash || recovered.Current.LocalServices.Candidate == nil || recovered.Current.LocalServices.Candidate.Revision.Hash != candidate {
		t.Fatal("explicit recovery changed unrelated candidate or restored wrong revision")
	}
	if engines[0].applies.Load() != 1 || engines[1].applies.Load() != 1 || engines[2].applies.Load() != 0 {
		t.Fatal("explicit recovery did not stay in firewall domain")
	}
}

func TestCoordinatorLocalV2ReachabilityWithBootFeature(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprintf("pending-%t", pending), func(t *testing.T) {
			c, area, engines, p := bootFixtureV2(t)
			c.options.LocalPolicy = localFaultPolicyV2{}
			config := localSample(t, 18443)
			if _, _, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
				t.Fatal(err)
			}
			id := v2BootID("a1111111-2222-3333-4444-555555555555")
			c.options.BootID = &id
			if pending {
				c.options.Hook = func(point string) error {
					if point == "after_boot_intent" {
						return ErrInterrupted
					}
					return nil
				}
			}
			c.store.mu.Lock()
			err := c.bootStartupLocked(context.Background(), id)
			c.store.mu.Unlock()
			if pending {
				if !errors.Is(err, ErrInterrupted) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !hasFeatureV2(c.store.state, v2BootFeature) || !hasFeatureV2(c.store.state, v2LocalFeature) {
				t.Fatal("combined features missing")
			}
			c.close()
			if err := c.store.close(); err != nil {
				t.Fatal(err)
			}
			before := journalFiles(t, area.Name())
			for _, engine := range engines {
				engine.reset()
			}
			report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
			if err != nil || !report.Complete {
				t.Fatal("combined feature closure rejected", report, err)
			}
			if !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("inspection mutated store")
			}
			for _, engine := range engines {
				if engine.applies.Load() != 0 {
					t.Fatal("inspection applied component")
				}
			}
		})
	}
}

func TestCoordinatorLocalV2BootMaterializesCandidateBeforeIntent(t *testing.T) {
	c, area, engines, p := bootFixtureV2(t)
	c.options.LocalPolicy = localFaultPolicyV2{}
	config := localSample(t, 18443)
	if _, _, err := localFaultRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config}); err != nil {
		t.Fatal(err)
	}
	before := clone(c.store.state)
	target, err := bootTargetV2(*before.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if target.Candidate == nil || target.Candidate.Hash == before.Configuration.Candidate.Hash {
		t.Fatal("fixture needs newly composed candidate")
	}
	c.options.BootID = ptrBootV2(testBootIDV2)
	c.options.Hook = func(point string) error {
		if point == "before_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	for _, engine := range engines {
		engine.reset()
	}
	c.store.mu.Lock()
	err = c.bootStartupLocked(context.Background(), testBootIDV2)
	c.store.mu.Unlock()
	if !errors.Is(err, ErrInterrupted) || !reflect.DeepEqual(before, c.store.state) {
		t.Fatal("pre-intent interruption selected state", err)
	}
	var stored v2CompositeConfig
	if err := c.store.readObject(target.Candidate.Hash, &stored); err != nil {
		t.Fatal("candidate not materialized before intent", err)
	}
	canonical, err := CanonicalComposite(stored)
	if err != nil || canonical.Hash != target.Candidate.Hash {
		t.Fatal("materialized wrong candidate", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("effect before durable intent")
		}
	}
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	if booted.store.state.Configuration.Candidate == nil || booted.store.state.Configuration.Candidate.Hash != target.Candidate.Hash || booted.store.state.Configuration.LocalServices.Candidate.Revision.Hash != before.Configuration.LocalServices.Candidate.Revision.Hash {
		t.Fatal("resume changed staged local candidate")
	}
	booted.close()
	if err := booted.store.close(); err != nil {
		t.Fatal(err)
	}
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("resumed boot closure incomplete", report, err)
	}
}
