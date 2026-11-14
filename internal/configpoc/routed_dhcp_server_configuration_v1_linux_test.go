//go:build linux

package configpoc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpserver"
)

func dhcpServerConfigFixtureV1(t *testing.T) Config {
	t.Helper()
	document, objects := compositeRoutedFixture(t, true)
	config := objects[document.Domains.Firewall.Revision].Config
	config.Routed.SchemaVersion = 2
	config.Routed.DHCPServer = &dhcpserver.Config{SchemaVersion: 1, Enabled: true, Scopes: []dhcpserver.Scope{{ID: "office", InterfaceID: "lan", Subnet: "198.18.0.0/24", Router: "198.18.0.1", Pools: []dhcpserver.Pool{{First: "198.18.0.10", Last: "198.18.0.20"}}, LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000}}}
	return config
}

func TestDHCPServerUnsupportedAdmissionNoWrites(t *testing.T) {
	c, engines, p := routedCoordinatorFixtureV2(t)
	ns, err := c.store.namespace(p.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	config := dhcpServerConfigFixtureV1(t)
	state := clone(c.store.state)
	selector, used := c.store.selector, c.store.used
	for _, engine := range engines {
		engine.reset()
	}
	_, err = c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config}, c.now())
	if !errors.Is(err, ErrDenied) || !reflect.DeepEqual(state, c.store.state) || selector != c.store.selector || used != c.store.used || c.store.blocked {
		t.Fatal("unsupported admission mutated store", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("unsupported factory applied")
		}
	}
}

func TestDHCPServerStageStickyReplayAndReopen(t *testing.T) {
	c, engines, p := routedCoordinatorFixtureV2(t)
	// Explicit test-only assembly: no DHCP process or activation claim.
	c.store.dhcpServerSupported = true
	config := dhcpServerConfigFixtureV1(t)
	ns, err := c.store.namespace(p.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config}, c.now())
	if err != nil || !hasFeatureV2(c.store.state, v1RoutedDHCPServerFeature) {
		t.Fatal("first durable admission lacks marker", err)
	}
	fingerprint := op.Fingerprint
	result, err := c.execute(context.Background(), p, op.ID)
	if err != nil || result.Current.Firewall.Candidate == nil {
		t.Fatal("stage", err)
	}
	got := result.Current.Firewall.Candidate.Revision.Config.Routed.DHCPServer
	if got == nil || !got.Enabled || got.Scopes[0].Router != "198.18.0.1" {
		t.Fatal("candidate lost DHCP")
	}
	selected, used := c.store.selector, c.store.used
	replay, err := c.execute(context.Background(), p, op.ID)
	if err != nil || replay.Operation.Fingerprint != fingerprint || c.store.selector != selected || c.store.used != used {
		t.Fatal("replay changed durable state", err)
	}
	without := clone(c.store.state)
	for i, f := range without.RequiredFeatures {
		if f == v1RoutedDHCPServerFeature {
			without.RequiredFeatures = append(without.RequiredFeatures[:i], without.RequiredFeatures[i+1:]...)
			break
		}
	}
	if validFeaturesV2(without) || preservesFeaturesV2(c.store.state, without) {
		t.Fatal("marker removed")
	}
	for _, engine := range engines {
		engine.reset()
	}
	area, budget := c.store.root, c.store.budget
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("DHCP closure", err)
	}
	reopened, err := openV2(area, budget)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.close(); err != nil {
			t.Error(err)
		}
	}()
	if !hasFeatureV2(reopened.state, v1RoutedDHCPServerFeature) {
		t.Fatal("marker not durable")
	}
	if _, err = openCoordinatorV2(context.Background(), reopened, c.firewall, c.local, c.options); !errors.Is(err, ErrRecovery) {
		t.Fatal("unsupported reopen", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("reopen invoked engine")
		}
	}
}

func TestDHCPServerJointProjectionRetainsConfiguration(t *testing.T) {
	c, _, p := routedCoordinatorFixtureV2(t)
	c.store.dhcpServerSupported = true
	config := dhcpServerConfigFixtureV1(t)
	_, staged, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	seconds := uint64(30)
	op := v2Operation{ID: "projection-only", Subject: p.Subject, Domain: "routed", Request: v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}}
	target, _, err := routedTargetV2(c.store, op, staged.Current, c.now(), "original-lease")
	if err != nil || target.Pending == nil || !target.Pending.Deadline.Equal(c.now().Add(30*time.Second)) || target.Firewall.Running.Config.Routed.DHCPServer == nil {
		t.Fatal("commit projection", err)
	}
	if target.Firewall.Startup.Hash != staged.Current.Firewall.Startup.Hash {
		t.Fatal("commit saved implicitly")
	}
	save := v2Operation{ID: "save-projection", Subject: p.Subject, Domain: "routed", Request: v2Request{Kind: OpSave}}
	if _, _, err = routedTargetV2(c.store, save, target, c.now(), ""); !errors.Is(err, ErrConflict) {
		t.Fatal("save bypassed pending", err)
	}
	// Pure projection only: clearing Pending here is not a physical Confirm.
	target.Pending = nil
	saved, _, err := routedTargetV2(c.store, save, target, c.now(), "")
	if err != nil || saved.Firewall.Startup.Hash != target.Firewall.Running.Hash || !reflect.DeepEqual(saved.Firewall.Startup.Config.Routed.DHCPServer, target.Firewall.Running.Config.Routed.DHCPServer) {
		t.Fatal("save projection lost DHCP", err)
	}
	target.Firewall.Running.Config.Routed.DHCPServer.Scopes[0].Pools[0].First = "mutated"
	if saved.Firewall.Startup.Config.Routed.DHCPServer.Scopes[0].Pools[0].First == "mutated" {
		t.Fatal("projection alias")
	}
}

func TestDHCPServerFirstCandidatePublicationMarksFeature(t *testing.T) {
	c, _, p := routedCoordinatorFixtureV2(t)
	config := dhcpServerConfigFixtureV1(t)
	// Test the low-level publication boundary independently of Admit. No engine
	// effects are permitted; this synthetic candidate is not claimed as a full G1 fixture.
	op := v2Operation{ID: "unpublished-stage", Subject: p.Subject, Domain: "routed", Request: v2Request{Kind: OpStage, Config: &config}}
	target, _, err := routedTargetV2(c.store, op, *c.store.state.Configuration, c.now(), "")
	if err != nil {
		t.Fatal(err)
	}
	next := clone(c.store.state)
	next.Configuration = &target
	next.Generation++
	addFeatureV2(&next, v2OwnedCandidateFeature)
	addFeatureV2(&next, v2LocalFeature)
	selected, used := c.store.selector, c.store.used
	if err = c.store.publish(next); !errors.Is(err, ErrDenied) || selected != c.store.selector || used != c.store.used {
		t.Fatal("unsupported direct publication", err)
	}
	c.store.dhcpServerSupported = true
	if err = c.store.publish(next); err != nil {
		t.Fatal(err)
	}
	if !hasFeatureV2(c.store.state, v1RoutedDHCPServerFeature) {
		t.Fatal("candidate selected without refusal marker")
	}
	if hasFeatureV2(next, v1RoutedDHCPServerFeature) {
		t.Fatal("publish mutated caller feature slice")
	}
}

func TestDHCPServerForecastReservesMarkerBeforeAdmission(t *testing.T) {
	state := v2State{}
	forecast := reserveMetadataCoreV2(state)
	if !hasFeatureV2(forecast, v1RoutedDHCPServerFeature) || hasFeatureV2(state, v1RoutedDHCPServerFeature) {
		t.Fatal("forecast omitted marker or mutated source")
	}
	addFeatureV2(&state, v1RoutedDHCPServerFeature)
	a, _, _ := v2Canonical(forecast)
	b, _, _ := v2Canonical(reserveMetadataCoreV2(state))
	if !bytes.Equal(a, b) {
		t.Fatal("unreserved marker growth")
	}
	// Find the exact core boundary with an inert padding value. Removing the
	// forecast marker would incorrectly admit this state at the old byte limit.
	base := v2State{Format: "padding"}
	raw, _, _ := v2Canonical(reserveMetadataCoreV2(base))
	base.Format += strings.Repeat("x", 128*1024-len(raw))
	if !reserveMetadataStateFitsV2(base) {
		t.Fatal("exact core limit rejected")
	}
	base.Format += "x"
	if reserveMetadataStateFitsV2(base) {
		t.Fatal("core overflow admitted")
	}
}

func TestDHCPServerOldReaderBarrier(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("explicit prior-source test binary required")
	}
	c, _, p := routedCoordinatorFixtureV2(t)
	area, budget := c.store.root, c.store.budget
	run := func(want string) {
		t.Helper()
		files := journalFiles(t, area.Name())
		output, err := exec.Command(*reclaimOldReader, "-test.run=^TestReclaimPriorReader$", "-prior-reclaim-area="+area.Name()).CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte(want)) {
			t.Fatalf("old reader: %v %s", err, output)
		}
		if !reflect.DeepEqual(files, journalFiles(t, area.Name())) {
			t.Fatal("old reader changed files")
		}
	}
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	run("OLD_READER_ACCEPTED")
	var err error
	c.store, err = openV2(area, budget)
	if err != nil {
		t.Fatal(err)
	}
	c.store.reserves = c.options.Reserves
	c.store.dhcpServerSupported = true
	config := dhcpServerConfigFixtureV1(t)
	_, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	candidate := c.store.state.Configuration.CandidateGroup.Operation
	_, _, err = routedRequestV2(t, c, p, v2Request{Kind: OpDiscardCandidate, ExpectedCandidateStage: candidate})
	if err != nil {
		t.Fatal(err)
	}
	if configurationHasDHCPServerV1(c.store.state.Configuration) {
		t.Fatal("fixture still has DHCP payload")
	}
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	run("OLD_READER_REJECTED")
	reopened, err := openV2(area, budget)
	if err != nil {
		t.Fatal("new reader rejected own marker", err)
	}
	if err = reopened.close(); err != nil {
		t.Fatal(err)
	}
}

func TestDHCPServerOperationLimitAndFeatureContext(t *testing.T) {
	c, _, p := routedCoordinatorFixtureV2(t)
	c.store.dhcpServerSupported = true
	ns, err := c.store.namespace(p.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	config := dhcpServerConfigFixtureV1(t)
	for i := 0; i < 200; i++ {
		config.Routed.DHCPServer.Scopes[0].Reservations = append(config.Routed.DHCPServer.Scopes[0].Reservations, dhcpserver.Reservation{MAC: fmt.Sprintf("02:00:00:00:00:%02x", i+1), Address: fmt.Sprintf("198.18.0.%d", i+30)})
	}
	if _, err := CanonicalRouted(config); err != nil {
		t.Fatal("standalone config should be valid", err)
	}
	selected, used := c.store.selector, c.store.used
	if _, err = c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config}, c.now()); !errors.Is(err, errV2Invalid) || c.store.selector != selected || c.store.used != used {
		t.Fatal("operation bound changed", err)
	}
	config = dhcpServerConfigFixtureV1(t)
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config}, c.now())
	if err != nil {
		t.Fatal(err)
	}
	if !c.store.validOperation(op) {
		t.Fatal("marked operation invalid")
	}
	reader := &v2Store{state: clone(c.store.state)}
	for i, f := range reader.state.RequiredFeatures {
		if f == v1RoutedDHCPServerFeature {
			reader.state.RequiredFeatures = append(reader.state.RequiredFeatures[:i], reader.state.RequiredFeatures[i+1:]...)
			break
		}
	}
	if reader.validOperation(op) {
		t.Fatal("operation accepted outside feature context")
	}
}
