//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// Real store/coordinator with the existing modeled authority. This fixture
// establishes no kernel, listener, network or native recovery evidence.
func noServicesCoordinatorFixtureV3(t *testing.T) (*v2Coordinator, *boundaryAuthorityFixtureV2, v2TrustedPrincipal, Revision) {
	t.Helper()
	fw, local := noServicesEmptyFixtureV3(t)
	legacy := func(revision Revision) *os.Root {
		area, path := checkpointFixtureArea(t)
		store, err := openStore(path, 2048)
		if err != nil {
			t.Fatal(err)
		}
		state := durableState{Snapshot: Snapshot{Generation: 1, Running: revision, Startup: revision, LastGood: revision, Revoked: []string{}}, Receipts: map[string]receipt{}}
		if err = store.append(state, Audit{Sequence: 1, Actor: "alice", At: time.Now().UTC(), Operation: OpSave, Surface: API, Result: "success", RunningHash: revision.Hash}, true, nil); err != nil {
			t.Fatal(err)
		}
		if err = store.lock.Close(); err != nil {
			t.Fatal(err)
		}
		return area
	}
	fwArea, localArea := legacy(fw), legacy(local)
	area, _ := checkpointFixtureArea(t)
	subject := "no-services-subject"
	store, err := prepareMigrationV2(area, fwArea, localArea, []v2Subject{{ID: subject, Login: "alice", CredentialRevision: checkpointDigest([]byte("fixture-revision"))}}, nil, v2Budget{Bytes: 8 << 30, Inodes: 2 << 20}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	fwEngine, localEngine := NewSimEngine("fixture-fw"), NewSimEngine("fixture-local")
	fwEngine.Drift(fw.Hash)
	localEngine.Drift(local.Hash)
	c, err := openCoordinatorV2(context.Background(), store, []Engine{fwEngine}, []Engine{localEngine}, v2CoordinatorOptions{ManualTimeout: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.close(); _ = store.close() })
	attachReserveManagerV2(t, c)
	if err = c.prepareRoutedCompositeLockedV2(context.Background(), reachabilityBudgetV2()); err != nil {
		t.Fatal(err)
	}
	target := noServicesFirewallFixtureV3(t, false)
	snapshot := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: target.Config.Routed.Network.Hash, Links: []networkexecutor.SnapshotLink{{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}, {Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}}, Routes: []networkexecutor.SnapshotRoute{}}
	_, snapshot.Hash, err = v2Canonical(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	a := &boundaryAuthorityFixtureV2{identity: networkexecutor.OwnedNamespaceIdentity{UID: 1000, GID: 1000, Host: 11, Namespace: 22, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}, legacy: fw, local: local, prepared: snapshot, receipt: RoutedReceiptV1{Phase: "bootstrap"}}
	c.options.Routed, c.options.RoutedIdentity = a, a.identity
	return c, a, v2TrustedPrincipal{Subject: subject, Role: RoleAdmin}, target
}

func TestNoServicesV3StageReplaceCommitRetainExactRollback(t *testing.T) {
	c, authority, principal, firewall := noServicesCoordinatorFixtureV3(t)
	before := clone(*c.store.state.Configuration)
	op, staged, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &firewall.Config})
	if err != nil || staged.Current.LocalServices.Candidate == nil || staged.Current.LocalServices.Candidate.Revision.Hash == before.LocalServices.Running.Hash {
		t.Fatal("missing internal inventory candidate", err)
	}
	if !reflect.DeepEqual(staged.Current.LocalServices.Running, before.LocalServices.Running) || !reflect.DeepEqual(staged.Current.LocalServices.Startup, before.LocalServices.Startup) || authority.applies != 0 || op.Request.LocalServicesConfig != nil {
		t.Fatal("stage changed effective state or admitted fingerprint")
	}
	dhcp := noServicesFirewallFixtureV3(t, true)
	replaced, replacement, err := routedRequestV2(t, c, principal, v2Request{Kind: OpReplaceCandidate, Config: &dhcp.Config, ExpectedCandidateStage: op.ID})
	if err != nil || len(replacement.Current.LocalServices.Candidate.Revision.Config.LocalServices.Interfaces) != 1 {
		t.Fatal("replacement failed to rederive DHCP LAN only", err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpReplaceCandidate, Config: &firewall.Config, ExpectedCandidateStage: op.ID}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale replacement consumed newer group", err)
	}
	_, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpReplaceCandidate, Config: &firewall.Config, ExpectedCandidateStage: replaced.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpValidate}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(30)
	commit, pending, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil || pending.Current.Pending == nil || authority.applies != 1 {
		t.Fatal("modeled grouped commit", err)
	}
	var retained v2Configuration
	if err = c.store.readObject(pending.Current.Pending.Previous, &retained); err != nil || !reflect.DeepEqual(retained.LocalServices.Running, before.LocalServices.Running) || !reflect.DeepEqual(pending.Current.LocalServices.Startup, before.LocalServices.Startup) {
		t.Fatal("rollback lost original local bytes", err)
	}
	_, confirmed, err := routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: commit.ID, Target: pending.Current.Running.Hash})
	if err != nil {
		t.Fatal(err)
	}
	rollback := v2Operation{ID: "modeled-rollback", Subject: principal.Subject, Domain: "routed", Request: v2Request{Kind: OpRollback, Target: before.Running.Hash, ConfirmSeconds: &seconds}}
	target, _, err := routedTargetV2(c.store, rollback, confirmed.Current, c.now(), "modeled-lease")
	if err != nil || !reflect.DeepEqual(target.LocalServices.Running, before.LocalServices.Running) || target.Running.Hash != before.Running.Hash || target.Pending == nil {
		t.Fatal("verified historical rollback changed local projection", err)
	}
	rollback.Request.Target = strings.Repeat("f", 64)
	if _, _, err = routedTargetV2(c.store, rollback, confirmed.Current, c.now(), "modeled-lease"); err == nil {
		t.Fatal("unverified historical rollback accepted")
	}
}

func TestNoServicesV3RejectsAPILocalMetadataBeforeAdmission(t *testing.T) {
	c, authority, principal, firewall := noServicesCoordinatorFixtureV3(t)
	derived, err := noServicesInventoryV3(firewall)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := c.store.namespace(principal.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before, used, watermark := c.store.selector, c.store.used, c.store.state.HighWater
	if _, err = c.store.admit(principal.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &firewall.Config, LocalServicesConfig: &derived.Config}, c.now()); !errors.Is(err, ErrDenied) {
		t.Fatal("caller supplied even exact derived local metadata", err)
	}
	if c.store.selector != before || c.store.used != used || c.store.state.HighWater != watermark || authority.applies != 0 {
		t.Fatal("denied metadata changed state")
	}
}

func TestNoServicesV3ConcurrentCandidatesCannotMixInventory(t *testing.T) {
	c, authority, principal, static := noServicesCoordinatorFixtureV3(t)
	dhcp := noServicesFirewallFixtureV3(t, true)
	ns, err := c.store.namespace(principal.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var operations []v2Operation
	for _, fw := range []Revision{static, dhcp} {
		op, err := c.store.admit(principal.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &fw.Config}, c.now())
		if err != nil {
			t.Fatal(err)
		}
		operations = append(operations, op)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, op := range operations {
		wg.Go(func() { _, err := c.execute(context.Background(), principal, op.ID); results <- err })
	}
	wg.Wait()
	close(results)
	accepted, rejected := 0, 0
	for err := range results {
		if err == nil {
			accepted++
		} else if errors.Is(err, ErrConflict) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	state := c.store.state.Configuration
	if accepted != 1 || rejected != 1 || authority.applies != 0 || !RoutedNoServicesTransitionV3(state.Firewall.Running, state.LocalServices.Running, state.Firewall.Candidate.Revision, state.LocalServices.Candidate.Revision) {
		t.Fatal("concurrent stages mixed candidate components", accepted, rejected)
	}
}

type noServicesRefusedAuthorityV3 struct{ *boundaryAuthorityFixtureV2 }

func (a noServicesRefusedAuthorityV3) Prepare(context.Context, RoutedActivationBundleV1, *RoutedBaselineV1) (RoutedPreparationV1, error) {
	return RoutedPreparationV1{}, ErrRecovery
}

func TestNoServicesV3CommitRequiresIndependentPreparation(t *testing.T) {
	c, authority, principal, firewall := noServicesCoordinatorFixtureV3(t)
	_, staged, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &firewall.Config})
	if err != nil {
		t.Fatal(err)
	}
	seconds := uint64(30)
	bad := clone(staged.Current)
	local := clone(bad.LocalServices.Candidate.Revision.Config)
	local.LocalServices.Interfaces[0].Addresses[0] = "198.18.0.99"
	bad.LocalServices.Candidate.Revision, err = Canonical(local)
	if err != nil {
		t.Fatal(err)
	}
	if err = bad.refresh(); err != nil {
		t.Fatal(err)
	}
	op := v2Operation{ID: "forged-local-commit", Subject: principal.Subject, Domain: "routed", Request: v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}}
	if _, _, err = routedTargetV2(c.store, op, bad, c.now(), "fixture-lease"); !errors.Is(err, ErrDenied) {
		t.Fatal("commit trusted arbitrary selected local metadata", err)
	}
	c.options.Routed = noServicesRefusedAuthorityV3{authority}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); !errors.Is(err, ErrRecovery) {
		t.Fatal("commit bypassed refused physical preparation", err)
	}
	state := c.store.state.Configuration
	if state.Pending != nil || state.Intent != nil || authority.applies != 0 || authority.arms != 0 || !reflect.DeepEqual(state.LocalServices, staged.Current.LocalServices) || state.Running.Hash != staged.Current.Running.Hash {
		t.Fatal("failed preparation changed effective configuration")
	}
}

func TestNoServicesV3DHCPCommitUsesOnlyLANInventory(t *testing.T) {
	c, authority, principal, _ := noServicesCoordinatorFixtureV3(t)
	// DHCP selected work requires the independent shared-reader profile.
	reader := sharedBoundaryReaderV2(t, c, authority)
	before := clone(*c.store.state.Configuration)
	dhcp := noServicesFirewallFixtureV3(t, true)
	authority.prepared.PlanHash, authority.prepared.Hash = dhcp.Config.Routed.Network.Hash, ""
	var err error
	_, authority.prepared.Hash, err = v2Canonical(authority.prepared)
	if err != nil {
		t.Fatal(err)
	}
	c.options.Routed = dhcpBootAuthorityTestV3{authority}
	boot := v2BootID(authority.identity.BootID)
	c.options.BootID = &boot
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &dhcp.Config}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(30)
	commit, pending, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil || authority.applies != 1 || pending.Current.Pending == nil {
		t.Fatal("modeled DHCP commit", err)
	}
	local := pending.Current.LocalServices.Running.Config.LocalServices
	if local == nil || len(local.Interfaces) != 1 || local.Interfaces[0].Name != "lan0" || len(local.Services) != 0 || pending.Current.LocalServices.Startup.Hash != before.LocalServices.Startup.Hash {
		t.Fatal("DHCP commit invented WAN metadata or changed Startup")
	}
	var retained v2Configuration
	if err = c.store.readObject(pending.Current.Pending.Previous, &retained); err != nil || !reflect.DeepEqual(retained.LocalServices.Running, before.LocalServices.Running) {
		t.Fatal("DHCP commit lost empty local rollback", err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: commit.ID, Target: pending.Current.Running.Hash}); err != nil {
		t.Fatal(err)
	}
	view, err := reader.PrepareCurrentView(context.Background())
	if err != nil || view.Current.LocalServices.Hash != pending.Current.LocalServices.Running.Hash || view.Saved.LocalServices.Hash != before.LocalServices.Running.Hash {
		t.Fatal("independent selected DHCP inventory read", err)
	}
}
