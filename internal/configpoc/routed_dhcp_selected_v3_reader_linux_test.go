//go:build linux

package configpoc

import (
	"context"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

type dhcpBootAuthorityTestV3 struct{ *boundaryAuthorityFixtureV2 }

func (a dhcpBootAuthorityTestV3) Prepare(ctx context.Context, target RoutedActivationBundleV1, baseline *RoutedBaselineV1) (RoutedPreparationV1, error) {
	p, err := a.boundaryAuthorityFixtureV2.Prepare(ctx, target, baseline)
	p.Before.Version, p.Target.Version, p.Dependencies.Version = 3, 3, 3
	p.Dependencies.NetworkMode = "dhcp-lan"
	return p, err
}

func selectedDHCPReaderFixtureV3(t *testing.T) (*RoutedSelectionReaderV2, *v2Coordinator, *boundaryAuthorityFixtureV2, *RoutedDHCPSelectedStoreV3, *dhcpAuthorityFixtureV3) {
	t.Helper()
	c, authority, principal, _ := boundaryCoordinatorLocalFixtureV2(t, true)
	r := sharedBoundaryReaderV2(t, c, authority)
	snap := dhcpSnapshotFixtureV3(t)
	snap.Identity = r.options.Identity
	snap.Links[0].Index, snap.Links[1].Index, snap.WANIndex = 2, 3, 3
	snap.Hash = ""
	_, snap.Hash, _ = v2Canonical(snap)
	var err error
	snap, err = networkexecutor.CanonicalLeaseSelectedSnapshotV3(snap)
	if err != nil {
		t.Fatal(err)
	}
	doc, objects := compositeRoutedFixture(t, true)
	cfg := objects[doc.Domains.Firewall.Revision].Config
	cfg.Routed.Network = snap.Desired
	fw, err := CanonicalRouted(cfg)
	if err != nil {
		t.Fatal(err)
	}
	authority.prepared.PlanHash, authority.prepared.Hash = snap.Desired.Hash, ""
	_, authority.prepared.Hash, _ = v2Canonical(authority.prepared)
	c.options.Routed = dhcpBootAuthorityTestV3{authority}
	boot := v2BootID(snap.Identity.BootID)
	c.options.BootID = &boot
	c.options.RoutedIdentity = snap.Identity
	local := Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}}, Services: []localpolicy.Service{}}}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &fw.Config, LocalServicesConfig: &local}); err != nil {
		t.Fatal("stage", err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpValidate}); err != nil {
		t.Fatal("validate", err)
	}
	seconds := uint64(30)
	op, result, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal("commit", err)
	}
	if _, _, err = routedRequestV2(t, c, principal, v2Request{Kind: OpConfirm, Origin: op.ID, Target: result.Current.Running.Hash}); err != nil {
		t.Fatal("confirm", err)
	}
	a := &dhcpAuthorityFixtureV3{grant: RoutedDHCPGrantV3{Epoch: 1, Snapshot: snap}, state: networkexecutor.LeaseSelectedBaselineV3}
	w, err := NewRoutedDHCPSelectedStoreV3(&ServiceV2{coordinator: c}, snap.Identity, a)
	if err != nil {
		t.Fatal(err)
	}
	return r, c, authority, w, a
}

func TestRoutedDHCPSelectedV3IndependentFullReaderAndRetirement(t *testing.T) {
	testRoutedDHCPSelectedV3ReaderAndRetirement(t, SelectionFullHistoryV2)
}

func TestRoutedDHCPSelectedV3ActionReaderAndRetirement(t *testing.T) {
	testRoutedDHCPSelectedV3ReaderAndRetirement(t, SelectionActionAuthorityV2)
}

func testRoutedDHCPSelectedV3ReaderAndRetirement(t *testing.T, policy SelectionReaderPolicyV2) {
	t.Helper()
	r, c, _, w, a := selectedDHCPReaderFixtureV3(t)
	r.options.Policy = policy
	snap := a.grant.Snapshot
	var err error
	ctx := context.Background()
	if err = r.VerifyDHCPReleasedV3(ctx); err != nil {
		t.Fatal("initial read", err)
	}
	hash, err := w.Prepare(ctx)
	if err != nil {
		t.Fatal("prepare", err)
	}
	selected, err := r.ResolveDHCPCurrentV3(ctx, hash)
	if err != nil || selected.Phase() != "prepared" || selected.Epoch() != 1 || selected.Snapshot().Hash != snap.Hash || selected.Running() != c.store.state.Configuration.Running.Hash {
		t.Fatal("independent prepared read", err)
	}
	if _, err := r.ResolveDHCPCurrentV3(ctx, strings.Repeat("f", 64)); err == nil {
		t.Fatal("foreign work accepted")
	}
	originalIdentity := r.options.Identity
	for _, kind := range []string{"namespace", "owner-uid", "run"} {
		r.options.Identity = originalIdentity
		switch kind {
		case "namespace":
			r.options.Identity.Namespace++
		case "owner-uid":
			r.options.Identity.UID++
		case "run":
			r.options.Identity.RunID = strings.Repeat("f", 32)
		}
		if _, err := r.ResolveDHCPCurrentV3(ctx, hash); err == nil {
			t.Fatal("foreign selected identity", kind)
		}
	}
	r.options.Identity = originalIdentity
	originalPlan := r.options.Plan
	r.options.Plan = r.options.Admission
	if _, err := r.ResolveDHCPCurrentV3(ctx, hash); err == nil {
		t.Fatal("substituted physical reserve accepted")
	}
	r.options.Plan = originalPlan
	if r.VerifyDHCPReleasedV3(ctx) == nil {
		t.Fatal("active work treated as retired")
	}
	a.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(ctx, hash); err != nil {
		t.Fatal(err)
	}
	probe := &v2Store{root: c.store.root, access: c.store.access, readOnly: true}
	if err = probe.readSelection(); err != nil {
		t.Fatal("applied selection decode", err)
	}
	selected, err = r.ResolveDHCPCurrentV3(ctx, hash)
	if err != nil || selected.Phase() != "applied" {
		t.Fatal("independent applied read", err)
	}
	a.state = networkexecutor.LeaseSelectedBaselineV3
	if err = w.Withdrawn(ctx, hash); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ResolveDHCPCurrentV3(ctx, hash); err == nil {
		t.Fatal("retired work replayed")
	}
	if err = r.VerifyDHCPReleasedV3(ctx); err != nil {
		t.Fatal("independent archive read", err)
	}
	last, err := r.LastWithdrawnDHCPV3(ctx)
	if err != nil || last == nil || last.Hash != snap.Hash {
		t.Fatal("selected terminal proof", err)
	}
	var terminal v3RoutedDHCPState
	if err := c.store.readObject(c.store.state.RoutedDHCPLast, &terminal); err != nil {
		t.Fatal(err)
	}
	archive, found, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: terminal.Bundle.Claims.Admission}, "claim")
	if err != nil || !found {
		t.Fatal("terminal archive fixture", found, err)
	}
	name, err := v2ObjectName(archive.FinalWork)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.store.root.Rename(name, name+".withheld-test"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.store.root.Rename(name+".withheld-test", name); err != nil {
			t.Error(err)
		}
	}()
	if err := r.VerifyDHCPReleasedV3(ctx); err == nil {
		t.Fatal("missing terminal FinalWork accepted as released")
	}
	if _, err := r.LastWithdrawnDHCPV3(ctx); err == nil {
		t.Fatal("missing terminal FinalWork accepted as witness")
	}

}

func TestRoutedDHCPSelectedV3PreparationHonorsIntegrityGate(t *testing.T) {
	w, _ := dhcpStoreFixtureV3(t)
	w.c.options.Integrity = &testIntegrityAdmissionV1{}
	before := w.c.store.selector
	if _, err := w.Prepare(context.Background()); err == nil || w.c.store.selector != before {
		t.Fatal("DHCP bypassed incomplete integrity")
	}
}
