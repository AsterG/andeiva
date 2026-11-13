//go:build linux

package configpoc

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// This models only the trusted helper's receipt/readback reply. Store, selected
// work, reserve pools and archive validation remain real. It is not native
// process drainage, namespace absence or FD-authentication evidence.
type freshScopeFixtureV3 struct {
	old          networkexecutor.OwnedNamespaceIdentity
	fresh        *boundaryAuthorityFixtureV2
	before, deps string
	denied       bool
	mutate       func(*RoutedFreshScopeEvidenceV3)
	calls        int
}

func (f *freshScopeFixtureV3) ProveFreshScope(_ context.Context, work string) (RoutedFreshScopeEvidenceV3, error) {
	f.calls++
	if f.denied {
		return RoutedFreshScopeEvidenceV3{}, ErrRecovery
	}
	e := RoutedFreshScopeEvidenceV3{Version: 3, Old: f.old, New: f.fresh.identity, Work: work, ReceiptSHA256: strings.Repeat("a", 64), MetadataSHA256: strings.Repeat("b", 64), DrainedAtBootNS: 100, ObservedAtBootNS: 200, Before: f.before, Dependencies: f.deps}
	if f.mutate != nil {
		f.mutate(&e)
	}
	return e, nil
}
func sharedBoundaryFixtureV3(t *testing.T) (*v2Coordinator, *boundaryAuthorityFixtureV2) {
	t.Helper()
	c, a, _, _ := boundaryCoordinatorFixtureV2(t)
	m := c.store.reserves
	c.store = sharedTestStoreV2(t, c.store)
	c.store.reserves = m
	c.options.SharedReader = c.store.access
	return c, a
}
func freshScopeAuthorityFixtureV3(t *testing.T, c *v2Coordinator, old *boundaryAuthorityFixtureV2) (*boundaryAuthorityFixtureV2, *freshScopeFixtureV3) {
	t.Helper()
	a := freshBoundaryAuthorityV2(old)
	a.identity.BootID, a.identity.Host = old.identity.BootID, old.identity.Host
	targetState, err := serviceRestartTargetV3(*c.store.state.Configuration, c.store.readObject)
	if err != nil {
		t.Fatal(err)
	}
	target, err := bundleFromConfigurationV2(targetState)
	if err != nil {
		t.Fatal(err)
	}
	saved := target
	if target.Firewall.Config.SchemaVersion != 4 {
		plan, e := loadRoutedWorkV2(c.store.state.RoutedActive.Work, c.store.state.Lineage, c.store.readObject)
		if e != nil {
			t.Fatal(e)
		}
		saved = plan.Baseline().Saved
	}
	p, err := a.PrepareBoot(context.Background(), target, saved)
	if err != nil {
		t.Fatal(err)
	}
	p.Before, err = CanonicalOwned(p.Before)
	if err != nil {
		t.Fatal(err)
	}
	p.Dependencies, err = CanonicalDependencies(p.Dependencies)
	if err != nil {
		t.Fatal(err)
	}
	_, before, _ := v2Canonical(p.Before)
	_, deps, _ := v2Canonical(p.Dependencies)
	return a, &freshScopeFixtureV3{old: old.identity, fresh: a, before: before, deps: deps}
}
func reopenFreshScopeFixtureV3(t *testing.T, c *v2Coordinator, a *boundaryAuthorityFixtureV2, f *freshScopeFixtureV3) (*v2Coordinator, error) {
	t.Helper()
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	s, err := openSharedStoreV2(c.store.root, c.store.budget, *c.store.access)
	if err != nil {
		return nil, err
	}
	opts := c.options
	opts.Routed, opts.RoutedIdentity, opts.FreshScope = a, a.identity, f
	b := v2BootID(a.identity.BootID)
	opts.BootID = &b
	opts.Hook = nil
	opened, err := openCoordinatorV2(context.Background(), s, c.firewall, c.local, opts)
	if err != nil {
		t.Logf("reopen: proof calls=%d selected intent=%t boundary=%t", f.calls, s.state.Configuration.Intent != nil, s.state.RoutedBootBoundary != nil)
	}
	t.Cleanup(func() {
		if opened != nil {
			opened.close()
		}
		_ = s.close()
	})
	return opened, err
}

func TestRoutedFreshScopeV3SameBootCompletedServiceRestart(t *testing.T) {
	c, old := sharedBoundaryFixtureV3(t)
	boot := v2BootID(old.identity.BootID)
	c.options.BootID = &boot
	if err := c.bootStartupLocked(context.Background(), boot); err != nil {
		t.Fatal(err)
	}
	prior := c.store.state.Configuration.LastCompletedBoot
	fresh, proof := freshScopeAuthorityFixtureV3(t, c, old)
	opened, err := reopenFreshScopeFixtureV3(t, c, fresh, proof)
	if err != nil {
		t.Fatal("normal same-Boot restart", err)
	}
	if fresh.bootstraps != 1 || fresh.recovers != 0 || fresh.foreign != 0 || opened.store.state.Configuration.LastCompletedBoot == prior || !hasFeatureV2(opened.store.state, v3RoutedFreshScopeFeature) {
		t.Fatal("fresh scope not selected/applied")
	}
	p, err := loadRoutedWorkV2(opened.store.state.RoutedActive.Work, opened.store.state.Lineage, opened.store.readObject)
	if err != nil || p.FreshScopeEvidenceV3() == nil || p.Scope().Identity != fresh.identity {
		t.Fatal("scope witness missing", err)
	}
	root, err := opened.store.root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	graph := &v2ReachabilityReader{ctx: context.Background(), area: opened.store.root, root: root, shared: opened.store.access, ownerRead: true, budget: reachabilityBudgetV2(), objects: map[string]bool{}, edges: map[string]uint8{}}
	if report, err := graph.traceLocked(opened.store.lock); err != nil || !report.Complete {
		t.Fatal("G1", err, report)
	}
}

func TestRoutedFreshScopeV3SameBootPendingBootPreservesDeadline(t *testing.T) {
	c, old := sharedBoundaryFixtureV3(t)
	boot := v2BootID(old.identity.BootID)
	c.options.BootID = &boot
	c.options.Hook = func(s string) error {
		if s == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	if err := c.bootStartupLocked(context.Background(), boot); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	var original v2RecoveryRecord
	if err := c.store.readObject(c.store.state.Configuration.LastRecovery, &original); err != nil {
		t.Fatal(err)
	}
	deadline := original.Started.Add(10 * time.Second)
	fresh, proof := freshScopeAuthorityFixtureV3(t, c, old)
	opened, err := reopenFreshScopeFixtureV3(t, c, fresh, proof)
	if err != nil {
		t.Fatal("pending same-Boot restart", err)
	}
	resolved, err := opened.recoveryLookupLocked(original.ID)
	if err != nil || resolved.SupersededBy == "" || !resolved.Started.Add(10*time.Second).Equal(deadline) || resolved.Previous != original.Previous || resolved.Target != original.Target || fresh.bootstraps != 1 || fresh.recovers != 0 {
		t.Fatal("old deadline/scope changed", err)
	}
}

func TestRoutedFreshScopeV3RejectsMissingMismatchedOrOccupiedProofBeforeEffects(t *testing.T) {
	for _, name := range []string{"missing", "wrong-old", "same-namespace", "wrong-receipt", "changed-preparation"} {
		t.Run(name, func(t *testing.T) {
			c, old := sharedBoundaryFixtureV3(t)
			boot := v2BootID(old.identity.BootID)
			c.options.BootID = &boot
			if err := c.bootStartupLocked(context.Background(), boot); err != nil {
				t.Fatal(err)
			}
			selectedBefore, err := c.store.readRecordV2("selected.json", 4096)
			if err != nil {
				t.Fatal(err)
			}
			fresh, proof := freshScopeAuthorityFixtureV3(t, c, old)
			switch name {
			case "missing":
				proof.denied = true
			case "wrong-old":
				proof.mutate = func(e *RoutedFreshScopeEvidenceV3) { e.Old.RunID = strings.Repeat("c", 32) }
			case "same-namespace":
				fresh.identity.Namespace = old.identity.Namespace
			case "wrong-receipt":
				proof.mutate = func(e *RoutedFreshScopeEvidenceV3) { e.ReceiptSHA256 = "unproven" }
			case "changed-preparation":
				proof.mutate = func(e *RoutedFreshScopeEvidenceV3) { e.Before = strings.Repeat("c", 64) }
			}
			if _, err := reopenFreshScopeFixtureV3(t, c, fresh, proof); err == nil {
				t.Fatal("unproven scope accepted")
			}
			if fresh.bootstraps != 0 || fresh.applies != 0 || fresh.arms != 0 || fresh.recovers != 0 {
				t.Fatal("effect before proof")
			}
			selectedAfter, err := c.store.readRecordV2("selected.json", 4096)
			if err != nil || string(selectedBefore) != string(selectedAfter) {
				t.Fatal("rejected scope changed selected metadata", err)
			}
		})
	}
}

func TestRoutedFreshScopeV3DHCPRetiresScopeWithoutClaimingWithdrawal(t *testing.T) {
	w, a := dhcpStoreFixtureV3(t)
	hash, err := w.Prepare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(context.Background(), hash); err != nil {
		t.Fatal(err)
	}
	old := a.grant.Snapshot.Identity
	fresh := &boundaryAuthorityFixtureV2{identity: old}
	fresh.identity.RunID = strings.Repeat("e", 32)
	fresh.identity.Namespace++
	f := &freshScopeFixtureV3{old: old, fresh: fresh, before: strings.Repeat("c", 64), deps: strings.Repeat("d", 64)}
	w.c.options.Routed, w.c.options.RoutedIdentity, w.c.options.FreshScope = fresh, fresh.identity, f
	if err = w.c.recoverRoutedDHCPAtOpenV3(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.withdrawCalls != 0 || a.state != networkexecutor.LeaseSelectedTargetV3 || w.c.store.state.RoutedDHCP != nil || w.c.store.state.RoutedDHCPLast == "" {
		t.Fatal("scope retirement misreported withdrawal")
	}
	var terminal v3RoutedDHCPState
	if err = w.c.store.readObject(w.c.store.state.RoutedDHCPLast, &terminal); err != nil || terminal.Phase != "scope_retired" || terminal.Retirement == nil {
		t.Fatal("terminal", err)
	}
	if err = w.c.store.verifyRoutedDHCPLastV3(); err != nil {
		t.Fatal("archive", err)
	}
}

func TestRoutedFreshScopeV3PendingOriginRetainsOriginalConfirmation(t *testing.T) {
	c, old, principal, cfg := boundaryCoordinatorFixtureV2(t)
	m := c.store.reserves
	c.store = sharedTestStoreV2(t, c.store)
	c.store.reserves = m
	c.options.SharedReader = c.store.access
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &cfg}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(90)
	origin, result, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err != nil {
		t.Fatal(err)
	}
	immutable := clone(result.Operation.Outcome)
	var previous v2Configuration
	if err = c.store.readObject(result.Current.Pending.Previous, &previous); err != nil {
		t.Fatal(err)
	}
	fresh, proof := freshScopeAuthorityFixtureV3(t, c, old)
	opened, err := reopenFreshScopeFixtureV3(t, c, fresh, proof)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := opened.store.lookupRetained(principal.Subject, origin.ID)
	if err != nil || retained.Pinned || !reflect.DeepEqual(retained.Outcome, immutable) || fresh.bootstraps != 1 || fresh.recovers != 0 {
		t.Fatal("pending origin changed", err)
	}
	if opened.store.state.Configuration.Running.Hash != previous.Running.Hash || fresh.current != previous.Running.Hash {
		t.Fatal("pending target was implicitly confirmed instead of rolled back")
	}
}

func TestRoutedFreshScopeV3ColdContinuationAfterDHCPRetirement(t *testing.T) {
	oldReader, c, old, w, dhcp := selectedDHCPReaderFixtureV3(t)
	ctx := context.Background()
	hash, err := w.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dhcp.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(ctx, hash); err != nil {
		t.Fatal(err)
	}
	fresh, proof := freshScopeAuthorityFixtureV3(t, c, old)
	options := oldReader.options
	options.Identity = fresh.identity
	r, err := NewRoutedSelectionReaderV2(oldReader.area, options)
	if err != nil {
		t.Fatal(err)
	}
	assembly, err := r.PrepareServiceRestartViewV3(ctx, old.identity)
	if err != nil || assembly.Target.Composite.Hash != c.store.state.Configuration.Running.Hash || assembly.Work != c.store.state.RoutedActive.Work {
		t.Fatal("selected assembly metadata", err)
	}
	wrongOld := old.identity
	wrongOld.RunID = strings.Repeat("f", 32)
	if _, err = r.PrepareServiceRestartViewV3(ctx, wrongOld); err == nil {
		t.Fatal("wrong receipt old identity accepted for assembly")
	}
	actionOptions := options
	actionOptions.Policy = SelectionActionAuthorityV2
	action, err := NewRoutedSelectionReaderV2(oldReader.area, actionOptions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = action.PrepareServiceRestartViewV3(ctx, old.identity); err == nil {
		t.Fatal("action-only reader issued service restart metadata")
	}
	if _, err = action.ResolveFreshScopeSourceV3(ctx, hash); err == nil {
		t.Fatal("action-only reader issued retirement source")
	}
	observations := 0
	if _, err = r.ObserveFreshScopeV3(ctx, hash, func(source RoutedFreshScopeSourceV3, view RoutedPrepareViewV2) error {
		observations++
		target, _ := source.PreparationBundles()
		if target.Composite.Hash != c.store.state.Configuration.Running.Hash || target.Composite.Hash == view.Startup.Composite.Hash {
			t.Fatal("helper preparation used Startup instead of selected Running")
		}
		return c.store.publish(clone(c.store.state))
	}); err == nil || observations != 1 {
		t.Fatal("selector changed during readonly observation was accepted", err)
	}
	anchor, err := r.CaptureColdAnchorV1(ctx)
	if err != nil {
		t.Fatal("attach", err)
	}
	source, err := r.ResolveFreshScopeSourceV3(ctx, hash)
	if err != nil || source.Identity() != old.identity {
		t.Fatal("selected old scope", err)
	}
	c.options.Routed, c.options.RoutedIdentity, c.options.FreshScope = fresh, fresh.identity, proof
	if err = c.recoverRoutedDHCPAtOpenV3(ctx); err != nil {
		t.Fatal("retire", err)
	}
	c.options.Hook = func(point string) error {
		if point == "after_boot_intent" {
			return ErrInterrupted
		}
		return nil
	}
	if err = c.bootStartupLocked(ctx, *c.options.BootID); !errors.Is(err, ErrInterrupted) {
		t.Fatal("select fresh boot", err)
	}
	plan, err := selectedRoutedPlanFromStoreV2(c.store, fresh.identity)
	if err != nil {
		t.Fatal(err)
	}
	if coldContinuationLinkedV1(anchor, plan, SelectionBootstrapV2) {
		t.Fatal("fixture did not cross retirement audit")
	}
	if _, err = r.ResolveColdContinuationV1(ctx, anchor, plan.Reference(), SelectionBootstrapV2); err != nil {
		t.Fatal("selected retirement continuation", err)
	}
	for _, purpose := range []RoutedSelectionPurposeV2{SelectionArmV2, SelectionApplyV2, SelectionRecoverV2} {
		if _, err = r.ResolveColdContinuationV1(ctx, anchor, plan.Reference(), purpose); err == nil {
			t.Fatal("ordinary/foreign action admitted", purpose)
		}
	}
}
