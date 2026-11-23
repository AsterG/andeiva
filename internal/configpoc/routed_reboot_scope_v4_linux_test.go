//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

func TestRoutedRebootScopeV4ReadsInterruptedTransaction(t *testing.T) {
	for _, interrupted := range []string{OpCommit, "timeout"} {
		t.Run(interrupted, func(t *testing.T) {
			ctx := context.Background()
			c, old, principal, cfg := boundaryCoordinatorFixtureV2(t)
			original := sharedBoundaryReaderV2(t, c, old)
			if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &cfg}); err != nil {
				t.Fatal(err)
			}
			checkpoint := "after_intent"
			if interrupted == "timeout" {
				checkpoint = "after_recovery_intent"
			}
			c.options.Hook = func(point string) error {
				if point == checkpoint {
					return ErrInterrupted
				}
				return nil
			}
			seconds := uint64(90)
			_, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			if interrupted == "timeout" {
				if err != nil {
					t.Fatal(err)
				}
				err = c.revertLocked(ctx, "timeout")
			}
			if !errors.Is(err, ErrInterrupted) {
				t.Fatal("expected a selected interrupted transaction", err)
			}
			state := c.store.state.Configuration
			work := state.Intent.RoutedWork
			if !validHash(work) {
				t.Fatal("interrupted operation does not have a selected work reference")
			}
			fresh := freshBoundaryAuthorityV2(old)
			options := original.options
			options.Identity = fresh.identity
			r, err := NewRoutedSelectionReaderV2(original.area, options)
			if err != nil {
				t.Fatal(err)
			}
			view, err := r.PrepareRebootScopeViewV4(ctx, old.identity)
			if err != nil || view.Work != work || view.Target.Composite.Hash != state.Startup.Hash {
				t.Fatal("reboot reader did not identify the exact work and saved Startup", err)
			}
			call := false
			if _, err = r.ObserveRebootScopeV4(ctx, strings.Repeat("d", 64), func(RoutedFreshScopeSourceV3, RoutedPrepareViewV2) error { call = true; return nil }); err == nil || call {
				t.Fatal("unselected work reached the proof callback", err)
			}
			options.Identity.BootID, options.Identity.Host = old.identity.BootID, old.identity.Host
			hot, err := NewRoutedSelectionReaderV2(original.area, options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = hot.PrepareRebootScopeViewV4(ctx, old.identity); err == nil {
				t.Fatal("same-boot restart got a reboot view")
			}
			if _, err = hot.PrepareServiceRestartViewV3(ctx, old.identity); err == nil {
				t.Fatal("service restart accepted a durable interrupted transaction")
			}
		})
	}
}

// Physical authority is explicitly doubled. Selected files, G1/R2, retained
// work, archive/CAS, and coordinator open are real; this is not native reboot.
type rebootScopeFixtureV4 struct {
	proof  RoutedRebootScopeEvidenceV4
	calls  int
	mutate func(*RoutedRebootScopeEvidenceV4)
}

func TestRoutedRebootScopeV4FullReaderRejectsCorruptSelectedHistory(t *testing.T) {
	oldReader, c, old, _, _ := selectedDHCPReaderFixtureV3(t)
	fresh, _ := rebootAuthorityFixtureV4(t, c, old)
	options := oldReader.options
	options.Identity = fresh.identity
	r, err := NewRoutedSelectionReaderV2(oldReader.area, options)
	if err != nil {
		t.Fatal(err)
	}
	name, err := v2ObjectName(c.store.state.Configuration.AuditTip)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.store.root.Name(), name), []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if _, err = r.ObserveRebootScopeV4(context.Background(), c.store.state.RoutedActive.Work, func(RoutedFreshScopeSourceV3, RoutedPrepareViewV2) error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatal("receipt path bypassed corrupt G1", err)
	}
}

func TestRoutedRebootScopeV4PendingKeepsOriginalUTCDeadline(t *testing.T) {
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
	startup := result.Current.Startup.Hash
	fresh, proof := rebootAuthorityFixtureV4(t, c, old)
	opened, err := reopenRebootFixtureV4(t, c, fresh, proof)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := opened.store.lookupRetained(principal.Subject, origin.ID)
	if err != nil || retained.Pinned || !reflect.DeepEqual(retained.Outcome, immutable) || fresh.current != startup || fresh.recovers != 0 {
		t.Fatal("reboot changed pending outcome/deadline", err)
	}
}

func (f *rebootScopeFixtureV4) ProveRebootScope(_ context.Context, work string) (RoutedRebootScopeEvidenceV4, error) {
	f.calls++
	p := f.proof
	p.Work = work
	if f.mutate != nil {
		f.mutate(&p)
	}
	return p, nil
}

func rebootAuthorityFixtureV4(t *testing.T, c *v2Coordinator, old *boundaryAuthorityFixtureV2) (*boundaryAuthorityFixtureV2, *rebootScopeFixtureV4) {
	t.Helper()
	a := freshBoundaryAuthorityV2(old)
	// Kernel inode numbers can repeat after a real OS boot.
	a.identity.Namespace, a.identity.Host = old.identity.Namespace, old.identity.Host
	target, err := NewRoutedActivationBundleV1(c.store.state.Configuration.Firewall.Startup, c.store.state.Configuration.LocalServices.Startup)
	if err != nil {
		t.Fatal(err)
	}
	saved := target
	if target.Firewall.Config.SchemaVersion != 4 {
		p, e := loadRoutedWorkV2(c.store.state.RoutedActive.Work, c.store.state.Lineage, c.store.readObject)
		if e != nil {
			t.Fatal(e)
		}
		saved = p.Baseline().Saved
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
	f := &rebootScopeFixtureV4{proof: RoutedRebootScopeEvidenceV4{Version: 4, Old: old.identity, New: a.identity, ReceiptSHA256: strings.Repeat("a", 64), MetadataSHA256: strings.Repeat("b", 64), DrainedAtOldBootNS: int64(30 * 24 * time.Hour), ObservedAtNewBootNS: 1, Before: before, Dependencies: deps}}
	return a, f
}

func reopenRebootFixtureV4(t *testing.T, c *v2Coordinator, a *boundaryAuthorityFixtureV2, f *rebootScopeFixtureV4) (*v2Coordinator, error) {
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
	opts.FreshScope = nil
	opts.RebootScope = f
	opts.Routed = a
	opts.RoutedIdentity = a.identity
	opts.Hook = nil
	b := v2BootID(a.identity.BootID)
	opts.BootID = &b
	opened, err := openCoordinatorV2(context.Background(), s, c.firewall, c.local, opts)
	t.Cleanup(func() {
		if opened != nil {
			opened.close()
		}
		_ = s.close()
	})
	return opened, err
}

func TestRoutedRebootScopeV4RetiresDHCPBeforeLANBootWithoutOldClockReuse(t *testing.T) {
	oldReader, c, old, w, dhcp := selectedDHCPReaderFixtureV3(t)
	ctx := context.Background()
	principal := v2TrustedPrincipal{Subject: "durable-subject", Role: RoleAdmin}
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpSave}); err != nil {
		t.Fatal(err)
	}
	startup := c.store.state.Configuration.Startup.Hash
	hash, err := w.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dhcp.state = networkexecutor.LeaseSelectedTargetV3
	if err = w.Applied(ctx, hash); err != nil {
		t.Fatal(err)
	}
	original, err := loadRoutedDHCPWorkV3(hash, c.store.state.Lineage, c.store.readObject)
	if err != nil {
		t.Fatal(err)
	}
	fresh, proof := rebootAuthorityFixtureV4(t, c, old)
	options := oldReader.options
	options.Identity = fresh.identity
	r, err := NewRoutedSelectionReaderV2(oldReader.area, options)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := r.PrepareRebootScopeViewV4(ctx, old.identity)
	if err != nil || metadata.Target.Composite.Hash != startup || metadata.Work != hash {
		t.Fatal("reboot assembly", err)
	}
	if _, err = r.PrepareServiceRestartViewV3(ctx, old.identity); err == nil {
		t.Fatal("v3 accepted another boot")
	}
	wrong := old.identity
	wrong.RunID = strings.Repeat("f", 32)
	if _, err = r.PrepareRebootScopeViewV4(ctx, wrong); err == nil {
		t.Fatal("stale receipt identity accepted")
	}
	anchor, err := r.CaptureColdAnchorV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := reopenRebootFixtureV4(t, c, fresh, proof)
	if err != nil {
		t.Fatal("reboot open", err)
	}
	st := opened.store.state
	if st.RoutedDHCP != nil || st.RoutedDHCPLast == "" || !hasFeatureV2(st, v4RoutedRebootScopeFeature) || st.Configuration.Running.Hash != startup || fresh.bootstraps != 1 || dhcp.withdrawCalls != 0 {
		t.Fatal("old DHCP was adopted or retirement omitted")
	}
	var terminal v3RoutedDHCPState
	if opened.store.readObject(st.RoutedDHCPLast, &terminal) != nil || terminal.Phase != "scope_retired" || terminal.Retirement != nil || terminal.RebootRetirement == nil || terminal.Work != hash {
		t.Fatal("wrong terminal semantics")
	}
	retained, err := loadRoutedDHCPWorkV3(hash, st.Lineage, opened.store.readObject)
	if err != nil || !reflect.DeepEqual(original, retained) {
		t.Fatal("old grant/deadline changed", err)
	}
	p, err := loadRoutedWorkV2(st.RoutedActive.Work, st.Lineage, opened.store.readObject)
	if err != nil || p.RebootScopeEvidenceV4() == nil || p.FreshScopeEvidenceV3() != nil || p.preparation.Before.Version != 3 || p.target.Composite.Hash != startup {
		t.Fatal("new boot plan", err)
	}
	if _, err = r.ResolveColdContinuationV1(ctx, anchor, p.Reference(), SelectionResumeV2); err != nil {
		t.Fatal("retirement anchor continuation", err)
	}
}

func TestRoutedRebootScopeV4UsesStartupInsteadOfRunning(t *testing.T) {
	_, c, old, _, _ := selectedDHCPReaderFixtureV3(t)
	before := clone(*c.store.state.Configuration)
	if before.Running.Hash == before.Startup.Hash {
		t.Fatal("fixture must differ")
	}
	fresh, proof := rebootAuthorityFixtureV4(t, c, old)
	opened, err := reopenRebootFixtureV4(t, c, fresh, proof)
	if err != nil {
		t.Fatal(err)
	}
	if opened.store.state.Configuration.Running.Hash != before.Startup.Hash || fresh.current != before.Startup.Hash {
		t.Fatal("OS reboot retained unsaved Running")
	}
}

func TestRoutedRebootScopeV4RejectsUnprovenScopeWithoutEffects(t *testing.T) {
	for _, name := range []string{"same-boot", "stale-old", "wrong-new", "wrong-receipt", "changed-preparation"} {
		t.Run(name, func(t *testing.T) {
			c, old := sharedBoundaryFixtureV3(t)
			b := v2BootID(old.identity.BootID)
			c.options.BootID = &b
			if err := c.bootStartupLocked(context.Background(), b); err != nil {
				t.Fatal(err)
			}
			fresh, proof := rebootAuthorityFixtureV4(t, c, old)
			proof.mutate = func(p *RoutedRebootScopeEvidenceV4) {
				switch name {
				case "same-boot":
					p.New.BootID = p.Old.BootID
				case "stale-old":
					p.Old.RunID = strings.Repeat("e", 32)
				case "wrong-new":
					p.New.Namespace++
				case "wrong-receipt":
					p.ReceiptSHA256 = "unverified"
				case "changed-preparation":
					p.Before = strings.Repeat("c", 64)
				}
			}
			before, err := c.store.readRecordV2("selected.json", 4096)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = reopenRebootFixtureV4(t, c, fresh, proof); err == nil {
				t.Fatal("unproven reboot accepted")
			}
			after, err := c.store.readRecordV2("selected.json", 4096)
			if err != nil || string(before) != string(after) || fresh.applies != 0 || fresh.bootstraps != 0 || fresh.arms != 0 || fresh.recovers != 0 {
				t.Fatal("rejection changed metadata/effects", err)
			}
		})
	}
}

func TestRoutedRebootScopeV4ClockDomainsAndV3RemainSeparate(t *testing.T) {
	c, old := sharedBoundaryFixtureV3(t)
	_, f := rebootAuthorityFixtureV4(t, c, old)
	p := f.proof
	p.Work = strings.Repeat("c", 64)
	for _, oldTime := range []int64{1, 1 << 62} {
		for _, newTime := range []int64{1, 1 << 61} {
			p.DrainedAtOldBootNS, p.ObservedAtNewBootNS = oldTime, newTime
			if !ValidRoutedRebootScopeEvidenceV4(p) {
				t.Fatal("unrelated boot clocks compared")
			}
		}
	}
	p.New.BootID = p.Old.BootID
	if ValidRoutedRebootScopeEvidenceV4(p) {
		t.Fatal("v4 admitted same BootID")
	}
}

func bootAttestedFixtureV4(f *rebootScopeFixtureV4) {
	f.mutate = func(p *RoutedRebootScopeEvidenceV4) { p.BootAttested, p.DrainedAtOldBootNS = true, 0 }
}

func TestRoutedRebootScopeV4BootAttestedEvidenceNeverClaimsADrain(t *testing.T) {
	c, old := sharedBoundaryFixtureV3(t)
	_, f := rebootAuthorityFixtureV4(t, c, old)
	p := f.proof
	p.Work = strings.Repeat("c", 64)
	if !ValidRoutedRebootScopeEvidenceV4(p) {
		t.Fatal("drain receipt evidence refused")
	}
	p.BootAttested = true
	if ValidRoutedRebootScopeEvidenceV4(p) {
		t.Fatal("boot attestation carried a drain time")
	}
	p.DrainedAtOldBootNS = 0
	if !ValidRoutedRebootScopeEvidenceV4(p) {
		t.Fatal("boot attestation refused")
	}
	p.BootAttested = false
	if ValidRoutedRebootScopeEvidenceV4(p) {
		t.Fatal("receipt evidence without a drain time accepted")
	}
	p.BootAttested, p.DrainedAtOldBootNS = true, -1
	if ValidRoutedRebootScopeEvidenceV4(p) {
		t.Fatal("negative drain time accepted")
	}
	p.DrainedAtOldBootNS = 0
	p.New.BootID = p.Old.BootID
	if ValidRoutedRebootScopeEvidenceV4(p) {
		t.Fatal("boot attestation admitted the same BootID")
	}
	receipt, attested := f.proof, f.proof
	receipt.Work, attested.Work = p.Work, p.Work
	attested.BootAttested, attested.DrainedAtOldBootNS = true, 0
	a, validA := compareScopeV4(nil, &receipt)
	b, validB := compareScopeV4(nil, &attested)
	if !validA || !validB || a == b || a.attested || !b.attested {
		t.Fatal("attested and drained evidence compare as equal")
	}
}

func TestRoutedRebootScopeV4BootAttestedPendingSelectsStartupAndDeclaresFeature(t *testing.T) {
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
	startup := result.Current.Startup.Hash
	fresh, proof := rebootAuthorityFixtureV4(t, c, old)
	bootAttestedFixtureV4(proof)
	opened, err := reopenRebootFixtureV4(t, c, fresh, proof)
	if err != nil {
		t.Fatal(err)
	}
	st := opened.store.state
	retained, err := opened.store.lookupRetained(principal.Subject, origin.ID)
	if err != nil || retained.Pinned || !reflect.DeepEqual(retained.Outcome, immutable) || fresh.current != startup || fresh.recovers != 0 || st.Configuration.Running.Hash != startup || st.Configuration.Pending != nil || st.Configuration.Intent != nil {
		t.Fatal("attested boot did not select Startup or changed the original outcome", err)
	}
	if !hasFeatureV2(st, v4RoutedBootAttestationFeature) || !hasFeatureV2(st, v4RoutedRebootScopeFeature) {
		t.Fatal("attested evidence was persisted without its required features")
	}
	p, err := loadRoutedWorkV2(st.RoutedActive.Work, st.Lineage, opened.store.readObject)
	if err != nil || p.RebootScopeEvidenceV4() == nil || !p.RebootScopeEvidenceV4().BootAttested || p.RebootScopeEvidenceV4().DrainedAtOldBootNS != 0 {
		t.Fatal("selected boot plan does not carry the attested evidence", err)
	}
	// A reader that does not know the attested shape must refuse the store.
	legacy := clone(st)
	var features []string
	for _, feature := range legacy.RequiredFeatures {
		if feature != v4RoutedBootAttestationFeature {
			features = append(features, feature)
		}
	}
	legacy.RequiredFeatures = features
	if rebootScopeDeclaredV4(legacy, p.RebootScopeEvidenceV4()) || !rebootScopeDeclaredV4(st, p.RebootScopeEvidenceV4()) {
		t.Fatal("attested evidence accepted without its declared feature")
	}
	orphan := clone(st)
	features = nil
	for _, feature := range orphan.RequiredFeatures {
		if feature != v4RoutedRebootScopeFeature {
			features = append(features, feature)
		}
	}
	orphan.RequiredFeatures = features
	if validFeaturesV2(orphan) || !validFeaturesV2(st) {
		t.Fatal("attestation feature accepted without the reboot scope feature")
	}
}

func TestRoutedRebootScopeV4RetiredScopeViewRequiresARecordedScope(t *testing.T) {
	oldReader, c, old, _, _ := selectedDHCPReaderFixtureV3(t)
	ctx := context.Background()
	fresh, _ := rebootAuthorityFixtureV4(t, c, old)
	options := oldReader.options
	options.Identity = fresh.identity
	r, err := NewRoutedSelectionReaderV2(oldReader.area, options)
	if err != nil {
		t.Fatal(err)
	}
	earlier := old.identity
	earlier.BootID, earlier.RunID = "92345678-1234-1234-1234-123456789abc", strings.Repeat("e", 32)
	single, err := r.PrepareRebootScopeViewV4(ctx, old.identity)
	if err != nil {
		t.Fatal(err)
	}
	among, err := r.PrepareRetiredScopeViewV4(ctx, []networkexecutor.OwnedNamespaceIdentity{earlier, old.identity})
	if err != nil || !reflect.DeepEqual(single, among) {
		t.Fatal("recorded scope was not selected among the retired scopes", err)
	}
	if _, err = r.PrepareRetiredScopeViewV4(ctx, []networkexecutor.OwnedNamespaceIdentity{earlier}); err == nil {
		t.Fatal("store scope missing from the root record was accepted")
	}
	if _, err = r.PrepareRetiredScopeViewV4(ctx, nil); err == nil {
		t.Fatal("empty root record accepted")
	}
	running := fresh.identity
	running.RunID = strings.Repeat("d", 32)
	if _, err = r.PrepareRetiredScopeViewV4(ctx, []networkexecutor.OwnedNamespaceIdentity{old.identity, running}); err == nil {
		t.Fatal("scope of the running boot accepted as retired")
	}
}
