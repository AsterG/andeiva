//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRoutedOwnedCandidateReplaceDiscardPreservesAppliedAndAudit(t *testing.T) {
	c, engines, p := routedCoordinatorFixtureV2(t)
	doc, objects := compositeRoutedFixture(t, true)
	config := objects[doc.Domains.Firewall.Revision].Config
	stage, staged, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	before := clone(staged.Current)
	for _, engine := range engines {
		engine.reset()
	}
	request := v2Request{Kind: OpReplaceCandidate, Config: &config, ExpectedCandidateStage: stage.ID}
	replaced, result, err := routedRequestV2(t, c, p, request)
	if err != nil {
		t.Fatal("replace", err)
	}
	if result.Current.CandidateGroup.Operation != replaced.ID || !reflect.DeepEqual(before.LocalServices.Candidate.Revision, result.Current.LocalServices.Candidate.Revision) || result.Current.Running.Hash != before.Running.Hash || result.Current.Startup.Hash != before.Startup.Hash {
		t.Fatal("replacement changed applied configuration/local candidate")
	}
	if !hasFeatureV2(c.store.state, v2OwnedCandidateFeature) || validateCandidateGroupEvidenceV2(result.Current, c.store.readObject) != nil {
		t.Fatal("replacement lacks selected feature/audit evidence")
	}
	selector, used := c.store.selector, c.store.used
	replay, err := c.execute(context.Background(), p, replaced.ID)
	if err != nil || !reflect.DeepEqual(replay.Operation.Outcome, result.Operation.Outcome) || c.store.selector != selector || c.store.used != used {
		t.Fatal("exact replay changed storage", err)
	}
	_, discarded, err := routedRequestV2(t, c, p, v2Request{Kind: OpDiscardCandidate, ExpectedCandidateStage: replaced.ID})
	if err != nil || discarded.Current.CandidateGroup != nil || discarded.Current.Firewall.Candidate != nil || discarded.Current.LocalServices.Candidate != nil || discarded.Current.Running.Hash != before.Running.Hash || discarded.Current.Startup.Hash != before.Startup.Hash {
		t.Fatal("discard", err)
	}
	if _, err = c.store.lookupRetained(p.Subject, stage.ID); err != nil {
		t.Fatal("discard removed original operation", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("metadata applied engine")
		}
	}
}

func TestRoutedOwnedCandidateGuardsAndStageRemainsStrict(t *testing.T) {
	c, _, p := routedCoordinatorFixtureV2(t)
	doc, objects := compositeRoutedFixture(t, true)
	config := objects[doc.Domains.Firewall.Revision].Config
	stage, result, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
	if err != nil {
		t.Fatal(err)
	}
	state := result.Current
	op := v2Operation{ID: "replacement-operation", Subject: p.Subject, Domain: "routed", Request: v2Request{Kind: OpReplaceCandidate, Config: &config, ExpectedCandidateStage: stage.ID}}
	for name, mutate := range map[string]func(*v2Operation, *v2Configuration){
		"foreign_owner": func(o *v2Operation, _ *v2Configuration) { o.Subject = "another-subject" },
		"wrong_stage":   func(o *v2Operation, _ *v2Configuration) { o.Request.ExpectedCandidateStage = "another-stage" },
		"incomplete":    func(_ *v2Operation, s *v2Configuration) { s.LocalServices.Candidate = nil },
		"pending":       func(_ *v2Operation, s *v2Configuration) { s.Pending = &v2Confirmation{} },
		"intent":        func(_ *v2Operation, s *v2Configuration) { s.Intent = &v2CoordinatorIntent{} },
		"recovery":      func(_ *v2Operation, s *v2Configuration) { s.RecoveryRequired = true },
	} {
		t.Run(name, func(t *testing.T) {
			o, s := clone(op), clone(state)
			mutate(&o, &s)
			if _, _, err := routedTargetV2(c.store, o, s, c.now(), ""); !errors.Is(err, ErrConflict) {
				t.Fatal("guard", err)
			}
		})
	}
	stageAgain := op
	stageAgain.Request = v2Request{Kind: OpStage, Config: &config}
	if _, _, err = routedTargetV2(c.store, stageAgain, state, c.now(), ""); !errors.Is(err, ErrConflict) {
		t.Fatal("Stage silently replaced candidate", err)
	}
	localChanged := clone(state)
	localConfig := clone(localChanged.LocalServices.Candidate.Revision.Config)
	if len(localConfig.LocalServices.Services) == 0 {
		t.Fatal("local access fixture empty")
	}
	localConfig.LocalServices.Services[0].Enabled = !localConfig.LocalServices.Services[0].Enabled
	localChanged.LocalServices.Candidate.Revision, err = Canonical(localConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = routedTargetV2(c.store, op, localChanged, c.now(), ""); !errors.Is(err, ErrDenied) {
		t.Fatal("replacement bypassed local recovery proof", err)
	}
	discard := clone(op)
	discard.Request = v2Request{Kind: OpDiscardCandidate, ExpectedCandidateStage: stage.ID}
	if discarded, _, err := routedTargetV2(c.store, discard, localChanged, c.now(), ""); err != nil || discarded.LocalServices.Candidate != nil {
		t.Fatal("discard could not remove unapplied local changes", err)
	}
	stale := clone(state)
	// Deliberately capture an obsolete base; only this explicit replacement may
	// create new bases, while validation of the old group remains forbidden.
	stale.CandidateGroup.Base = checkpointDigest([]byte("previous-running"))
	stale.Firewall.Candidate.Base = checkpointDigest([]byte("previous-firewall"))
	replaced, _, err := routedTargetV2(c.store, op, stale, c.now(), "")
	if err != nil || replaced.CandidateGroup.Base != stale.Running.Hash || replaced.Firewall.Candidate.Base != stale.Firewall.Running.Hash {
		t.Fatal("explicit stale replacement", err)
	}
	ns, err := c.store.namespace(p.Subject, "routed", c.now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	expected := c.store.state.Generation
	a, err := c.store.admit(p.Subject, ns.ID, expected, op.Request, c.now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.store.admit(p.Subject, ns.ID, expected, op.Request, c.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.execute(context.Background(), p, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = c.execute(context.Background(), p, b.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("second CAS writer accepted", err)
	}
}

func TestRoutedOwnedCandidateRequestBoundaryAndLegacyBytes(t *testing.T) {
	doc, objects := compositeRoutedFixture(t, true)
	config := objects[doc.Domains.Firewall.Revision].Config
	for _, r := range []v2Request{{Kind: OpReplaceCandidate, Config: &config}, {Kind: OpDiscardCandidate}, {Kind: OpDiscardCandidate, ExpectedCandidateStage: "stage", Config: &config}, {Kind: OpStage, Config: &config, ExpectedCandidateStage: "stage"}} {
		if v2RequestValid("routed", r) {
			t.Fatal("invalid request accepted", r.Kind)
		}
	}
	for _, kind := range []string{OpReplaceCandidate, OpDiscardCandidate} {
		r := v2Request{Kind: kind, ExpectedCandidateStage: "stage"}
		if kind == OpReplaceCandidate {
			r.Config = &config
		}
		if !v2RequestValid("routed", r) || v2RequestValid("firewall", r) || v2RequestValid("local_services", r) {
			t.Fatal("domain boundary", kind)
		}
	}
	raw, err := json.Marshal(v2Request{Kind: OpValidate})
	if err != nil || string(raw) != `{"kind":"validate"}` {
		t.Fatal("legacy encoding changed", string(raw), err)
	}
}

func TestRoutedOwnedCandidateInterruptedIntentRecoversWithoutEffects(t *testing.T) {
	for _, kind := range []string{OpReplaceCandidate, OpDiscardCandidate} {
		t.Run(kind, func(t *testing.T) {
			c, engines, p := routedCoordinatorFixtureV2(t)
			doc, objects := compositeRoutedFixture(t, true)
			config := objects[doc.Domains.Firewall.Revision].Config
			stage, staged, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &config})
			if err != nil {
				t.Fatal(err)
			}
			for _, engine := range engines {
				engine.reset()
			}
			request := v2Request{Kind: kind, ExpectedCandidateStage: stage.ID}
			if kind == OpReplaceCandidate {
				request.Config = &config
			}
			c.options.Hook = func(point string) error {
				if point == "after_intent" {
					return ErrInterrupted
				}
				return nil
			}
			op, _, err := routedRequestV2(t, c, p, request)
			if !errors.Is(err, ErrInterrupted) {
				t.Fatal("missing interruption", err)
			}
			if c.store.state.Configuration.Intent == nil || c.store.state.Configuration.CandidateGroup.Operation != stage.ID {
				t.Fatal("unselected candidate published")
			}
			reopened, err := reopenCoordinatorV2(t, c, c.store.root)
			if err != nil {
				t.Fatal("reopen", err)
			}
			selected := reopened.store.state.Configuration
			if selected.Intent != nil || selected.RecoveryRequired || selected.Running.Hash != staged.Current.Running.Hash || selected.Startup.Hash != staged.Current.Startup.Hash {
				t.Fatal("interrupted metadata changed applied state")
			}
			retained, err := reopened.store.lookupRetained(p.Subject, op.ID)
			if err != nil || retained.State != "final" {
				t.Fatal("interrupted operation not final", err)
			}
			for _, engine := range engines {
				if engine.applies.Load() != 0 {
					t.Fatal("recovery applied independent engine")
				}
			}
		})
	}
}
