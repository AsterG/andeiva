//go:build linux

package configpoc

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRoutedBootTargetPreservesStaleCandidateWithoutRebasing(t *testing.T) {
	c, _, principal := routedCoordinatorFixtureV2(t)
	document, objects := compositeRoutedFixture(t, true)
	firewall := objects[document.Domains.Firewall.Revision]
	state := clone(*c.store.state.Configuration)
	state.Firewall.Running, state.Firewall.LastGood = firewall, firewall
	if err := state.refresh(); err != nil {
		t.Fatal(err)
	}
	op := v2Operation{ID: "candidate-operation", Subject: principal.Subject, Domain: "routed", Request: v2Request{Kind: OpStage, Config: &firewall.Config}}
	staged, _, err := routedTargetV2(c.store, op, state, c.now(), "")
	if err != nil {
		t.Fatal(err)
	}
	originalGroup, originalFirewall, originalLocal := clone(staged.CandidateGroup), clone(staged.Firewall.Candidate), clone(staged.LocalServices.Candidate)
	target, err := bootTargetV2(staged)
	if err != nil || !validV2Configuration(&target) {
		t.Fatal("boot target", err)
	}
	if target.Running.Hash != target.Startup.Hash || target.LastGood.Hash != target.Startup.Hash {
		t.Fatal("boot did not select complete Startup")
	}
	if !reflect.DeepEqual(target.CandidateGroup, originalGroup) || !reflect.DeepEqual(target.Firewall.Candidate, originalFirewall) || !reflect.DeepEqual(target.LocalServices.Candidate, originalLocal) {
		t.Fatal("boot dropped or rebased a candidate")
	}
	if target.CandidateGroup.Base == target.Running.Hash {
		t.Fatal("fixture did not produce stale base")
	}
	for _, kind := range []string{OpValidate, OpCommit} {
		op.Request = v2Request{Kind: kind}
		if kind == OpCommit {
			seconds := uint64(30)
			op.Request.ConfirmSeconds = &seconds
		}
		if _, _, err = routedTargetV2(c.store, op, target, c.now(), "confirmed-lease"); !errors.Is(err, ErrConflict) {
			t.Fatal("stale candidate accepted after Startup recovery", kind, err)
		}
	}
}

func TestRoutedBootRecordDeadlineIsOriginalAndExact(t *testing.T) {
	work, _, _ := routedWorkFixtureV2(t)
	work.Kind = v2BootKind
	id := v2BootID(work.Scope.Identity.BootID)
	started := work.Deadline.Add(-10 * time.Second)
	original := v2RecoveryRecord{Format: v2Format, ID: work.Operation, Kind: v2BootKind, State: "pending", Previous: work.Transition.Previous, Target: work.Transition.Target, Lineage: work.Lineage, BootID: &id, Started: started, Pinned: true}
	plan := RoutedSelectedPlanV1{work: work, bootRecord: &original}
	if !routedBootRecordMatchesV2(plan, original) {
		t.Fatal("original deadline rejected")
	}
	changed := original
	changed.Started = changed.Started.Add(time.Nanosecond)
	if routedBootRecordMatchesV2(plan, changed) {
		t.Fatal("renewed deadline accepted")
	}
	changed = original
	changed.Target = changed.Previous
	if routedBootRecordMatchesV2(plan, changed) {
		t.Fatal("foreign boot target accepted")
	}
}
