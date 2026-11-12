//go:build linux

package configpoc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func growReserveMetadataFixtureV2(t *testing.T, s *v2Store, subject string) {
	t.Helper()
	st := clone(s.state)
	for i := len(st.Namespaces); i < int(st.NamespaceSlots); i++ {
		raw, _, err := v2Canonical(st)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 128*1024+512 {
			break
		}
		st.Namespaces = append(st.Namespaces, v2Namespace{ID: fmt.Sprintf("v2.ns.%d.%s", i, strings.Repeat("a", 90)), Subject: subject, Domain: "firewall", AdmitUntil: st.Clock.Add(time.Hour), Closed: true, Open: []string{}})
		st.NamespaceSequence++
	}
	for i := len(st.Subjects); ; i++ {
		raw, _, err := v2Canonical(st)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 128*1024+512 {
			break
		}
		if i >= int(st.SubjectSlots) {
			t.Fatal("fixture cannot reach bounded profile cap")
		}
		st.Subjects = append(st.Subjects, v2Subject{ID: fmt.Sprintf("v2.subject.%d.%s", i, strings.Repeat("s", 100)), Login: fmt.Sprintf("fixture-%d-%s", i, strings.Repeat("u", 100)), CredentialRevision: checkpointDigest([]byte(fmt.Sprint(i))), Retired: true})
		st.SubjectSequence++
	}
	if err := s.publish(st); err != nil {
		data, _, _ := v2Canonical(st)
		core, _, _ := v2Canonical(reserveMetadataCoreV2(st))
		t.Fatalf("fixture publication: %v; state=%d core=%d valid=%v subjects=%d namespaces=%d", err, len(data), len(core), v2ValidState(st), len(st.Subjects), len(st.Namespaces))
	}
}

func TestReserveProfileRefusalPrecedesPhysicalClaim(t *testing.T) {
	c, _, engines, p, now := coordinatorV2Fixture(t, false)
	m := attachReserveManagerV2(t, c)
	ns, err := c.store.namespace(p.Subject, "firewall", *now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first := coordinatorV2Rule("already-accepted")
	if _, err = c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &first}, *now); err != nil {
		t.Fatal(err)
	}
	if _, err = c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &first}, *now); err != nil {
		t.Fatal(err)
	}
	growReserveMetadataFixtureV2(t, c.store, p.Subject)
	for _, engine := range engines {
		engine.reset()
	}
	config := coordinatorV2Rule("no-claim")
	_, err = c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config}, *now)
	if !errors.Is(err, errV2Limited) {
		t.Fatal("oversized profile admitted", err)
	}
	claim, err := m.admission.ClaimClass("profile-refusal-probe", recoveryreserve.OrdinaryV2)
	if err != nil || claim.Slot != 2 || claim.Epoch != 1 {
		t.Fatal("profile refusal consumed a physical claim", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 || engine.reads.Load() != 0 || engine.validations.Load() != 0 {
			t.Fatal("profile refusal touched engine")
		}
	}
}

func TestReserveProfileGrowthAfterACKFinalizesWithoutEffects(t *testing.T) {
	c, area, engines, p, now := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	ns, err := c.store.namespace(p.Subject, "firewall", *now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	config := coordinatorV2Rule("profile-growth")
	op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config}, *now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.store.admit(p.Subject, ns.ID, c.store.state.Generation, v2Request{Kind: OpStage, Config: &config}, *now); err != nil {
		t.Fatal(err)
	}
	growReserveMetadataFixtureV2(t, c.store, p.Subject)
	for _, engine := range engines {
		engine.reset()
	}
	result, err := c.execute(context.Background(), p, op.ID)
	if !errors.Is(err, errV2Limited) || result.Operation.State != "final" || result.Operation.Outcome.Code != "profile_changed_without_effects" || result.Operation.Reserve.Plan != nil || len(c.store.state.ActiveReserves) != 1 {
		t.Fatal("changed profile was applied or left ambiguous", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 || engine.reads.Load() != 0 || engine.validations.Load() != 0 {
			t.Fatal("profile rejection reached an engine")
		}
	}
	if err = c.store.closeNamespace(p.Subject, ns.ID, *now); err != nil {
		t.Fatal(err)
	}
	c.store.mu.Lock()
	err = c.store.reserves.maintain(c.store)
	c.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	c.close()
	_ = c.store.close()
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("without-effects finality not traceable", report, err)
	}
}

func TestReserveCOWCostIncludesDeepSplit(t *testing.T) {
	keys := []string{}
	for i := range 65 {
		keys = append(keys, fmt.Sprintf("%s%016x", strings.Repeat("a", 48), i))
	}
	// A terminal full prefix cannot be split: refusing it is part of the bound.
	if _, err := reserveIndexBuildCostV2(keys, 0); !errors.Is(err, errV2Limited) {
		t.Fatal("unbounded terminal split accepted", err)
	}
	keys = nil
	for i := range 65 {
		keys = append(keys, fmt.Sprintf("%x%063x", i%16, i))
	}
	sort.Strings(keys)
	count, err := reserveIndexBuildCostV2(keys, 0)
	if err != nil || count != 17 {
		t.Fatal("split node count omitted partitions", count, err)
	}
}
