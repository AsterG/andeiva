//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func TestGuardDeadlineLegacyIntentGolden(t *testing.T) {
	in := v2CoordinatorIntent{Operation: "op", Subject: "subject", Domain: "firewall", Kind: OpCommit, Previous: strings.Repeat("a", 64), Target: strings.Repeat("b", 64), TargetGeneration: 1}
	golden := `{"operation_id":"op","subject":"subject","domain":"firewall","kind":"commit","previous_snapshot":"` + strings.Repeat("a", 64) + `","target_snapshot":"` + strings.Repeat("b", 64) + `","target_generation":"1","recovery":false}`
	data, hash, err := v2Canonical(in)
	if err != nil || string(data) != golden || hash != checkpointDigest([]byte(golden)) {
		t.Fatal("legacy intent bytes/hash changed", err, string(data))
	}
}

func TestGuardDeadlineActualReserveArchiveAndReachability(t *testing.T) {
	c, area, _, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	c.options.GuardDeadlines = true
	c.store.guardDeadlines = true
	coordinatorV2Stage(t, c, p, "archived-deadline")
	zero := uint64(0)
	result := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	bundle := result.Operation.Reserve
	if bundle == nil || bundle.PlanIntent == nil || bundle.PlanIntent.GuardDeadline == nil {
		t.Fatal("canonical plan lost deadline")
	}
	for range 2 {
		if err := c.store.publish(c.store.state); err != nil {
			t.Fatal(err)
		}
	}
	entry := v2ReserveArchiveEntry{Claim: bundle.Plan.Claim, Binding: bundle.Plan, Scope: bundle.PlanScope}
	archive, found, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, entry, "binding")
	if err != nil || !found || validateArchiveFinalityV2(archive, c.store.state, c.store.readObject) != nil {
		t.Fatal("deadline archive invalid", err, found)
	}
	without := clone(c.store.state)
	without.RequiredFeatures = nil
	if validateArchiveGuardDeadlinesV2(archive, without, c.store.readObject) == nil {
		t.Fatal("archived deadline accepted without feature")
	}
	for _, record := range archive.Entries {
		if record.Claim.Role != recoveryreserve.PlanV2 || record.Binding == nil {
			continue
		}
		var plan v2ReservePlan
		if json.Unmarshal(record.Raw, &plan) != nil {
			t.Fatal("plan")
		}
		if plan.Intent.GuardDeadline != nil && !plan.Intent.GuardDeadline.Equal(*bundle.PlanIntent.GuardDeadline) {
			t.Fatal("archive changed exact deadline")
		}
	}
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	if report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2()); err != nil || !report.Complete {
		t.Fatal("deadline typed graph incomplete", err, report)
	}
}

func TestGuardDeadlineColdOptInRejectsLegacyIntent(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	coordinatorV2Stage(t, c, p, "legacy-intent")
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return ErrInterrupted
		}
		return nil
	}
	zero := uint64(0)
	_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	c.close()
	for _, e := range engines {
		e.reset()
	}
	options := c.options
	options.Hook = nil
	options.GuardDeadlines = true
	if opened, err := openCoordinatorV2(context.Background(), c.store, c.firewall, c.local, options); !errors.Is(err, ErrRecovery) {
		if opened != nil {
			opened.close()
		}
		t.Fatal("legacy intent acquired invented deadline", err)
	}
	for _, e := range engines {
		if e.applies.Load() != 0 || e.reads.Load() != 0 || e.validations.Load() != 0 {
			t.Fatal("cold refusal executed engine")
		}
	}
}

func TestGuardDeadlineFeatureAndExclusiveSources(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, false)
	coordinatorV2Stage(t, c, p, "guard-shape")
	zero := uint64(0)
	c.options.GuardDeadlines = true
	c.store.guardDeadlines = true
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return ErrInterrupted
		}
		return nil
	}
	_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	st := clone(c.store.state)
	in := st.Configuration.Intent
	if in == nil || in.GuardDeadline == nil || !validFeaturesV2(st) {
		t.Fatal("opt-in missing")
	}
	without := clone(st)
	without.RequiredFeatures = nil
	if validFeaturesV2(without) || preservesFeaturesV2(st, without) {
		t.Fatal("feature downgraded")
	}
	for _, delta := range []time.Duration{-time.Nanosecond, time.Nanosecond} {
		changed := clone(st)
		d := changed.Configuration.Intent.GuardDeadline.Add(delta)
		changed.Configuration.Intent.GuardDeadline = &d
		if preservesFeaturesV2(st, changed) {
			t.Fatal("selected deadline replaced")
		}
		selected, used := c.store.selector, c.store.used
		if err := c.store.publish(changed); err == nil || c.store.selector != selected || c.store.used != used || c.store.blocked {
			t.Fatal("deadline replacement publication", err)
		}
	}
	var previous, target v2Configuration
	foreign := clone(st)
	foreign.Configuration.Intent.Operation = "different-operation"
	if preservesFeaturesV2(st, foreign) {
		t.Fatal("unresolved deadline changed operation identity")
	}
	if c.store.readObject(in.Previous, &previous) != nil || c.store.readObject(in.Target, &target) != nil {
		t.Fatal("snapshot")
	}
	bad := clone(*in)
	bad.Recovery = true
	if validGuardDeadlineShapeV2(&bad) {
		t.Fatal("recovery acquired duplicate source")
	}
	bad = clone(*in)
	bad.Kind = v2BootKind
	if validGuardDeadlineShapeV2(&bad) {
		t.Fatal("Boot acquired duplicate source")
	}
	target.Pending = &v2Confirmation{Deadline: *in.GuardDeadline}
	if validateGuardDeadlineContextV2(in, previous, target, true, true) == nil {
		t.Fatal("Pending acquired duplicate deadline")
	}
}

func TestGuardDeadlineNoOptInClearsEphemeralForecastOnly(t *testing.T) {
	c, _, _, _, _ := coordinatorV2Fixture(t, false)
	c.store.guardDeadlines = true
	before, _, _ := v2Canonical(c.store.state)
	if err := c.guardDeadlineOpenV2(); err != nil || c.store.guardDeadlines {
		t.Fatal("legacy assembly retained previous forecast option", err)
	}
	after, _, _ := v2Canonical(c.store.state)
	if string(before) != string(after) {
		t.Fatal("ephemeral option changed canonical state")
	}
}

func TestGuardDeadlineSelectedFeatureNeedsTrustedAssembly(t *testing.T) {
	c, _, engines, p, _ := coordinatorV2Fixture(t, false)
	c.options.GuardDeadlines = true
	c.store.guardDeadlines = true
	coordinatorV2Stage(t, c, p, "sticky-deadline")
	zero := uint64(0)
	coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	c.close()
	for _, engine := range engines {
		engine.reset()
	}
	options := c.options
	options.GuardDeadlines = false
	if opened, err := openCoordinatorV2(context.Background(), c.store, c.firewall, c.local, options); !errors.Is(err, ErrRecovery) {
		if opened != nil {
			opened.close()
		}
		t.Fatal("feature opened without trusted opt-in", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 || engine.reads.Load() != 0 || engine.validations.Load() != 0 {
			t.Fatal("assembly refusal executed engine")
		}
	}
}

func TestGuardDeadlineActiveIntentTypedReachability(t *testing.T) {
	c, area, _, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	c.options.GuardDeadlines = true
	c.store.guardDeadlines = true
	coordinatorV2Stage(t, c, p, "active-deadline")
	c.options.Hook = func(point string) error {
		if point == "after_intent" {
			return ErrInterrupted
		}
		return nil
	}
	zero := uint64(0)
	_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.store.publish(c.store.state); err != nil {
			t.Fatal(err)
		}
	}
	view := clone(c.store.state)
	view.Configuration = reserveFreezeSummaryV2(c.store.state.Configuration)
	if !preservesFeaturesV2(c.store.state, view) {
		t.Fatal("selection summary lost exact deadline")
	}
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	if report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2()); err != nil || !report.Complete {
		t.Fatal("active deadline graph incomplete", err, report)
	}
}

func TestGuardDeadlinePreAckFeatureBudgetNoClaim(t *testing.T) {
	c, _, _, p, now := coordinatorV2Fixture(t, false)
	m := attachReserveManagerV2(t, c)
	s := c.store
	ns, err := s.namespace(p.Subject, "firewall", *now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st := clone(s.state)
	st.Configuration.Firewall.Startup = st.Configuration.Firewall.Running
	if st.Configuration.refresh() != nil {
		t.Fatal("refresh")
	}
	for {
		core, _, _ := v2Canonical(reserveMetadataCoreV2(st))
		if len(core) >= 128*1024-200 {
			break
		}
		i := len(st.Subjects)
		if i >= int(st.SubjectSlots) {
			j := len(st.Namespaces)
			if j >= int(st.NamespaceSlots-closingRegistryReservedV2(st)) {
				break
			}
			st.Namespaces = append(st.Namespaces, v2Namespace{ID: fmt.Sprint("deadline-ns-", j), Subject: p.Subject, Domain: "firewall", AdmitUntil: st.Clock.Add(time.Hour), Closed: true})
			st.NamespaceSequence++
			data, _, _ := v2Canonical(reserveMetadataCoreV2(st))
			if len(data) > 128*1024-10 {
				st.Namespaces = st.Namespaces[:j]
				st.NamespaceSequence--
				break
			}
			continue
		}
		st.Subjects = append(st.Subjects, v2Subject{ID: fmt.Sprint("deadline-subject-", i), Login: "x", CredentialRevision: strings.Repeat("a", 64), Retired: true})
		st.SubjectSequence++
	}
	var padding []*string
	for i := 1; i < len(st.Subjects); i++ {
		padding = append(padding, &st.Subjects[i].ID, &st.Subjects[i].Login)
	}
	for i := 1; i < len(st.Namespaces); i++ {
		padding = append(padding, &st.Namespaces[i].ID)
	}
	for _, field := range padding {
		core, _, _ := v2Canonical(reserveMetadataCoreV2(st))
		gap := 128*1024 - 10 - len(core)
		if gap <= 0 {
			break
		}
		add := min(gap, 128-len(*field))
		*field += strings.Repeat("x", add)
	}
	core, _, _ := v2Canonical(reserveMetadataCoreV2(st))
	if len(core) != 128*1024-10 {
		t.Fatalf("fixture padding exhausted: %d", len(core))
	}
	if !v2ValidState(st) || s.publish(st) != nil {
		t.Fatal("valid feature-off boundary rejected")
	}
	s.guardDeadlines = true
	selected, used := s.selector, s.used
	_, err = s.admit(p.Subject, ns.ID, s.state.Generation, v2Request{Kind: OpSave}, *now)
	if !errors.Is(err, errV2Limited) || selected != s.selector || used != s.used || s.blocked {
		t.Fatal("deadline feature budget not refused cleanly", err)
	}
	claim, err := m.admission.ClaimClass("deadline-profile-probe", recoveryreserve.OrdinaryV2)
	if err != nil || claim.Slot != 0 || claim.Epoch != 1 {
		t.Fatal("pre-ACK refusal consumed physical claim", err)
	}
}
