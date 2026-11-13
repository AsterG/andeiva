//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"testing"
)

func TestReserveCompensatedLeaseRetiresAndReplays(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	coordinatorV2Stage(t, c, p, "compensation")
	before := clone(*c.store.state.Configuration)
	engines[1].base.FailNext("after")
	seconds := uint64(90)
	op, result, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrEngine) || result.Operation.Outcome == nil || result.Operation.Outcome.Code != "failed_rolled_back" {
		final, lookup := c.store.lookup(p.Subject, op.ID)
		t.Fatalf("compensated confirmed operation cannot retire: error=%v lookup=%v final=%s active=%d", err, lookup, final.State, len(c.store.state.ActiveReserves))
	}
	if len(c.store.state.ActiveReserves) != 0 || len(c.store.state.ClosingCredits) != 0 || c.store.state.ReservedBytes != 0 || c.store.state.ReservedInodes != 0 {
		t.Fatal("compensation retained physical or logical reservation")
	}
	if result.Current.Pending != nil || result.Current.Running.Hash != before.Running.Hash || result.Current.Startup.Hash != before.Startup.Hash {
		t.Fatal("compensation changed verified state")
	}
	for _, engine := range engines[:2] {
		if engine.Current() != before.Firewall.Running.Hash {
			t.Fatal("compensation readback differs")
		}
	}
	resumed, err := reopenCoordinatorV2(t, c, area)
	if err != nil {
		t.Fatal("reopen", err)
	}
	replay, err := resumed.execute(context.Background(), p, op.ID)
	if err != nil || replay.Operation.Outcome.Code != "failed_rolled_back" {
		t.Fatal("replay", err)
	}
}

func compensationArchiveV2(t *testing.T, c *v2Coordinator, op v2Operation) (v2ReserveArchive, v2ReserveFinality, v2ReserveCompensationResolution) {
	t.Helper()
	a, known, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: op.Reserve.Claims.Admission}, "claim")
	if err != nil || !known {
		t.Fatalf("archive: %t %v", known, err)
	}
	var facts v2ReserveFinality
	var resolution v2ReserveCompensationResolution
	if c.store.readObject(a.FinalWork, &facts) != nil || c.store.readObject(facts.Resolution, &resolution) != nil {
		t.Fatal("missing typed finality")
	}
	return a, facts, resolution
}

func compensatedFixtureV2(t *testing.T) (*v2Coordinator, *os.Root, v2Operation) {
	t.Helper()
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	coordinatorV2Stage(t, c, p, "compensated")
	engines[1].base.FailNext("after")
	seconds := uint64(90)
	_, result, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrEngine) || result.Operation.Outcome == nil || result.Operation.Outcome.Code != "failed_rolled_back" {
		t.Fatal("compensation", err)
	}
	return c, area, result.Operation
}

func TestReserveCompensationRejectsForeignFacts(t *testing.T) {
	c, _, op := compensatedFixtureV2(t)
	original, facts, resolution := compensationArchiveV2(t, c, op)
	if validateArchiveFinalityV2(original, c.store.state, c.store.readObject) != nil {
		t.Fatal("valid fixture")
	}
	encoded, _, _ := v2Canonical(resolution)
	t.Logf("typed resolution serialized_bytes=%d; archive_entries=%d unused_escrow=%d", len(encoded), len(original.Entries), len(original.UnusedEscrow))
	for _, tc := range []struct {
		name   string
		change func(*v2ReserveCompensationResolution)
	}{
		{"version", func(r *v2ReserveCompensationResolution) { r.Version = 1 }},
		{"kind", func(r *v2ReserveCompensationResolution) { r.Kind = "system_completed" }},
		{"origin", func(r *v2ReserveCompensationResolution) { r.Origin += "foreign" }},
		{"lease", func(r *v2ReserveCompensationResolution) { r.Lease += "foreign" }},
		{"deadline", func(r *v2ReserveCompensationResolution) { r.Deadline = r.Deadline.Add(time.Nanosecond) }},
		{"plan", func(r *v2ReserveCompensationResolution) { r.Plan.Claim.Epoch++ }},
		{"previous", func(r *v2ReserveCompensationResolution) { r.Previous = r.Target }},
		{"target", func(r *v2ReserveCompensationResolution) { r.Target = r.Previous }},
		{"audit", func(r *v2ReserveCompensationResolution) { r.Audit = r.Previous }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, f, r := clone(original), clone(facts), clone(resolution)
			tc.change(&r)
			var err error
			f.Resolution, err = c.store.object(r)
			if err != nil {
				t.Fatal(err)
			}
			a.LeaseResolution = f.Resolution
			a.FinalWork, err = c.store.object(f)
			if err != nil {
				t.Fatal(err)
			}
			if validateArchiveFinalityV2(a, c.store.state, c.store.readObject) == nil {
				t.Fatal("foreign compensation admitted")
			}
		})
	}
	for _, name := range []string{"audit-subject", "audit-running", "audit-result", "audit-generation", "missing-previous", "missing-target", "missing-resolution"} {
		t.Run(name, func(t *testing.T) {
			load := func(hash string, out any) error {
				if name == "missing-previous" && hash == resolution.Previous || name == "missing-target" && hash == resolution.Target || name == "missing-resolution" && hash == facts.Resolution {
					return errV2Unavailable
				}
				if err := c.store.readObject(hash, out); err != nil {
					return err
				}
				if audit, ok := out.(*v2CoordinatorAudit); ok && hash == resolution.Audit {
					switch name {
					case "audit-subject":
						audit.Subject += "foreign"
					case "audit-running":
						audit.Running = resolution.Target
					case "audit-result":
						audit.Result = "applied"
					case "audit-generation":
						audit.Generation++
					}
				}
				return nil
			}
			if validateArchiveFinalityV2(original, c.store.state, load) == nil {
				t.Fatal("invalid contextual dependency accepted")
			}
		})
	}
	for _, name := range []string{"missing-feature", "unsupported-finality", "fake-child", "system-kind"} {
		t.Run(name, func(t *testing.T) {
			state, a, f := clone(c.store.state), clone(original), clone(facts)
			switch name {
			case "missing-feature":
				state.RequiredFeatures = nil
			case "unsupported-finality":
				f.Version = 3
			case "fake-child":
				f.Child = &f.Origin
			case "system-kind":
				f.Kind = "system"
			}
			var err error
			a.FinalWork, err = c.store.object(f)
			if err != nil {
				t.Fatal(err)
			}
			if validateArchiveFinalityV2(a, state, c.store.readObject) == nil {
				t.Fatal("version/domain gate bypassed")
			}
		})
	}
}

func TestReserveCompensationInterruptedRetirementReopens(t *testing.T) {
	for _, point := range []string{"reserve_archive_selected", "reserve_archive_anchored", "reserve_role_retired", "reserve_escrow_retired", "reserve_physical_retired"} {
		t.Run(point, func(t *testing.T) {
			c, area, engines, p, _ := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			coordinatorV2Stage(t, c, p, "retire-interrupted")
			engines[1].base.FailNext("after")
			hit := false
			c.store.hook = func(at string) error {
				if at == point && !hit {
					hit = true
					return ErrInterrupted
				}
				return nil
			}
			seconds := uint64(90)
			op, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			if !hit || !errors.Is(err, ErrInterrupted) {
				t.Fatal("retirement boundary", point, err)
			}
			if !hasFeatureV2(c.store.state, v2ReserveCompensationFeature) || len(c.store.state.ActiveReserves) != 1 {
				t.Fatal("retirement lost feature or held authority")
			}
			current, previous := c.store.selector.Current, c.store.selector.Previous
			resumed, err := reopenCoordinatorV2(t, c, area)
			if err != nil {
				t.Fatal("restart", err)
			}
			if len(resumed.store.state.ActiveReserves) != 0 || len(resumed.store.state.ClosingCredits) != 0 || resumed.store.state.ReservedBytes != 0 {
				t.Fatal("reservation not finalized")
			}
			final, err := resumed.store.lookup(p.Subject, op.ID)
			if err != nil || final.Outcome.Code != "failed_rolled_back" {
				t.Fatal("immutable outcome changed", err)
			}
			archive, _, _ := compensationArchiveV2(t, resumed, final)
			if archive.LeaseResolution == "" {
				t.Fatal("proof lost")
			}
			t.Logf("interruption=%s retained_anchor=%t", point, resumed.store.selector.Previous == current || resumed.store.selector.Previous == previous)
			coordinatorV2Run(t, resumed, p, v2Request{Kind: OpSave})
		})
	}
}

func TestReserveCompensationInterruptedIntentRecovers(t *testing.T) {
	for _, point := range []string{"after_intent", "after_component_apply", "after_readback"} {
		t.Run(point, func(t *testing.T) {
			c, area, _, p, _ := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			coordinatorV2Stage(t, c, p, "intent-compensated")
			c.options.Hook = func(at string) error {
				if at == point {
					return ErrInterrupted
				}
				return nil
			}
			seconds := uint64(90)
			op, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
			if !errors.Is(err, ErrInterrupted) {
				t.Fatal(err)
			}
			resumed, err := reopenCoordinatorV2(t, c, area)
			if err != nil {
				t.Fatal("compensation reopen", err)
			}
			final, err := resumed.store.lookup(p.Subject, op.ID)
			if err != nil || final.Outcome.Code != "failed_rolled_back" || len(resumed.store.state.ActiveReserves) != 0 {
				t.Fatal("compensated plan remains held", err)
			}
			if final.Reserve.PlanScope.Lease == "" || final.Reserve.PlanScope.Deadline.IsZero() {
				t.Fatal("lease or deadline removed")
			}
		})
	}
}

func TestReserveCompensationArchiveClosureAndStickyFeatures(t *testing.T) {
	c, area, op := compensatedFixtureV2(t)
	a, facts, resolution := compensationArchiveV2(t, c, op)
	st := clone(c.store.state)
	addFeatureV2(&st, v2LocalFeature)
	addFeatureV2(&st, v2BootFeature)
	if !reflect.DeepEqual(st.RequiredFeatures, []string{v2BootFeature, v2LocalFeature, v2ReserveCompensationFeature}) || !validFeaturesV2(st) {
		t.Fatal("three feature ordering")
	}
	if err := c.store.publish(st); err != nil {
		t.Fatal(err)
	}
	for range 66 {
		if err := c.store.publish(clone(c.store.state)); err != nil {
			t.Fatal(err)
		}
	}
	stripped := clone(c.store.state)
	stripped.RequiredFeatures = []string{v2BootFeature, v2LocalFeature}
	if c.store.publish(stripped) == nil {
		t.Fatal("downgrade allowed")
	}
	// Full closure is independently inspected after releasing the writer flock.
	c.close()
	if err := c.store.close(); err != nil {
		t.Fatal(err)
	}
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("archive closure", err)
	}
	for _, hash := range []string{a.FinalWork, facts.Resolution, resolution.Previous, resolution.Target, resolution.Audit} {
		name, err := v2ObjectName(hash)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := area.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = area.Remove(name); err != nil {
			t.Fatal(err)
		}
		incomplete, e := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
		if e == nil || incomplete.Complete {
			t.Fatal("missing archive dependency was accepted")
		}
		if err = area.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReserveCompensationActualPriorReaderRefusal(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("supply actual main7fe test binary with -reclaim-old-reader; skip is not evidence")
	}
	for _, point := range []string{"legacy", "reserve_archive_selected", "reserve_role_retired", "complete"} {
		t.Run(point, func(t *testing.T) {
			c, area, engines, p, _ := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			coordinatorV2Stage(t, c, p, "prior-reader")
			if point != "legacy" {
				engines[1].base.FailNext("after")
				hit := false
				c.store.hook = func(at string) error {
					if at == point && !hit {
						hit = true
						return ErrInterrupted
					}
					return nil
				}
				seconds := uint64(90)
				_, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
				if point == "complete" && !errors.Is(err, ErrEngine) || point != "complete" && !errors.Is(err, ErrInterrupted) {
					t.Fatal("fixture", err)
				}
			}
			c.close()
			if err := c.store.close(); err != nil {
				t.Fatal(err)
			}
			before := journalFiles(t, area.Name())
			command := exec.Command(*reclaimOldReader, "-test.run=^TestReclaimPriorReader$", "-prior-reclaim-area="+area.Name())
			output, err := command.CombinedOutput()
			want := "OLD_READER_REJECTED"
			if point == "legacy" {
				want = "OLD_READER_ACCEPTED"
			}
			if err != nil || !strings.Contains(string(output), want) || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatalf("prior reader %s: %v %s", point, err, output)
			}
		})
	}
}

func TestReserveCompensationProcessExitDuringRetirement(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	m, areas := attachReserveAreasV2(t, c)
	coordinatorV2Stage(t, c, p, "process-compensation")
	engines[1].base.FailNext("after")
	c.store.hook = func(at string) error {
		if at == "reserve_archive_anchored" {
			return ErrInterrupted
		}
		return nil
	}
	seconds := uint64(90)
	op, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	for _, pool := range []*recoveryreserve.PoolV2{m.admission, m.plan, m.emergency} {
		if err = pool.Close(); err != nil {
			t.Fatal(err)
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestReserveCoordinatorProcessExitHelper$")
	cmd.Env = append(os.Environ(), "ANDEIVA_RESERVE_EXIT_STORE="+area.Name(), "ANDEIVA_RESERVE_EXIT_ADMISSION="+areas[0].Name(), "ANDEIVA_RESERVE_EXIT_PLAN="+areas[1].Name(), "ANDEIVA_RESERVE_EXIT_EMERGENCY="+areas[2].Name())
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 47 {
		t.Fatalf("process exit47: %v %s", err, output)
	}
	s, err := openV2(area, c.store.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.reserves = openTestReserveAreasV2(t, areas)
	if s.reserves.verifySelected(s) != nil || s.reserves.maintain(s) != nil {
		t.Fatal("exact CAS retirement could not resume")
	}
	final, err := s.lookup(p.Subject, op.ID)
	if err != nil || final.Outcome.Code != "failed_rolled_back" || len(s.state.ActiveReserves) != 0 || s.state.ReservedBytes != 0 {
		t.Fatal("terminal compensation lost", err)
	}
}

func TestReserveCompensationProspectiveSnapshotContext(t *testing.T) {
	c, area, op := compensatedFixtureV2(t)
	_, _, proof := compensationArchiveV2(t, c, op)
	var target v2Configuration
	if c.store.readObject(proof.Target, &target) != nil {
		t.Fatal("target")
	}
	if !reserveCompensatedSnapshotV2(target, c.store.state, op, c.store.readObject) {
		t.Fatal("valid prospective context")
	}
	for _, mode := range []string{"missing-feature", "foreign-target", "origin", "lease", "deadline", "binding", "audit", "pending-operation", "system"} {
		t.Run(mode, func(t *testing.T) {
			cfg, state, origin := clone(target), clone(c.store.state), clone(op)
			switch mode {
			case "missing-feature":
				state.RequiredFeatures = nil
			case "foreign-target":
				cfg.Firewall.Startup = cfg.Firewall.Running
				if cfg.refresh() != nil {
					t.Fatal("refresh")
				}
			case "origin":
				cfg.Pending.OriginCommit += "foreign"
			case "lease":
				cfg.Pending.Lease += "foreign"
			case "deadline":
				cfg.Pending.Deadline = cfg.Pending.Deadline.Add(time.Nanosecond)
			case "binding":
				origin.Reserve.Plan.ScopeHash = strings.Repeat("f", 64)
			case "audit":
				origin.Outcome.AuditHash = proof.Target
			case "pending-operation":
				origin.State = "pending"
				origin.Pinned = true
			case "system":
				origin.Reserve.Scope.Kind = "boot"
			}
			if reserveCompensatedSnapshotV2(cfg, state, origin, c.store.readObject) {
				t.Fatal("foreign prospective context accepted")
			}
		})
	}
	rootInfo, err := area.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	reader := func() *v2ReachabilityReader {
		return &v2ReachabilityReader{ctx: context.Background(), area: area, root: rootInfo, budget: reachabilityBudgetV2(), objects: map[string]bool{}, edges: map[string]uint8{}}
	}
	if err := reader().configuration(target, "prospective", c.store.state, 0, false); err != nil {
		t.Fatal("prospective graph", err)
	}
	if err := reader().configuration(target, "live", c.store.state, 0, true); err == nil {
		t.Fatal("prospective target granted live authority")
	}
}

func TestReserveCompensationMarkerPrecedesArchivePublication(t *testing.T) {
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	coordinatorV2Stage(t, c, p, "before-archive")
	archiveRoot := c.store.state.ReserveArchiveRoot
	engines[1].base.FailNext("after")
	hit := false
	c.store.hook = func(at string) error {
		if at == "object_written" && hasFeatureV2(c.store.state, v2ReserveCompensationFeature) && !hit {
			hit = true
			return ErrInterrupted
		}
		return nil
	}
	seconds := uint64(90)
	op, _, err := coordinatorV2Request(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if err == nil || !hit || c.store.state.ReserveArchiveRoot != archiveRoot || !hasFeatureV2(c.store.state, v2ReserveCompensationFeature) || c.store.state.Configuration.Intent != nil {
		t.Fatal("missing pre-archive boundary", err)
	}
	final, err := c.store.lookupRetained(p.Subject, op.ID)
	if err != nil || final.Outcome.Code != "failed_rolled_back" {
		t.Fatal("final facts not selected", err)
	}
	c.close()
	if err = c.store.close(); err != nil {
		t.Fatal(err)
	}
	if *reclaimOldReader != "" {
		before := journalFiles(t, area.Name())
		output, e := exec.Command(*reclaimOldReader, "-test.run=^TestReclaimPriorReader$", "-prior-reclaim-area="+area.Name()).CombinedOutput()
		if e != nil || !strings.Contains(string(output), "OLD_READER_REJECTED") || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
			t.Fatalf("pre-archive downgrade: %v %s", e, output)
		}
	}
	s, err := openV2(area, c.store.budget)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	resumed, err := openCoordinatorV2(context.Background(), s, c.firewall, c.local, c.options)
	if err != nil {
		t.Fatal("pre-archive resume", err)
	}
	defer resumed.close()
	if len(s.state.ActiveReserves) != 0 || s.state.ReservedBytes != 0 {
		t.Fatal("pre-archive reservation lost")
	}
	resumed.close()
	if err = s.close(); err != nil {
		t.Fatal(err)
	}
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("intermediate compensation graph", err)
	}
}

func TestReserveCompensationLegacyBytesAndEnvelope(t *testing.T) {
	c, _, _, p, _ := coordinatorV2Fixture(t, false)
	attachReserveManagerV2(t, c)
	before, _, err := v2Canonical(reserveMetadataCoreV2(c.store.state))
	if err != nil {
		t.Fatal(err)
	}
	marked := clone(c.store.state)
	addFeatureV2(&marked, v2ReserveCompensationFeature)
	after, _, err := v2Canonical(reserveMetadataCoreV2(marked))
	if err != nil || string(before) != string(after) {
		t.Fatal("marker bytes not reserved before admission")
	}
	if hasFeatureV2(c.store.state, v2ReserveCompensationFeature) {
		t.Fatal("normal store silently migrated")
	}
	coordinatorV2Stage(t, c, p, "v1-confirmed")
	seconds := uint64(90)
	commit := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	coordinatorV2Run(t, c, p, v2Request{Kind: OpConfirm, Origin: commit.Operation.ID, Target: commit.Current.Running.Hash})
	archive, found, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: commit.Operation.Reserve.Claims.Admission}, "claim")
	var facts v2ReserveFinality
	var resolution v2ReserveLeaseResolution
	if err != nil || !found || c.store.readObject(archive.FinalWork, &facts) != nil || c.store.readObject(facts.Resolution, &resolution) != nil || facts.Version != 1 || resolution.Version != 1 || hasFeatureV2(c.store.state, v2ReserveCompensationFeature) {
		t.Fatal("normal V1 archive changed", err)
	}
}

func TestReserveCompensationRejectsHistoricalIncompleteArchive(t *testing.T) {
	c, _, op := compensatedFixtureV2(t)
	a, f, _ := compensationArchiveV2(t, c, op)
	f.Version = 1
	f.Resolution = ""
	a.LeaseResolution = ""
	var err error
	a.FinalWork, err = c.store.object(f)
	if err != nil {
		t.Fatal(err)
	}
	before := journalFiles(t, c.store.root.Name())
	if validateArchiveFinalityV2(a, c.store.state, c.store.readObject) == nil {
		t.Fatal("incomplete old proof was silently repaired")
	}
	if !reflect.DeepEqual(before, journalFiles(t, c.store.root.Name())) {
		t.Fatal("validation changed historical evidence")
	}
}

func TestReserveCompensationValidationResourceSample(t *testing.T) {
	c, _, op := compensatedFixtureV2(t)
	archive, _, proof := compensationArchiveV2(t, c, op)
	var validationError error
	allocations := testing.AllocsPerRun(5, func() { validationError = validateArchiveFinalityV2(archive, c.store.state, c.store.readObject) })
	if validationError != nil {
		t.Fatal(validationError)
	}
	start := time.Now()
	for range 10 {
		if err := validateArchiveFinalityV2(archive, c.store.state, c.store.readObject); err != nil {
			t.Fatal(err)
		}
	}
	raw, _, err := v2Canonical(proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("source-only sample: resolution_bytes=%d validation_allocs=%.0f mean_wall=%s (filesystem and host dependent; not appliance sizing)", len(raw), allocations, time.Since(start)/10)
}
