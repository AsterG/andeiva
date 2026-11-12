//go:build linux

package configpoc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

const testBootIDV2 v2BootID = "ed012378-aabc-4123-9123-0123456789ab"

func bootFixtureV2(t *testing.T) (*v2Coordinator, *os.Root, []*countedCoordinatorV2Engine, v2TrustedPrincipal) {
	t.Helper()
	c, area, engines, p, _ := coordinatorV2Fixture(t, false)
	// This prepared firewall-only fixture has no Local Services change to
	// activate. The separate negative fixture retains the imported difference.
	st := clone(c.store.state)
	st.Configuration.LocalServices.Startup = st.Configuration.LocalServices.Running
	if st.Configuration.refresh() != nil {
		t.Fatal("fixture refresh")
	}
	if _, err := c.appendAuditLocked(st.Configuration, "boot-fixture", "", "", "system", "fixture", "verified", st.Generation, c.recoveryNow()); err != nil {
		t.Fatal(err)
	}
	if err := c.store.publish(st); err != nil {
		t.Fatal(err)
	}
	config := coordinatorV2Rule("not-saved")
	coordinatorV2Run(t, c, p, v2Request{Kind: OpStage, Config: &config})
	seconds := uint64(0)
	coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
	if c.store.state.Configuration.Running.Hash == c.store.state.Configuration.Startup.Hash {
		t.Fatal("fixture needs unsaved Running")
	}
	for _, engine := range engines {
		engine.reset()
	}
	return c, area, engines, p
}

func reopenBootV2(t *testing.T, prior *v2Coordinator, area *os.Root, id *v2BootID, hook func(string) error) (*v2Coordinator, error) {
	t.Helper()
	prior.close()
	if err := prior.store.close(); err != nil {
		t.Fatal(err)
	}
	store, err := openV2(area, prior.store.budget)
	if err != nil {
		return nil, err
	}
	options := prior.options
	options.BootID, options.Hook = id, hook
	c, err := openCoordinatorV2(context.Background(), store, prior.firewall, prior.local, options)
	t.Cleanup(func() {
		if c != nil {
			c.close()
		}
		_ = store.close()
	})
	return c, err
}

func TestV2BootStartupAndProcessRestart(t *testing.T) {
	c, area, engines, _ := bootFixtureV2(t)
	before := clone(c.store.state)
	restarted, err := reopenBootV2(t, c, area, nil, nil)
	if err != nil || restarted.store.state.Configuration.Running.Hash != before.Configuration.Running.Hash {
		t.Fatal("process restart changed Running", err)
	}
	booted, err := reopenBootV2(t, restarted, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	state := booted.store.state
	if state.Configuration.Running.Hash != before.Configuration.Startup.Hash || state.Configuration.Startup.Hash != before.Configuration.Startup.Hash || state.Generation != before.Generation+1 || state.Configuration.Firewall.Generation != before.Configuration.Firewall.Generation+1 || state.Configuration.LocalServices.Generation != before.Configuration.LocalServices.Generation || state.Configuration.Intent != nil || state.ReservedBytes != before.ReservedBytes {
		t.Fatal("incorrect selected boot", state)
	}
	for _, engine := range engines[:2] {
		if engine.applies.Load() != 1 {
			t.Fatal("wrong boot effects")
		}
	}
	seq, generation, audit := state.Configuration.AuditSequence, state.Generation, state.Configuration.AuditTip
	same, err := reopenBootV2(t, booted, area, ptrBootV2(testBootIDV2), nil)
	if err != nil || same.store.state.Generation != generation || same.store.state.Configuration.AuditSequence != seq || same.store.state.Configuration.AuditTip != audit {
		t.Fatal("same boot repeated selection", err)
	}
	for _, engine := range engines[:2] {
		if engine.applies.Load() != 1 {
			t.Fatal("same boot repeated effects")
		}
	}
}

func ptrBootV2(id v2BootID) *v2BootID { return &id }

func TestV2BootInterruptedBoundaries(t *testing.T) {
	for _, boundary := range []string{"before_boot_intent", "after_boot_intent", "after_boot_engine", "after_boot_readback", "before_boot_completion", "after_boot_completion"} {
		t.Run(boundary, func(t *testing.T) {
			c, area, engines, _ := bootFixtureV2(t)
			original := clone(c.store.state)
			fired := false
			interrupted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), func(point string) error {
				if point == boundary && !fired {
					fired = true
					return ErrInterrupted
				}
				return nil
			})
			if !errors.Is(err, ErrInterrupted) || !fired || interrupted == nil {
				t.Fatal("boundary not reached", err)
			}
			if boundary == "before_boot_intent" {
				if len(interrupted.store.state.RequiredFeatures) != 0 || interrupted.store.state.Configuration.Intent != nil {
					t.Fatal("premature sticky feature")
				}
				for _, engine := range engines {
					if engine.applies.Load() != 0 {
						t.Fatal("effect before intent")
					}
				}
			} else if boundary != "after_boot_completion" {
				if len(interrupted.store.state.RequiredFeatures) != 1 || interrupted.store.state.Configuration.Intent == nil || interrupted.store.state.ReservedBytes < v2OperationReserveBytes {
					t.Fatal("intent/feature/reserve not durable")
				}
			}
			resumed, err := reopenBootV2(t, interrupted, area, ptrBootV2(testBootIDV2), nil)
			if err != nil || resumed.store.state.Configuration.Running.Hash != original.Configuration.Startup.Hash || resumed.store.state.Generation != original.Generation+1 {
				t.Fatal("recovery did not select Startup once", err)
			}
			for _, engine := range engines[:2] {
				if engine.applies.Load() != 1 {
					t.Fatal("recovery repeated effect", engine.applies.Load())
				}
			}
		})
	}
}

func TestV2BootWrongIdentityAndUnavailableDomain(t *testing.T) {
	t.Run("wrong-boot", func(t *testing.T) {
		c, area, engines, _ := bootFixtureV2(t)
		interrupted, _ := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), func(point string) error {
			if point == "after_boot_intent" {
				return ErrInterrupted
			}
			return nil
		})
		wrong := v2BootID("dd012378-aabc-4123-9123-0123456789ab")
		blocked, err := reopenBootV2(t, interrupted, area, &wrong, nil)
		if !errors.Is(err, ErrRecovery) {
			t.Fatal(err)
		}
		for _, engine := range engines {
			if engine.applies.Load() != 0 {
				t.Fatal("wrong boot caused effects")
			}
		}
		if _, err := reopenBootV2(t, blocked, area, ptrBootV2(testBootIDV2), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("process-context-cannot-resume-boot", func(t *testing.T) {
		c, area, engines, _ := bootFixtureV2(t)
		interrupted, _ := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), func(point string) error {
			if point == "after_boot_intent" {
				return ErrInterrupted
			}
			return nil
		})
		blocked, err := reopenBootV2(t, interrupted, area, nil, nil)
		if !errors.Is(err, ErrRecovery) {
			t.Fatal("process context resumed boot", err)
		}
		for _, engine := range engines {
			if engine.applies.Load() != 0 {
				t.Fatal("process context applied Startup")
			}
		}
		if _, err := reopenBootV2(t, blocked, area, ptrBootV2(testBootIDV2), nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("local-mapper-unavailable", func(t *testing.T) {
		c, area, engines, _, _ := coordinatorV2Fixture(t, false)
		for _, engine := range engines {
			engine.reset()
		}
		if c.store.state.Configuration.LocalServices.Running.Hash == c.store.state.Configuration.LocalServices.Startup.Hash {
			t.Fatal("negative needs distinct imported Local Services Startup")
		}
		_, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
		if !errors.Is(err, ErrRecovery) {
			t.Fatal("unsupported local mutation accepted", err)
		}
		for _, engine := range engines {
			if engine.applies.Load() != 0 {
				t.Fatal("unsupported local mutation caused effects")
			}
		}
	})
}

func TestV2BootPartialFailureKeepsSelectedRunning(t *testing.T) {
	c, area, engines, _ := bootFixtureV2(t)
	old := clone(c.store.state)
	engines[1].base.SetFailure(old.Configuration.Firewall.Startup.Hash, "before")
	failed, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if !errors.Is(err, ErrEngine) || failed.store.state.Generation != old.Generation || failed.store.state.Configuration.Running.Hash != old.Configuration.Running.Hash || failed.store.state.Configuration.LastCompletedBoot != "" || failed.store.state.Configuration.Intent == nil {
		t.Fatal("partial boot published Running", err)
	}
	if engines[0].Current() != old.Configuration.Firewall.Startup.Hash || engines[1].Current() != old.Configuration.Firewall.Running.Hash {
		t.Fatal("partial failure not exercised")
	}
	engines[1].base.ClearFailure()
	resumed, err := reopenBootV2(t, failed, area, ptrBootV2(testBootIDV2), nil)
	if err != nil || !resumed.readback(*resumed.store.state.Configuration) || resumed.store.state.Generation != old.Generation+1 {
		t.Fatal("partial recovery failed", err)
	}
	if engines[0].applies.Load() != 1 {
		t.Fatal("already verified component reapplied")
	}
}

func TestV2BootKeepsInactiveStagedCandidate(t *testing.T) {
	c, area, engines, p := bootFixtureV2(t)
	config := coordinatorV2Rule("staged-not-applied")
	coordinatorV2Run(t, c, p, v2Request{Kind: OpStage, Config: &config})
	before := clone(c.store.state.Configuration.Firewall.Candidate)
	startup := c.store.state.Configuration.Startup.Hash
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, booted.store.state.Configuration.Firewall.Candidate) || booted.store.state.Configuration.Running.Hash != startup || booted.store.state.Configuration.Firewall.Running.Hash == before.Revision.Hash {
		t.Fatal("boot discarded or committed Candidate")
	}
	for _, engine := range engines[:2] {
		if engine.Current() == before.Revision.Hash {
			t.Fatal("staged candidate reached engine")
		}
	}
	same, err := reopenBootV2(t, booted, area, ptrBootV2(testBootIDV2), nil)
	if err != nil || !reflect.DeepEqual(before, same.store.state.Configuration.Firewall.Candidate) {
		t.Fatal("same boot changed Candidate", err)
	}
	zero := uint64(0)
	_, _, err = coordinatorV2Request(t, same, p, v2Request{Kind: OpCommit, ConfirmSeconds: &zero})
	if !errors.Is(err, ErrConflict) {
		t.Fatal("boot implicitly rebased staged Candidate", err)
	}
}

func TestV2BootRecoversPendingByItsOriginalLease(t *testing.T) {
	c, area, _, p := bootFixtureV2(t)
	startup := c.store.state.Configuration.Startup.Hash
	config := coordinatorV2Rule("unconfirmed-at-reboot")
	coordinatorV2Run(t, c, p, v2Request{Kind: OpStage, Config: &config})
	window := uint64(30)
	commit := coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &window})
	original := clone(commit.Operation.Outcome)
	before := c.store.state.Generation
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := booted.store.lookup(p.Subject, commit.Operation.ID)
	if err != nil || stored.Pinned || !reflect.DeepEqual(original, stored.Outcome) || booted.store.state.Configuration.Pending != nil || booted.store.state.Configuration.Running.Hash != startup || booted.store.state.Generation != before+2 {
		t.Fatal("boot lost original confirmation semantics", err)
	}
}

func TestV2BootLogicalBudgetRejectsBeforeIntent(t *testing.T) {
	c, _, engines, _ := bootFixtureV2(t)
	before := clone(c.store.state)
	c.store.budget.Bytes = c.store.used.Bytes + c.store.state.ReservedBytes + v2OperationReserveBytes
	c.options.BootID = ptrBootV2(testBootIDV2)
	c.store.mu.Lock()
	err := c.bootStartupLocked(context.Background(), testBootIDV2)
	c.store.mu.Unlock()
	if !errors.Is(err, errV2Limited) || !reflect.DeepEqual(before, c.store.state) {
		t.Fatal("budget rejection changed selected state", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("effect before recovery budget")
		}
	}
}

func TestV2BootMissingCompletedReferenceFailsClosed(t *testing.T) {
	c, area, engines, _ := bootFixtureV2(t)
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	st := clone(booted.store.state)
	st.Configuration.LastCompletedBoot = checkpointDigest([]byte("missing boot object"))
	if err := booted.store.publish(st); err != nil {
		t.Fatal(err)
	}
	for _, engine := range engines {
		engine.reset()
	}
	_, err = reopenBootV2(t, booted, area, ptrBootV2(testBootIDV2), nil)
	if !errors.Is(err, errV2Unavailable) {
		t.Fatal("missing completion reference accepted", err)
	}
	for _, engine := range engines {
		if engine.applies.Load() != 0 {
			t.Fatal("effect from corrupt completion")
		}
	}
}

func oldStateDecoderV2(data []byte) error {
	// Exact pre-feature v2State shape: preserve every field/type/order except
	// the newly added top-level discriminator. This decoder existed before
	// any coordinator could be constructed or call an engine.
	typ := reflect.TypeOf(v2State{})
	fields := make([]reflect.StructField, 0, typ.NumField()-1)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Name != "RequiredFeatures" {
			fields = append(fields, typ.Field(i))
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(reflect.New(reflect.StructOf(fields)).Interface())
}

func oldStateBytesV2(state v2State) []byte {
	typ := reflect.TypeOf(state)
	fields := make([]reflect.StructField, 0, typ.NumField()-1)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Name != "RequiredFeatures" {
			fields = append(fields, typ.Field(i))
		}
	}
	old := reflect.New(reflect.StructOf(fields)).Elem()
	current := reflect.ValueOf(state)
	for i := 0; i < old.NumField(); i++ {
		old.Field(i).Set(current.FieldByName(old.Type().Field(i).Name))
	}
	data, _ := json.Marshal(old.Interface())
	return data
}

func TestV2BootStickyFeatureAndOldReader(t *testing.T) {
	c, area, engines, p := bootFixtureV2(t)
	old, _ := json.Marshal(c.store.state)
	if !bytes.Equal(old, oldStateBytesV2(c.store.state)) || bytes.Contains(old, []byte("required_features")) || bytes.Contains(old, []byte("last_completed_boot")) || bytes.Contains(old, []byte("boot_id")) || oldStateDecoderV2(old) != nil {
		t.Fatal("default old format changed")
	}
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 70; i++ {
		coordinatorV2Run(t, booted, p, v2Request{Kind: OpSave})
	}
	latest, _ := json.Marshal(booted.store.state)
	if oldStateDecoderV2(latest) == nil || len(booted.store.state.RequiredFeatures) != 1 {
		t.Fatal("old reader can cross sticky checkpoint")
	}
	st := clone(booted.store.state)
	st.RequiredFeatures = nil
	if booted.store.publish(st) == nil {
		t.Fatal("feature stripped")
	}
	for _, engine := range engines[:2] {
		if engine.applies.Load() != 1 {
			t.Fatal("metadata operations applied engines")
		}
	}
}
