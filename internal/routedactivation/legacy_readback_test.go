package routedactivation

import (
	"context"
	"testing"

	"github.com/AsterG/andeiva/internal/firewallnft"
)

type legacyReadbackKernelFixture struct{ *kernelFixture }

func (k legacyReadbackKernelFixture) Observe(ctx context.Context, table Table) ([]byte, bool, error) {
	data, present, err := k.kernelFixture.Observe(ctx, table)
	if err == nil && !present {
		return nil, false, nil
	}
	return data, present, err
}

func TestLegacyReadbackTracksGroupWithoutInventingLease(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	f.engine.kernel = legacyReadbackKernelFixture{f.kernel}
	ctx := context.Background()
	before, present, first, err := f.engine.ObserveLegacy(ctx)
	if err != nil || !present || before.Revision.Hash != f.prepared.Before.LegacyFirewall.Revision.Hash {
		t.Fatal("initial verified legacy unavailable", err)
	}
	if err := f.group.BootstrapStartup(ctx, f.plan, f.target, f.started); err != nil {
		t.Fatal(err)
	}
	_, present, applied, err := f.engine.ObserveLegacy(ctx)
	if err != nil || present || applied <= first {
		t.Fatal("routed transition did not expose actual legacy absence", applied, err)
	}
	state, _, err := f.group.SnapshotObserved()
	if err != nil || state.Phase != "pending" {
		t.Fatal("compatibility read changed group lease", err)
	}
	if err = f.group.RecoverLease(f.plan, state); err != nil {
		t.Fatal(err)
	}
	after, present, restored, err := f.engine.ObserveLegacy(ctx)
	if err != nil || !present || after.Revision.Hash != before.Revision.Hash || restored <= applied {
		t.Fatal("same-hash restore retained counter continuity", restored, err)
	}
}

func TestLegacyReadbackRejectsUnknownPolicyAndObservationFailure(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	f.engine.kernel = legacyReadbackKernelFixture{f.kernel}
	ctx := context.Background()
	delete(f.kernel.objects, LegacyTable)
	if _, present, _, err := f.engine.ObserveLegacy(ctx); err != nil || present {
		t.Fatal("successful cold absence rejected", err)
	}
	f.kernel.readFail = true
	if _, _, _, err := f.engine.ObserveLegacy(ctx); err == nil {
		t.Fatal("observation failure exposed as absence")
	}
	f.kernel.readFail = false
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, _, err := f.engine.ObserveLegacy(cancelled); err == nil {
		t.Fatal("cancelled capture accepted")
	}
	foreign := f.engine.options.Legacy.Config
	foreign.DefaultAction = "deny"
	// A valid but different schema is still not the trusted schema-4 projection.
	foreign.SchemaVersion = 2
	artifact, err := firewallnft.Compile(foreign)
	if err != nil || f.kernel.Apply(ctx, artifact.Create) != nil {
		t.Fatal("foreign fixture failed", err)
	}
	if _, _, _, err := f.engine.ObserveLegacy(ctx); err == nil {
		t.Fatal("unselected kernel policy adopted")
	}
}

func TestLegacyReadbackFailedApplyInvalidatesCounterEpoch(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	f.kernel.failAt = 1
	if err := f.group.BootstrapStartup(context.Background(), f.plan, f.target, f.started); err == nil {
		t.Fatal("failed apply succeeded")
	}
	if f.engine.legacyEpoch == 0 {
		t.Fatal("failed kernel apply retained counter epoch")
	}
}

func TestLegacyCounterExhaustionDoesNotPreventSafetyRollback(t *testing.T) {
	f := assembleFixture(t)
	defer f.group.Close()
	f.engine.legacyEpoch = ^uint64(0)
	ctx := context.Background()
	if err := f.group.BootstrapStartup(ctx, f.plan, f.target, f.started); err != nil {
		t.Fatal("counter exhaustion blocked policy safety", err)
	}
	if _, _, _, err := f.engine.ObserveLegacy(ctx); err == nil {
		t.Fatal("counter continuity wrapped")
	}
	state, _, err := f.group.SnapshotObserved()
	if err != nil || f.group.RecoverLease(f.plan, state) != nil || !f.engine.matches(ctx, f.prepared.Before, f.prepared.Dependencies) {
		t.Fatal("counter exhaustion blocked rollback", err)
	}
}
