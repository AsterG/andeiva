//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/routedactivation"
)

func TestRoutedIntegrityV3OpaqueStoreBridge(t *testing.T) {
	f := newRoutedIPCFixtureWithPolicyV3(t, configpoc.SelectionActionAuthorityV2)
	ctx := context.Background()
	ref, err := f.reader.CaptureReferenceV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.reader.Resolve(ctx, ref, configpoc.SelectionResumeV2)
	if err != nil {
		t.Fatal(err)
	}
	work := firewallipc.RoutedReferenceV3{Work: plan.Reference().Work, Lineage: plan.Reference().Lineage, Generation: strconv.FormatUint(plan.Reference().Generation, 10)}
	f.source.coldMu.Lock()
	f.source.cold = configpoc.RoutedColdAnchorV1{}
	f.source.coldMu.Unlock()
	if _, err := f.source.ResolveColdContinuationV1(ctx, work, "resume"); err == nil {
		t.Fatal("zero/uncaptured token authorized")
	}
	if err := f.source.CaptureColdAnchorV1(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := f.source.ResolveColdContinuationV1(ctx, work, "resume"); err != nil {
		t.Fatal("opaque captured active resume", err)
	}
	wrong := ref
	wrong.Selection = strings.Repeat("a", 64)
	if err := f.source.CaptureColdAnchorV1(ctx, wrong); err == nil {
		t.Fatal("caller tuple replaced opaque authority")
	}
	f.source.coldMu.Lock()
	retained := f.source.cold.Reference()
	f.source.coldMu.Unlock()
	if retained != ref {
		t.Fatal("failed capture discarded original anchor")
	}
	for _, purpose := range []string{"bootstrap", "confirm", "resume"} {
		if _, err := f.source.ResolveFencedContinuationV1(ctx, work, purpose); err == nil {
			t.Fatal("fenced active anchor authorized new work", purpose)
		}
	}
}

func TestRoutedIntegrityV3FencedPendingCannotAdmitNewConfirmationEffect(t *testing.T) {
	f := newRoutedIPCFixtureWithPolicyV3(t, configpoc.SelectionActionAuthorityV2)
	before, err := f.service.Status(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	edited := f.legacy.Config
	edited.Rules = append([]configpoc.Rule(nil), edited.Rules...)
	edited.Rules[0].Action = "deny"
	f.run(configpoc.OperationRequestV2{Kind: configpoc.OpStage, Config: &edited})
	seconds := uint64(30)
	pending := f.run(configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds})
	ref, err := f.reader.CaptureReferenceV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.integrity.Attach(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	// The helper fixture latches the real marker only after the new Confirm
	// Intent exists, then invokes the real fenced resolver with the old opaque
	// Pending anchor. No supplied success flag or synthetic plan is involved.
	f.corruptConfirm.Store(true)
	status, err := f.service.Status(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := f.service.Namespace(f.binding, "routed", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := f.service.Admit(f.binding, ns.ID, status.GlobalGeneration, configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Origin: pending.Operation.ID, Target: pending.Current.RunningRevision})
	if err != nil {
		t.Fatal(err)
	}
	result, executeErr := f.service.Execute(context.Background(), f.binding, operation.ID)
	if !errors.Is(executeErr, configpoc.ErrEngine) {
		t.Fatal("fenced confirmation did not report engine rejection", executeErr)
	}
	if result.Operation.Outcome == nil || result.Operation.Outcome.Code != "failed_rolled_back" || result.Current.RunningRevision != before.RunningRevision {
		t.Fatal("fenced newly admitted confirm published target", result.Operation.Outcome)
	}
	raw, exists, err := f.kernel.Observe(context.Background(), routedactivation.LegacyTable)
	if err != nil || !exists {
		t.Fatal(err)
	}
	if _, err := firewallnft.VerifyObservation(raw, f.legacy); err != nil {
		t.Fatal("original rollback not preserved", err)
	}
	if f.integrity.IntegrityPublicationAllowedV1() {
		t.Fatal("effect error retained publication")
	}
}
