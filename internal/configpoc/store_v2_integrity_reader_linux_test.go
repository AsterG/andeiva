//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func integrityFilesV1(t *testing.T, area *os.Root) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(area.Name())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, entry := range entries {
		data, err := area.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = checkpointDigest(data) + info.Mode().String()
	}
	return out
}

func TestIntegrityReaderV1CompleteAcceptedAndPotentialClosing(t *testing.T) {
	for _, kind := range []string{OpStage, OpCommit} {
		t.Run(kind, func(t *testing.T) {
			r, c, p := selectedReaderFixtureV2(t)
			doc, objects := compositeRoutedFixture(t, true)
			fw := objects[doc.Domains.Firewall.Revision].Config
			request := v2Request{Kind: OpStage, Config: &fw}
			if kind == OpCommit {
				if _, _, err := routedRequestV2(t, c, p, request); err != nil {
					t.Fatal(err)
				}
				seconds := uint64(60)
				request = v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}
			}
			ns, err := c.store.namespace(p.Subject, "routed", c.now(), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			op, err := c.store.admit(p.Subject, ns.ID, c.store.state.Generation, request, c.now())
			if err != nil {
				t.Fatal(err)
			}
			if op.State != "accepted" || !inspectionQuiescentV1(c.store.state) {
				t.Fatal("fixture not accepted and quiescent")
			}
			if kind == OpCommit && len(c.store.state.ClosingCredits) == 0 {
				t.Fatal("missing potential escrow")
			}
			before := integrityFilesV1(t, c.store.root)
			state := clone(c.store.state)
			start := time.Now()
			ref, err := r.InspectionReference(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.InspectQuiescentV1(context.Background(), ref)
			if err != nil || result.State != IntegrityCompleteV1 || result.Selection != ref {
				t.Fatal(result, err)
			}
			if !reflect.DeepEqual(before, integrityFilesV1(t, c.store.root)) || !reflect.DeepEqual(state, c.store.state) {
				t.Fatal("inspection mutated state/files")
			}
			t.Logf("header+full inspection: %s, store files: %d; accepted operation and potential escrow retained", time.Since(start), len(before))
		})
	}
}

func TestIntegrityReaderV1CorrelationPolicyAndCancellation(t *testing.T) {
	r, c, p := selectedReaderFixtureV2(t)
	ref, err := r.InspectionReference(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r.options.Policy = SelectionActionAuthorityV2
	if result, err := r.InspectQuiescentV1(context.Background(), ref); !errors.Is(err, ErrDenied) || result.State == IntegrityCompleteV1 {
		t.Fatal("action policy claimed full inspection", result, err)
	}
	r.options.Policy = SelectionFullHistoryV2
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := r.InspectQuiescentV1(ctx, ref); !errors.Is(err, context.Canceled) || result.State != IntegrityCancelledV1 {
		t.Fatal(result, err)
	}
	for _, mutate := range []func(*SelectionReferenceV2){func(v *SelectionReferenceV2) { v.Generation++ }, func(v *SelectionReferenceV2) { v.Sequence++ }, func(v *SelectionReferenceV2) { v.Lineage = "foreign" }, func(v *SelectionReferenceV2) { v.WorkHash = v.State }, func(v *SelectionReferenceV2) { v.Previous = "" }, func(v *SelectionReferenceV2) { v.Mode = "active" }} {
		bad := ref
		mutate(&bad)
		if result, err := r.InspectQuiescentV1(context.Background(), bad); !errors.Is(err, ErrConflict) || result.State != IntegrityStaleV1 {
			t.Fatal("foreign tuple", result, err)
		}
	}
	if _, err = c.store.namespace(p.Subject, "routed", c.now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	if result, err := r.InspectQuiescentV1(context.Background(), ref); !errors.Is(err, ErrConflict) || result.State != IntegrityStaleV1 {
		t.Fatal("old selector", result, err)
	}
}

func TestIntegrityReaderV1HeaderDoesNotWalkCorruptHistory(t *testing.T) {
	r, c, p := selectedReaderFixtureV2(t)
	doc, objects := compositeRoutedFixture(t, true)
	fw := objects[doc.Domains.Firewall.Revision].Config
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &fw}); err != nil {
		t.Fatal(err)
	}
	hash := c.store.state.Configuration.AuditTip
	if !validHash(hash) {
		t.Fatal("fixture lacks audit")
	}
	name, _ := v2ObjectName(hash)
	if err := c.store.root.WriteFile(name, []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	before := integrityFilesV1(t, c.store.root)
	ref, err := r.InspectionReference(context.Background())
	if err != nil {
		t.Fatal("header walked historical audit", err)
	}
	result, err := r.InspectQuiescentV1(context.Background(), ref)
	if err == nil || result.State != IntegrityFencedV1 {
		t.Fatal("stable hash-invalid history not classified", result, err)
	}
	if !reflect.DeepEqual(before, integrityFilesV1(t, c.store.root)) {
		t.Fatal("failure changed files")
	}
}

func TestIntegrityReaderV1IntentRejectedBeforeHistory(t *testing.T) {
	r, c, ref := selectedIntentFixtureV2(t)
	captured, err := r.CaptureReferenceV1(context.Background())
	if err != nil || captured != ref {
		t.Fatal("capture lost intent", captured, err)
	}
	name, _ := v2ObjectName(c.store.state.Configuration.AuditTip)
	if err := c.store.root.WriteFile(name, []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := r.InspectionReference(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatal("intent did not stop header", err)
	}
	result, err := r.InspectQuiescentV1(context.Background(), ref)
	if !errors.Is(err, ErrConflict) || result.State != IntegrityUnavailableV1 {
		t.Fatal("inspection crossed live intent", result, err)
	}
}

func TestIntegrityReaderV1QuiescencePredicate(t *testing.T) {
	base := v2State{Configuration: &v2Configuration{}}
	if !inspectionQuiescentV1(base) {
		t.Fatal("empty control state not quiescent")
	}
	for _, change := range []func(*v2Configuration){func(v *v2Configuration) { v.Pending = &v2Confirmation{} }, func(v *v2Configuration) { v.Intent = &v2CoordinatorIntent{} }, func(v *v2Configuration) { v.RecoveryRequired = true }} {
		bad := clone(base)
		change(bad.Configuration)
		if inspectionQuiescentV1(bad) {
			t.Fatal("live recovery work accepted")
		}
	}
	if inspectionQuiescentV1(v2State{}) {
		t.Fatal("missing configuration accepted")
	}
}

func TestIntegrityReaderV1UnavailableIsNeverComplete(t *testing.T) {
	for _, kind := range []string{"profile", "foreign-owner", "pending-file", "budget", "missing-object", "pool"} {
		t.Run(kind, func(t *testing.T) {
			r, c, _ := selectedReaderFixtureV2(t)
			ref, err := r.InspectionReference(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "profile":
				if err = os.Chmod(filepath.Join(c.store.root.Name(), "selected.json"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				r.options.Access.OwnerUID++
			case "pending-file":
				if err = c.store.root.WriteFile("selection.pending", []byte("{}"), 0640); err != nil {
					t.Fatal(err)
				}
			case "budget":
				r.options.Budget.Objects = 1
			case "missing-object":
				name, _ := v2ObjectName(c.store.selection.State)
				if err = c.store.root.Remove(name); err != nil {
					t.Fatal(err)
				}
			case "pool":
				if err = r.options.Plan.Close(); err != nil {
					t.Fatal(err)
				}
			}
			result, err := r.InspectQuiescentV1(context.Background(), ref)
			if err == nil || result.State != IntegrityUnavailableV1 {
				t.Fatal("uncertainty misclassified", result, err)
			}
		})
	}
	for _, r := range []*RoutedSelectionReaderV2{nil, {}} {
		if _, err := r.InspectionReference(context.Background()); err == nil {
			t.Fatal("invalid reader accepted")
		}
		if result, err := r.InspectQuiescentV1(context.Background(), SelectionReferenceV2{}); err == nil || result.State == IntegrityCompleteV1 {
			t.Fatal(result, err)
		}
	}
}

func TestIntegrityReaderV1PendingRejectsBeforeHistory(t *testing.T) {
	c, a, p, fw := boundaryCoordinatorFixtureV2(t)
	r := sharedBoundaryReaderV2(t, c, a)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpStage, Config: &fw}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(60)
	if _, _, err := routedRequestV2(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); err != nil {
		t.Fatal(err)
	}
	if c.store.state.Configuration.Pending == nil {
		t.Fatal("missing real pending fixture")
	}
	ref, err := r.CaptureReferenceV1(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	name, _ := v2ObjectName(c.store.state.Configuration.AuditTip)
	if err = c.store.root.WriteFile(name, []byte("{}"), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err = r.InspectionReference(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatal("pending crossed header gate", err)
	}
	result, err := r.InspectQuiescentV1(context.Background(), ref)
	if !errors.Is(err, ErrConflict) || result.State != IntegrityUnavailableV1 {
		t.Fatal(result, err)
	}
}
