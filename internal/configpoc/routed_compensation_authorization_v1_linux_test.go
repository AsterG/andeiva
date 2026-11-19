//go:build linux

package configpoc

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRoutedCompensationAuthorizationV1Selected(t *testing.T) {
	ctx := context.Background()
	reader, coordinator, unmarked := selectedIntentFixtureV2(t)
	store := coordinator.store
	plan, err := reader.Resolve(ctx, unmarked, SelectionRecoverV2)
	if err != nil {
		t.Fatal(err)
	}
	work := plan.Reference()
	operation := store.state.Configuration.Intent.Operation
	before := journalFiles(t, store.root.Name())
	if _, err := reader.ResolveCompensationV1(ctx, unmarked, operation, work); !errors.Is(err, ErrRecovery) {
		t.Fatal("authorization was inferred from a legacy intent", err)
	}
	if !reflect.DeepEqual(before, journalFiles(t, store.root.Name())) {
		t.Fatal("refusal changed the store")
	}

	state := clone(store.state)
	addFeatureV2(&state, routedCompensationFeatureV1)
	state.RoutedCompensation = &routedCompensationRecordV1{
		Version: 1, Cause: routedCompensationOperationV1, Operation: operation,
		Scope: plan.Scope(), Work: work.Work, Lease: plan.Lease(), Deadline: plan.Deadline(),
		BeforeOwned: plan.Transition().BeforeOwned,
	}
	if err := store.publish(state); err != nil {
		t.Fatal("publish fixture authorization", err)
	}
	selected, err := reader.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []SelectionReaderPolicyV2{SelectionFullHistoryV2, SelectionActionAuthorityV2} {
		opts := reader.options
		opts.Policy = policy
		r, err := NewRoutedSelectionReaderV2(reader.area, opts)
		if err != nil {
			t.Fatal(err)
		}
		auth, err := r.ResolveCompensationV1(ctx, selected, operation, work)
		if err != nil || auth.Selection() != selected || auth.Reference() != work {
			t.Fatal(policy, "exact authorization rejected", err)
		}
		before := journalFiles(t, store.root.Name())
		if _, err := r.ResolveCompensationV1(ctx, selected, operation+"-foreign", work); !errors.Is(err, ErrRecovery) {
			t.Fatal("foreign operation", err)
		}
		if _, err := r.ResolveCompensationV1(ctx, unmarked, operation, work); !errors.Is(err, ErrRecovery) {
			t.Fatal("stale selection", err)
		}
		foreign := work
		foreign.Generation++
		if _, err := r.ResolveCompensationV1(ctx, selected, operation, foreign); !errors.Is(err, ErrRecovery) {
			t.Fatal("foreign Work", err)
		}
		r.options.Identity.BootID = "80000000-0000-4000-8000-000000000001"
		if _, err := r.ResolveCompensationV1(ctx, selected, operation, work); err == nil {
			t.Fatal("foreign boot")
		}
		if !reflect.DeepEqual(before, journalFiles(t, store.root.Name())) {
			t.Fatal("reader or refusal changed the store")
		}
	}

	state = clone(store.state)
	state.RoutedCompensation.Consumed = true
	if err := store.publish(state); err != nil {
		t.Fatal("publish consumed fixture", err)
	}
	// A fresh reader has no in-memory knowledge of the consumption.
	reader, err = NewRoutedSelectionReaderV2(reader.area, reader.options)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := reader.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ResolveCompensationV1(ctx, consumed, operation, work); !errors.Is(err, ErrRecovery) {
		t.Fatal("consumed authorization could be reused", err)
	}
	receipt := RoutedReceiptV1{
		Phase: "expired", ID: plan.Lease(), Deadline: plan.Deadline(),
		Previous: plan.previous.Composite.Hash, Target: plan.target.Composite.Hash,
	}
	if plan.Cold() {
		receipt.Previous = ""
	}
	for _, test := range []struct {
		name string
		edit func(*RoutedReceiptV1, *string)
	}{
		{"pending", func(g *RoutedReceiptV1, _ *string) { g.Phase = "pending" }},
		{"blocked", func(g *RoutedReceiptV1, _ *string) { g.Phase = "blocked" }},
		{"rearmed", func(g *RoutedReceiptV1, _ *string) { g.Deadline = g.Deadline.Add(time.Second) }},
		{"foreign-lease", func(g *RoutedReceiptV1, _ *string) { g.ID += "-foreign" }},
		{"foreign-owned", func(_ *RoutedReceiptV1, owned *string) { *owned = plan.Transition().TargetOwned }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad, owned := receipt, plan.Transition().BeforeOwned
			test.edit(&bad, &owned)
			if err := reader.VerifyRestoredCompensationV1(ctx, consumed, operation, work, bad, owned); !errors.Is(err, ErrRecovery) {
				t.Fatal("unproved restoration accepted", err)
			}
		})
	}
	if err := reader.VerifyRestoredCompensationV1(ctx, consumed, operation, work, receipt, plan.Transition().BeforeOwned); err != nil {
		t.Fatal("exact restored readback rejected", err)
	}
	state = clone(store.state)
	state.RoutedCompensation.Consumed = false
	if err := store.publish(state); err == nil {
		t.Fatal("durable consumption could be reset")
	}
	state.RoutedCompensation = nil
	if err := store.publish(state); err == nil {
		t.Fatal("durable consumption could be removed")
	}
	state = clone(store.state)
	state.Configuration.RecoveryRequired = true
	if err := store.publish(state); err != nil {
		t.Fatal("could not retain a closed recovery selection", err)
	}
	closed, err := reader.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.VerifyRestoredCompensationV1(ctx, consumed, operation, work, receipt, plan.Transition().BeforeOwned); !errors.Is(err, ErrRecovery) {
		t.Fatal("readback survived a new recovery selection", err)
	}
	if err := reader.VerifyRestoredCompensationV1(ctx, closed, operation, work, receipt, plan.Transition().BeforeOwned); !errors.Is(err, ErrRecovery) {
		t.Fatal("closed recovery became a restored publication", err)
	}
}

func TestRoutedCompensationKeepsOriginalConfirmDeadlineV1(t *testing.T) {
	c, authority, principal, cfg := boundaryCoordinatorFixtureV2(t)
	reader := sharedBoundaryReaderV2(t, c, authority)
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpStage, Config: &cfg}); err != nil {
		t.Fatal(err)
	}
	seconds := uint64(60)
	if _, _, err := routedRequestV2(t, c, principal, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}); err != nil {
		t.Fatal(err)
	}
	plan, work, err := selectedPendingReadbackV2(c.store)
	if err != nil {
		t.Fatal(err)
	}
	deadline := plan.Deadline()
	state := clone(c.store.state)
	addFeatureV2(&state, routedCompensationFeatureV1)
	state.RoutedCompensation = &routedCompensationRecordV1{
		Version: 1, Cause: routedCompensationTimeoutV1, Operation: state.Configuration.Pending.OriginCommit,
		Scope: plan.Scope(), Work: work, Lease: plan.Lease(), Deadline: deadline,
		BeforeOwned: plan.Transition().BeforeOwned,
	}
	if err := c.store.publish(state); err != nil {
		t.Fatal(err)
	}
	if _, err := routedCompensationPlanV1(c.store, reader.options.Identity, deadline.Add(-time.Nanosecond)); !errors.Is(err, ErrRecovery) {
		t.Fatal("pending authorization could beat Confirm", err)
	}
	atDeadline, err := routedCompensationPlanV1(c.store, reader.options.Identity, deadline)
	if err != nil || atDeadline.Reference() != plan.Reference() || !atDeadline.Deadline().Equal(deadline) {
		t.Fatal("deadline did not select the original Work", err)
	}
	state = clone(c.store.state)
	state.RoutedCompensation.Deadline = deadline.Add(time.Second)
	if err := c.store.publish(state); err == nil {
		t.Fatal("previously selected deadline could be extended")
	}
}

func TestRoutedCompensationV1PriorReader(t *testing.T) {
	if *reclaimOldReader == "" {
		t.Skip("supply the historical shared-reader binary via -reclaim-old-reader")
	}
	_, coordinator, _ := selectedIntentFixtureV2(t)
	store := coordinator.store
	area, budget, access, reserves := store.root, store.budget, *store.access, store.reserves
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	run := func(want string) {
		t.Helper()
		before := journalFiles(t, area.Name())
		cmd := exec.Command(*reclaimOldReader, "-test.v", "-test.run=^TestCompensationCompatibilityProbe$", "-compensation-probe-area="+area.Name())
		output, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(output), want) || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
			t.Fatalf("historical shared reader: %v %s", err, output)
		}
	}
	run("COMPENSATION_READER_ACCEPTED")
	store, err := openSharedStoreV2(area, budget, access)
	if err != nil {
		t.Fatal(err)
	}
	store.reserves = reserves
	state := clone(store.state)
	addFeatureV2(&state, routedCompensationFeatureV1)
	if err := store.publish(state); err != nil {
		t.Fatal("test setup could not publish the required feature", err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	run("COMPENSATION_READER_REJECTED")
	store, err = openSharedStoreV2(area, budget, access)
	if err != nil {
		t.Fatal("current shared reader rejected the marker", err)
	}
	defer store.close()
}
