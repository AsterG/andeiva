package configpoc

import (
	"context"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
)

const routedCompensationFeatureV1 = "configuration.routed-compensation.v1"

type routedCompensationCauseV1 string

const (
	routedCompensationOperationV1 routedCompensationCauseV1 = "operation"
	routedCompensationTimeoutV1   routedCompensationCauseV1 = "timeout"
)

// One record serves both DHCP roles. Keep the consumed record as a watermark
// until a newer Work replaces it. A consumed authorization cannot start work.
type routedCompensationRecordV1 struct {
	Version     int                       `json:"version"`
	Cause       routedCompensationCauseV1 `json:"cause"`
	Operation   string                    `json:"operation_id"`
	Scope       RoutedWorkScopeV1         `json:"scope"`
	Work        string                    `json:"work"`
	Lease       string                    `json:"lease"`
	Deadline    time.Time                 `json:"deadline"`
	BeforeOwned string                    `json:"before_owned"`
	Consumed    bool                      `json:"consumed"`
}

// RoutedCompensationAuthorizationV1 is evidence from the selected reader,
// rather than a request DTO or permission to restore a DHCP grant.
type RoutedCompensationAuthorizationV1 struct {
	record    routedCompensationRecordV1
	selection SelectionReferenceV2
	previous  string
	target    string
}

func (a RoutedCompensationAuthorizationV1) Selection() SelectionReferenceV2 { return a.selection }

func (a RoutedCompensationAuthorizationV1) Reference() RoutedWorkReferenceV1 {
	return RoutedWorkReferenceV1{Work: a.record.Work, Lineage: a.record.Scope.Lineage, Generation: a.record.Scope.Generation}
}

func validRoutedCompensationRecordV1(st v2State) bool {
	marked := hasFeatureV2(st, routedCompensationFeatureV1)
	if marked && (st.Configuration == nil || st.RecoveryReserveVersion != 1 ||
		!hasFeatureV2(st, v2RoutedFeature) || !hasFeatureV2(st, v2SharedReaderFeature)) {
		return false
	}
	a := st.RoutedCompensation
	if a == nil {
		return true
	}
	return marked && a.Version == 1 && (a.Cause == routedCompensationOperationV1 || a.Cause == routedCompensationTimeoutV1) &&
		a.Operation != "" && len(a.Operation) <= 128 && a.Scope.Version == 1 &&
		a.Scope.Lineage == st.Lineage && validRoutedIdentityV1(a.Scope.Identity) &&
		a.Scope.Generation > 0 && a.Scope.Generation-1 <= st.Generation && validHash(a.Work) && validHash(a.BeforeOwned) &&
		a.Lease != "" && len(a.Lease) <= 128 && !a.Deadline.IsZero() && a.Deadline.Location() == time.UTC
}

func preservesRoutedCompensationV1(previous, next v2State) bool {
	p, n := previous.RoutedCompensation, next.RoutedCompensation
	if p == nil {
		return n == nil || !n.Consumed
	}
	if n == nil {
		return false
	}
	if n.Work != p.Work {
		return p.Consumed && !n.Consumed && n.Scope.Generation > p.Scope.Generation && inspectionQuiescentV1(previous)
	}
	prior := *p
	prior.Consumed = n.Consumed
	return (!p.Consumed || n.Consumed) && prior == *n
}

func (a routedCompensationRecordV1) matches(plan RoutedSelectedPlanV1) bool {
	return plan.Valid() && plan.work.Kind != v2BootKind &&
		plan.Reference().Work == a.Work && plan.Scope() == a.Scope &&
		plan.Lease() == a.Lease && plan.Deadline().Equal(a.Deadline) &&
		plan.Transition().BeforeOwned == a.BeforeOwned && plan.previous.Composite.Hash != ""
}

func routedCompensationPlanV1(s *v2Store, identity networkexecutor.OwnedNamespaceIdentity, now time.Time) (RoutedSelectedPlanV1, error) {
	a := s.state.RoutedCompensation
	var zero RoutedSelectedPlanV1
	if a == nil || a.Scope.Identity != identity || now.IsZero() || s.state.Configuration == nil || s.state.Configuration.RecoveryRequired {
		return zero, ErrRecovery
	}
	cfg := s.state.Configuration
	if a.Cause == routedCompensationTimeoutV1 {
		if cfg.Intent != nil || cfg.Pending == nil || cfg.Pending.OriginCommit != a.Operation || now.Before(a.Deadline) {
			return zero, ErrRecovery
		}
		plan, _, err := selectedPendingReadbackV2(s)
		if err != nil || !a.matches(plan) {
			return zero, ErrRecovery
		}
		return plan, nil
	}
	in := cfg.Intent
	if a.Cause != routedCompensationOperationV1 || in == nil || a.Operation != in.Operation {
		return zero, ErrRecovery
	}
	plan, err := selectedRoutedPlanFromStoreV2(s, identity)
	if err != nil || !a.matches(plan) || !selectedPurposeV2(s, plan, SelectionRecoverV2) {
		return zero, ErrRecovery
	}
	return plan, nil
}

// ResolveCompensationV1 rechecks the current selection and pools. Its result
// has no effects. The future writer must consume it durably before an effect
// and retain the publication barrier while the restored state is verified.
func (r *RoutedSelectionReaderV2) ResolveCompensationV1(ctx context.Context, selected SelectionReferenceV2, operation string, work RoutedWorkReferenceV1) (RoutedCompensationAuthorizationV1, error) {
	return r.readCompensationV1(ctx, selected, operation, work, false)
}

// VerifyRestoredCompensationV1 checks trusted guardian and owned-state
// readback against the consumed record. It does not grant a second attempt.
// Callers retain the same publication barrier through finalization.
func (r *RoutedSelectionReaderV2) VerifyRestoredCompensationV1(ctx context.Context, selected SelectionReferenceV2, operation string, work RoutedWorkReferenceV1, receipt RoutedReceiptV1, beforeOwned string) error {
	a, err := r.readCompensationV1(ctx, selected, operation, work, true)
	if err != nil {
		return err
	}
	if receipt.Phase != "expired" || receipt.ID != a.record.Lease ||
		!receipt.Deadline.Equal(a.record.Deadline) || receipt.Previous != a.previous ||
		receipt.Target != a.target || beforeOwned != a.record.BeforeOwned {
		return ErrRecovery
	}
	return nil
}

func (r *RoutedSelectionReaderV2) readCompensationV1(ctx context.Context, selected SelectionReferenceV2, operation string, work RoutedWorkReferenceV1, consumed bool) (out RoutedCompensationAuthorizationV1, resultErr error) {
	if r == nil || ctx == nil {
		return out, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return out, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out, resultErr = RoutedCompensationAuthorizationV1{}, ErrRecovery
		}
	}()
	a := v.store.state.RoutedCompensation
	if selected != v.ref || a == nil || a.Operation != operation || a.Consumed != consumed {
		return out, ErrRecovery
	}
	plan, err := routedCompensationPlanV1(v.store, r.options.Identity, time.Now().UTC())
	if err != nil || plan.Reference() != work {
		return out, ErrRecovery
	}
	if err := r.revalidate(ctx, v); err != nil {
		return out, err
	}
	previous := plan.previous.Composite.Hash
	if plan.Cold() {
		previous = "" // The original guardian armed against the empty baseline.
	}
	return RoutedCompensationAuthorizationV1{record: *a, selection: selected, previous: previous, target: plan.target.Composite.Hash}, nil
}
