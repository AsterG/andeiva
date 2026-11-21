package configpoc

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/routedmodel"
)

const v3RoutedDHCPFeature = "configuration.routed-dhcp-selected.v3"
const v3RoutedDHCPKind = "routed_dhcp_lease"

// DHCP work is an internal, versioned selected-store extension. It never changes
// the static network plan or converts BOOTTIME into a wall-clock confirmation.
type v3RoutedDHCPWork struct {
	Version       int                                     `json:"version"`
	Lineage       string                                  `json:"lineage"`
	Generation    uint64                                  `json:"generation,string"`
	Running       string                                  `json:"running"`
	Configuration string                                  `json:"configuration"`
	Epoch         uint64                                  `json:"epoch,string"`
	Snapshot      networkexecutor.LeaseSelectedSnapshotV3 `json:"snapshot"`
}

type v3RoutedDHCPState struct {
	RebootRetirement *RoutedRebootScopeEvidenceV4 `json:"reboot_retirement,omitempty"`
	Work             string                       `json:"work"`
	Phase            string                       `json:"phase"`
	Bundle           *v2ReserveBundle             `json:"bundle"`
	Audit            string                       `json:"audit,omitempty"`
	Retirement       *RoutedFreshScopeEvidenceV3  `json:"scope_retirement,omitempty"`
}

func routedDHCPTerminalV3(d *v3RoutedDHCPState) bool {
	return d != nil && (d.Phase == "withdrawn" || d.Phase == "scope_retired")
}

// RoutedDHCPSelectedV3 has no exported authority fields. Only the selected
// reader can issue it after checking active authority, physical R2 bindings and
// final selector. An action reader relies on its runtime's separate full-G1 gate.
type RoutedDHCPSelectedV3 struct {
	work         v3RoutedDHCPWork
	ref          SelectionReferenceV2
	phase        string
	running      string
	pending      bool
	confirmation *RoutedReceiptV1
	baseline     *routedmodel.AdmissionMarks
}

func (p RoutedDHCPSelectedV3) Reference() SelectionReferenceV2 { return p.ref }
func (p RoutedDHCPSelectedV3) Snapshot() networkexecutor.LeaseSelectedSnapshotV3 {
	return clone(p.work.Snapshot)
}
func (p RoutedDHCPSelectedV3) Epoch() uint64   { return p.work.Epoch }
func (p RoutedDHCPSelectedV3) Phase() string   { return p.phase }
func (p RoutedDHCPSelectedV3) Running() string { return p.running }

func (p RoutedDHCPSelectedV3) PendingPolicyV4() bool { return p.pending }

// BaselineAdmissionMarksV4 is issued only for the initial selected grant.
func (p RoutedDHCPSelectedV3) BaselineAdmissionMarksV4() *routedmodel.AdmissionMarks {
	return clone(p.baseline)
}

// MatchesPendingPolicyV4 must be paired with a physical observation made by
// the helper. Only a selected, successful grouped Commit can arm this proof.
func (p RoutedDHCPSelectedV3) MatchesPendingPolicyV4(receipt RoutedReceiptV1, running string) bool {
	want := p.confirmation
	return p.pending && want != nil && receipt.Phase == "pending" && receipt.ID == want.ID &&
		receipt.Previous == want.Previous && receipt.Target == want.Target &&
		running == p.running && receipt.Deadline.Equal(want.Deadline) && time.Now().Before(want.Deadline)
}

func validRoutedDHCPShapeV3(st v2State) bool {
	if st.RoutedDHCPLast != "" && (!validHash(st.RoutedDHCPLast) || !hasFeatureV2(st, v3RoutedDHCPFeature) || st.RecoveryReserveVersion != 1) {
		return false
	}
	d := st.RoutedDHCP
	if d == nil {
		return true
	}
	if !hasFeatureV2(st, v3RoutedDHCPFeature) || st.RecoveryReserveVersion != 1 || st.Configuration == nil || !validHash(d.Work) || !validReserveBundleV2(d.Bundle) || d.Bundle.Scope.Kind != "recovery" || d.Bundle.Scope.Domain != "routed" || d.Bundle.Scope.Fingerprint != d.Work || d.Bundle.Scope.Lineage != st.Lineage || d.Bundle.PlanIntent == nil || d.Bundle.PlanIntent.DHCPWork != d.Work || d.Bundle.PlanIntent.RoutedWork != "" || d.Bundle.PlanIntent.Kind != v3RoutedDHCPKind || !d.Bundle.PlanIntent.Recovery || d.Bundle.PlanIntent.BootID != nil || d.Bundle.PlanIntent.GuardDeadline != nil || d.Bundle.ClosingEscrow != nil {
		return false
	}
	if d.Phase != "prepared" && d.Phase != "applied" && !routedDHCPTerminalV3(d) {
		return false
	}
	if d.Phase == "scope_retired" {
		_, valid := compareScopeV4(d.Retirement, d.RebootRetirement)
		if !valid || d.Retirement != nil && !hasFeatureV2(st, v3RoutedFreshScopeFeature) || !rebootScopeDeclaredV4(st, d.RebootRetirement) {
			return false
		}
	} else if d.Retirement != nil || d.RebootRetirement != nil {
		return false
	}
	return (routedDHCPTerminalV3(d) && validHash(d.Audit)) || (!routedDHCPTerminalV3(d) && d.Audit == "")
}

func preservesRoutedDHCPV3(before, next v2State) bool {
	a, b := before.RoutedDHCP, next.RoutedDHCP
	if a == nil {
		return before.RoutedDHCPLast == next.RoutedDHCPLast
	}
	if b == nil {
		_, hash, err := v2Canonical(a)
		return routedDHCPTerminalV3(a) && err == nil && next.RoutedDHCPLast == hash
	}
	if before.RoutedDHCPLast != next.RoutedDHCPLast || a.Work != b.Work || !reserveJSONEqualV2(a.Bundle, b.Bundle) || before.Generation != next.Generation {
		return false
	}
	if a.Phase == b.Phase {
		return a.Audit == b.Audit && reflect.DeepEqual(a.Retirement, b.Retirement) && reflect.DeepEqual(a.RebootRetirement, b.RebootRetirement)
	}
	return (a.Phase == "prepared" && (b.Phase == "applied" || routedDHCPTerminalV3(b))) || (a.Phase == "applied" && routedDHCPTerminalV3(b))
}

func loadRoutedDHCPWorkV3(hash, lineage string, load func(string, any) error) (v3RoutedDHCPWork, error) {
	var w v3RoutedDHCPWork
	if !validHash(hash) || load == nil || load(hash, &w) != nil || w.Version != 3 || w.Lineage != lineage || w.Generation == 0 || w.Epoch == 0 || !validHash(w.Running) || !validHash(w.Configuration) {
		return w, ErrRecovery
	}
	canonical, err := networkexecutor.CanonicalLeaseSelectedSnapshotV3(w.Snapshot)
	if err != nil || !reflect.DeepEqual(canonical, w.Snapshot) {
		return w, ErrRecovery
	}
	_, actual, err := v2Canonical(w)
	if err != nil || actual != hash {
		return w, ErrRecovery
	}
	var cfg v2Configuration
	if load(w.Configuration, &cfg) != nil || !validV2Configuration(&cfg) || cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired || cfg.Running.Hash != w.Running || cfg.Running.Config.Domains.Network == nil || cfg.Running.Config.Domains.Network.Revision != w.Snapshot.Desired.Hash {
		return w, ErrRecovery
	}
	return w, nil
}

func validateRoutedDHCPSelectedV3(st v2State, load func(string, any) error) error {
	if !validRoutedDHCPShapeV3(st) {
		return ErrRecovery
	}
	if st.RoutedDHCPLast != "" {
		var last v3RoutedDHCPState
		if load(st.RoutedDHCPLast, &last) != nil || validateRoutedDHCPTerminalV3(last, st.Lineage, load) != nil {
			return ErrRecovery
		}
		if last.Phase == "scope_retired" && (last.Retirement != nil && !hasFeatureV2(st, v3RoutedFreshScopeFeature) || !rebootScopeDeclaredV4(st, last.RebootRetirement)) {
			return ErrRecovery
		}
	}
	d := st.RoutedDHCP
	if d == nil {
		return nil
	}
	w, err := loadRoutedDHCPWorkV3(d.Work, st.Lineage, load)
	if err != nil || w.Generation != st.Generation || w.Running != st.Configuration.Running.Hash || st.Configuration.Intent != nil || st.Configuration.Pending != nil || d.Bundle.Scope.Global != w.Generation || d.Bundle.Scope.Generation != w.Generation {
		return ErrRecovery
	}
	in := d.Bundle.PlanIntent
	if in.Operation != reserveWorkV2(d.Bundle) || in.Previous != w.Configuration || in.Target != w.Configuration || in.TargetGeneration != w.Generation || in.Subject != "" || in.Lease != "" || in.OriginCommit != "" || !d.Bundle.Scope.Deadline.IsZero() || d.Bundle.Scope.Lease != "" {
		return ErrRecovery
	}
	if d.Phase == "scope_retired" {
		proof, valid := compareScopeV4(d.Retirement, d.RebootRetirement)
		if !valid || proof.old != w.Snapshot.Identity || proof.work != d.Work {
			return ErrRecovery
		}
	}
	if routedDHCPTerminalV3(d) {
		var audit v2CoordinatorAudit
		if load(d.Audit, &audit) != nil || audit.Operation != in.Operation || audit.Kind != v3RoutedDHCPKind || audit.Result != d.Phase || audit.Generation != w.Generation || audit.Running != w.Running || audit.Sequence > st.Configuration.AuditSequence {
			return ErrRecovery
		}
	}
	return nil
}

// ErrRoutedDHCPBindingMismatchV4 is a verified contradiction in a readable,
// revalidated selection. It is also ErrRecovery and grants no actions.
var ErrRoutedDHCPBindingMismatchV4 = errors.New("ANDEIVA_ROUTED_DHCP_BINDING_MISMATCH")

// ResolveDHCPCurrentV3 never accepts an arbitrary work hash as owner evidence.
// The caller must retain the publication/owner barrier through kernel effects.
func (r *RoutedSelectionReaderV2) ResolveDHCPCurrentV3(ctx context.Context, expected string) (RoutedDHCPSelectedV3, error) {
	return r.resolveDHCPLeaseAuthority(ctx, expected, false)
}

// ResolveDHCPLeaseAuthorityV4 retains the original grant and its reserve
// scope while reporting the revision proven by the current selection.
func (r *RoutedSelectionReaderV2) ResolveDHCPLeaseAuthorityV4(ctx context.Context, expected string) (RoutedDHCPSelectedV3, error) {
	return r.resolveDHCPLeaseAuthority(ctx, expected, true)
}

func (r *RoutedSelectionReaderV2) resolveDHCPLeaseAuthority(ctx context.Context, expected string, acceptContinuation bool) (out RoutedDHCPSelectedV3, resultErr error) {
	if r == nil || !validHash(expected) {
		return RoutedDHCPSelectedV3{}, ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// This path resolves additional Work dependencies before its single final
	// validation. No candidate or proof escapes before that validation.
	v, err := r.readCandidateWithGateV2(ctx, nil)
	if err != nil {
		return RoutedDHCPSelectedV3{}, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = RoutedDHCPSelectedV3{}
			resultErr = ErrRecovery
		}
	}()
	st := v.store.state
	d := st.RoutedDHCP
	if d == nil || d.Work != expected || !validRoutedDHCPShapeV3(st) {
		if err = r.revalidate(ctx, v); err != nil {
			return RoutedDHCPSelectedV3{}, err
		}
		return RoutedDHCPSelectedV3{}, errors.Join(ErrRecovery, ErrRoutedDHCPBindingMismatchV4)
	}
	var header *v4RoutedDHCPConfigurationState
	if acceptContinuation {
		header = st.RoutedDHCPConfiguration
	}
	var confirmation *RoutedReceiptV1
	if header == nil {
		if validateRoutedDHCPSelectedV3(st, v.store.readObject) != nil {
			return out, ErrRecovery
		}
	} else {
		view, e := routedDHCPConfigurationViewV4Read(header, st, v.store.readObject, v.store.lookupRetained, routedDHCPConfigurationHeaderV4)
		if e != nil {
			return out, ErrRecovery
		}
		if current := view.current; view.pending == nil && current != nil && current.transition.Kind == "grouped" {
			if pending := current.target.Pending; pendingOriginMatchesV2(pending, current.operation) {
				confirmation = &RoutedReceiptV1{ID: pending.Lease, Previous: current.before.Running.Hash,
					Target: current.target.Running.Hash, Deadline: pending.Deadline}
			}
		}
	}
	w, err := loadRoutedDHCPWorkV3(d.Work, st.Lineage, v.store.readObject)
	if err != nil {
		return RoutedDHCPSelectedV3{}, ErrRecovery
	}
	var baseline *routedmodel.AdmissionMarks
	if acceptContinuation && header == nil && d.Phase == "applied" && st.RoutedBootMarks != nil {
		verified, e := loadRoutedBootMarkReservationV1(st.RoutedBootMarks, st.Lineage, v.store.readObject)
		if e != nil || verified.Work != d.Work || verified.Scope != w.Snapshot.Identity ||
			verified.Operation != retainedDHCPBaselineMarksV4 || verified.Before != verified.Target ||
			!sameRoutedAdmissionMarksV1(verified.Applied, verified.Restored) {
			return out, ErrRecovery
		}
		baseline = &verified.Applied
	}
	if err = r.revalidate(ctx, v); err != nil {
		return RoutedDHCPSelectedV3{}, err
	}
	if w.Snapshot.Identity != r.options.Identity {
		return RoutedDHCPSelectedV3{}, errors.Join(ErrRecovery, ErrRoutedDHCPBindingMismatchV4)
	}
	ref := v.ref
	ref.WorkHash = d.Work
	running := w.Running
	if header != nil {
		ref.Mode = "dhcp-configuration-v4"
		running = st.Configuration.Running.Hash
	}
	return RoutedDHCPSelectedV3{work: w, ref: ref, phase: d.Phase, running: running,
		pending: header != nil && st.Configuration.Pending != nil, confirmation: confirmation, baseline: baseline}, nil
}
