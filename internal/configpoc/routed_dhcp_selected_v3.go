package configpoc

import (
	"context"
	"reflect"

	"github.com/AsterG/andeiva/internal/networkexecutor"
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
	Work   string           `json:"work"`
	Phase  string           `json:"phase"`
	Bundle *v2ReserveBundle `json:"bundle"`
	Audit  string           `json:"audit,omitempty"`
}

// RoutedDHCPSelectedV3 has no exported authority fields. Only the selected
// reader can issue it after checking G1, physical R2 bindings and final selector.
type RoutedDHCPSelectedV3 struct {
	work  v3RoutedDHCPWork
	ref   SelectionReferenceV2
	phase string
}

func (p RoutedDHCPSelectedV3) Reference() SelectionReferenceV2 { return p.ref }
func (p RoutedDHCPSelectedV3) Snapshot() networkexecutor.LeaseSelectedSnapshotV3 {
	return clone(p.work.Snapshot)
}
func (p RoutedDHCPSelectedV3) Epoch() uint64   { return p.work.Epoch }
func (p RoutedDHCPSelectedV3) Phase() string   { return p.phase }
func (p RoutedDHCPSelectedV3) Running() string { return p.work.Running }

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
	if d.Phase != "prepared" && d.Phase != "applied" && d.Phase != "withdrawn" {
		return false
	}
	return (d.Phase == "withdrawn" && validHash(d.Audit)) || (d.Phase != "withdrawn" && d.Audit == "")
}

func preservesRoutedDHCPV3(before, next v2State) bool {
	a, b := before.RoutedDHCP, next.RoutedDHCP
	if a == nil {
		return before.RoutedDHCPLast == next.RoutedDHCPLast
	}
	if b == nil {
		_, hash, err := v2Canonical(a)
		return a.Phase == "withdrawn" && err == nil && next.RoutedDHCPLast == hash
	}
	if before.RoutedDHCPLast != next.RoutedDHCPLast || a.Work != b.Work || !reserveJSONEqualV2(a.Bundle, b.Bundle) || before.Generation != next.Generation {
		return false
	}
	if a.Phase == b.Phase {
		return a.Audit == b.Audit
	}
	return (a.Phase == "prepared" && (b.Phase == "applied" || b.Phase == "withdrawn")) || (a.Phase == "applied" && b.Phase == "withdrawn")
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
	if d.Phase == "withdrawn" {
		var audit v2CoordinatorAudit
		if load(d.Audit, &audit) != nil || audit.Operation != in.Operation || audit.Kind != v3RoutedDHCPKind || audit.Result != "withdrawn" || audit.Generation != w.Generation || audit.Running != w.Running || audit.Sequence > st.Configuration.AuditSequence {
			return ErrRecovery
		}
	}
	return nil
}

// ResolveDHCPCurrentV3 never accepts an arbitrary work hash as owner evidence.
// The caller must retain the publication/owner barrier through kernel effects.
func (r *RoutedSelectionReaderV2) ResolveDHCPCurrentV3(ctx context.Context, expected string) (out RoutedDHCPSelectedV3, resultErr error) {
	if r == nil || !validHash(expected) {
		return RoutedDHCPSelectedV3{}, ErrRecovery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	v, err := r.read(ctx)
	if err != nil {
		return RoutedDHCPSelectedV3{}, err
	}
	defer func() {
		if v.graph.closeSelectedV2() != nil {
			out = RoutedDHCPSelectedV3{}
			resultErr = ErrRecovery
		}
	}()
	d := v.store.state.RoutedDHCP
	if d == nil || d.Work != expected || validateRoutedDHCPSelectedV3(v.store.state, v.store.readObject) != nil {
		return RoutedDHCPSelectedV3{}, ErrRecovery
	}
	w, err := loadRoutedDHCPWorkV3(d.Work, v.store.state.Lineage, v.store.readObject)
	if err != nil || w.Snapshot.Identity != r.options.Identity {
		return RoutedDHCPSelectedV3{}, ErrRecovery
	}
	if err = r.revalidate(ctx, v); err != nil {
		return RoutedDHCPSelectedV3{}, err
	}
	ref := v.ref
	ref.WorkHash = d.Work
	return RoutedDHCPSelectedV3{work: w, ref: ref, phase: d.Phase}, nil
}
