package configpoc

import (
	"bytes"
	"context"
	"reflect"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// RoutedDHCPGrantV3 is supplied only by the authenticated owner/helper assembly.
// Epoch is the DHCP engine epoch; Snapshot.Sequence is the controller sequence.
type RoutedDHCPGrantV3 struct {
	Epoch    uint64
	Snapshot networkexecutor.LeaseSelectedSnapshotV3
}

// Verification runs while the selected-store writer barrier is held. It must
// not reenter ServiceV2. Both phases require observed gate closure/forwarding0;
// baseline additionally proves the original LAN plus empty WAN, target proves
// the complete exact owned delta. This is not a web/API request interface.
type RoutedDHCPAuthorityV3 interface {
	Current(context.Context) (RoutedDHCPGrantV3, error)
	VerifyClosed(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedStateV3) error
}

type RoutedDHCPSelectedStoreV3 struct {
	c         *v2Coordinator
	authority RoutedDHCPAuthorityV3
	identity  networkexecutor.OwnedNamespaceIdentity
}

func NewRoutedDHCPSelectedStoreV3(service *ServiceV2, identity networkexecutor.OwnedNamespaceIdentity, authority RoutedDHCPAuthorityV3) (*RoutedDHCPSelectedStoreV3, error) {
	if service == nil || service.coordinator == nil || authority == nil || !validRoutedIdentityV1(identity) {
		return nil, ErrInvalid
	}
	c := service.coordinator
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.closed || c.store.blocked || c.store.reserves == nil || !hasFeatureV2(c.store.state, v2SharedReaderFeature) || c.store.state.RecoveryReserveVersion != 1 || c.options.BootID == nil || string(*c.options.BootID) != identity.BootID || c.options.RoutedIdentity != identity {
		return nil, ErrRecovery
	}
	return &RoutedDHCPSelectedStoreV3{c: c, identity: identity, authority: authority}, nil
}

func (w *RoutedDHCPSelectedStoreV3) ready(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || w.c.closed || w.c.store.blocked || w.c.store.readOnly {
		return ErrRecovery
	}
	cfg := w.c.store.state.Configuration
	if cfg == nil || cfg.Intent != nil || cfg.Pending != nil || cfg.RecoveryRequired {
		return ErrRecovery
	}
	return nil
}

func (w *RoutedDHCPSelectedStoreV3) current(ctx context.Context, want RoutedDHCPGrantV3) error {
	got, err := w.authority.Current(ctx)
	if err != nil || !reflect.DeepEqual(got, want) {
		return ErrRecovery
	}
	return nil
}

// Prepare selects the immutable work and verified R2 admission/plan before any
// WAN effects. The initial version deliberately requires a verified baseline
// between grants; it does not claim the zero-L3-change renewal optimization.
func (w *RoutedDHCPSelectedStoreV3) Prepare(ctx context.Context) (string, error) {
	if w == nil || w.c == nil {
		return "", ErrInvalid
	}
	s := w.c.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.ready(ctx) != nil || s.state.RoutedDHCP != nil {
		return "", ErrRecovery
	}
	if err := s.reserves.maintain(s); err != nil {
		return "", err
	}
	if s.state.SystemBundle != nil || s.state.RoutedBootBoundary != nil || len(s.state.ActiveReserves) != 0 {
		return "", ErrRecovery
	}
	g, err := w.authority.Current(ctx)
	if err != nil || g.Epoch == 0 || g.Snapshot.Identity != w.identity {
		return "", ErrRecovery
	}
	snapshot, err := networkexecutor.CanonicalLeaseSelectedSnapshotV3(g.Snapshot)
	if err != nil || w.authority.VerifyClosed(ctx, snapshot, networkexecutor.LeaseSelectedBaselineV3) != nil || w.current(ctx, g) != nil {
		return "", ErrRecovery
	}
	cfg := s.state.Configuration
	if cfg.Running.Config.Domains.Network == nil || cfg.Running.Config.Domains.Network.Revision != snapshot.Desired.Hash {
		return "", ErrRecovery
	}
	configuration, err := s.object(*cfg)
	if err != nil {
		return "", err
	}
	work := v3RoutedDHCPWork{Version: 3, Lineage: s.state.Lineage, Generation: s.state.Generation, Running: cfg.Running.Hash, Configuration: configuration, Epoch: g.Epoch, Snapshot: snapshot}
	hash, err := s.object(work)
	if err != nil {
		return "", err
	}
	owner, err := v2ID("reserve", s.selection.Sequence+1)
	if err != nil {
		return "", err
	}
	if err = w.freshGrant(g); err != nil {
		return "", err
	}
	if err = w.profile(owner); err != nil {
		return "", err
	}
	id := "dhcp-" + hash
	st := clone(s.state)
	if st.ReservedBytes > ^uint64(0)-v2OperationReserveBytes || st.ReservedInodes > ^uint64(0)-v2OperationReserveInodes {
		return "", errV2Limited
	}
	st.ReservedBytes += v2OperationReserveBytes
	st.ReservedInodes += v2OperationReserveInodes
	addFeatureV2(&st, v3RoutedDHCPFeature)
	claims, err := s.reserves.claimOwner(recoveryreserve.SystemV2, owner)
	if err != nil {
		return "", err
	}
	scope := recoveryreserve.ScopeV2{Kind: "recovery", Lineage: st.Lineage, Bundle: owner, Recovery: id, Domain: "routed", Fingerprint: hash, Global: st.Generation, Generation: st.Generation}
	admissionData, _, err := v2Canonical(v2ReserveAdmission{Format: v2Format, Version: 1, Scope: scope, Claims: claims})
	if err != nil || len(admissionData) > claims.Admission.Capacity {
		return "", errV2Limited
	}
	admission, err := s.reserves.admission.WriteOnce(claims.Admission, admissionData, scope)
	if err != nil {
		return "", ErrRecovery
	}
	actual, err := s.reserves.admission.ReadBound(admission)
	if err != nil || !bytes.Equal(actual, admissionData) {
		return "", ErrRecovery
	}
	intent := v2CoordinatorIntent{DHCPWork: hash, Operation: id, Domain: "routed", Kind: v3RoutedDHCPKind, Previous: configuration, Target: configuration, TargetGeneration: st.Generation, Recovery: true}
	planData, _, err := v2Canonical(v2ReservePlan{Format: v2Format, Version: 1, Scope: scope, Admission: admission, Intent: intent})
	if err != nil || len(planData) > claims.Plan.Capacity {
		return "", errV2Limited
	}
	plan, err := s.reserves.plan.WriteOnce(claims.Plan, planData, scope)
	if err != nil {
		return "", ErrRecovery
	}
	actual, err = s.reserves.plan.ReadBound(plan)
	if err != nil || !bytes.Equal(actual, planData) {
		return "", ErrRecovery
	}
	st.RoutedDHCP = &v3RoutedDHCPState{Work: hash, Phase: "prepared", Bundle: &v2ReserveBundle{Scope: scope, Claims: claims, Admission: admission, Plan: &plan, PlanScope: &scope, PlanIntent: &intent}}
	if _, err = w.c.appendAuditLocked(st.Configuration, id, "", "", "", v3RoutedDHCPKind, "prepared", st.Generation, w.c.now()); err != nil {
		return "", err
	}
	if validateRoutedDHCPSelectedV3(st, s.readObject) != nil || s.reserves.verifyBundle(s, st.RoutedDHCP.Bundle) != nil || w.current(ctx, g) != nil || w.authority.VerifyClosed(ctx, snapshot, networkexecutor.LeaseSelectedBaselineV3) != nil {
		return "", ErrRecovery
	}
	if err = s.publish(st); err != nil {
		return "", err
	}
	return hash, nil
}

// Applied records exact readback while the gate is still closed. Opening the
// token is a separate helper action after a fresh selected-reader verification.
func (w *RoutedDHCPSelectedStoreV3) Applied(ctx context.Context, hash string) error {
	return w.transition(ctx, hash, false)
}

// Withdrawn records verified baseline, not restoration of an earlier lease.
func (w *RoutedDHCPSelectedStoreV3) Withdrawn(ctx context.Context, hash string) error {
	return w.transition(ctx, hash, true)
}

func (w *RoutedDHCPSelectedStoreV3) transition(ctx context.Context, hash string, withdrawn bool) error {
	if w == nil || w.c == nil {
		return ErrInvalid
	}
	s := w.c.store
	s.mu.Lock()
	defer s.mu.Unlock()
	return w.transitionLocked(ctx, hash, withdrawn)
}

func (w *RoutedDHCPSelectedStoreV3) transitionLocked(ctx context.Context, hash string, withdrawn bool) error {
	s := w.c.store
	if w.ready(ctx) != nil || s.state.RoutedDHCP == nil || s.state.RoutedDHCP.Work != hash || validateRoutedDHCPSelectedV3(s.state, s.readObject) != nil {
		return ErrRecovery
	}
	previousAllowance := s.allowance
	s.allowance = v2Budget{Bytes: v2OperationReserveBytes, Inodes: v2OperationReserveInodes}
	defer func() { s.allowance = previousAllowance }()
	d := s.state.RoutedDHCP
	work, err := loadRoutedDHCPWorkV3(hash, s.state.Lineage, s.readObject)
	if err != nil || work.Snapshot.Identity != w.identity || s.reserves.verifyBundle(s, d.Bundle) != nil {
		return ErrRecovery
	}
	state := networkexecutor.LeaseSelectedTargetV3
	if withdrawn {
		state = networkexecutor.LeaseSelectedBaselineV3
	} else if d.Phase != "prepared" {
		return ErrRecovery
	}
	if w.authority.VerifyClosed(ctx, work.Snapshot, state) != nil {
		return ErrRecovery
	}
	if !withdrawn && w.current(ctx, RoutedDHCPGrantV3{Epoch: work.Epoch, Snapshot: work.Snapshot}) != nil {
		return ErrRecovery
	}
	st := clone(s.state)
	if withdrawn {
		if d.Phase != "withdrawn" {
			audit, err := w.c.appendAuditLocked(st.Configuration, reserveWorkV2(d.Bundle), "", "", "", v3RoutedDHCPKind, "withdrawn", st.Generation, w.c.now())
			if err != nil {
				return err
			}
			st.RoutedDHCP.Phase, st.RoutedDHCP.Audit = "withdrawn", audit
		}
	} else {
		st.RoutedDHCP.Phase = "applied"
		if _, err := w.c.appendAuditLocked(st.Configuration, reserveWorkV2(d.Bundle), "", "", "", v3RoutedDHCPKind, "applied", st.Generation, w.c.now()); err != nil {
			return err
		}
	}
	if w.authority.VerifyClosed(ctx, work.Snapshot, state) != nil {
		return ErrRecovery
	}
	if !withdrawn && w.current(ctx, RoutedDHCPGrantV3{Epoch: work.Epoch, Snapshot: work.Snapshot}) != nil {
		return ErrRecovery
	}
	if err := s.publish(st); err != nil {
		return err
	}
	if withdrawn {
		return s.reserves.archiveTerminal(s, v2ActiveReserve{Work: reserveWorkV2(d.Bundle), Bundle: clone(d.Bundle), CanonicalHeld: true})
	}
	return nil
}
