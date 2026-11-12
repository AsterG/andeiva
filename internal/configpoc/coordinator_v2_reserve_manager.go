package configpoc

import (
	"bytes"
	"encoding/json"
	"reflect"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

// Trusted assembly owns the already opened pools and their lifetimes. No
// request chooses paths, classes, pool IDs or a privileged operation here.
type v2ReserveManager struct {
	admission *recoveryreserve.PoolV2
	plan      *recoveryreserve.PoolV2
	emergency *recoveryreserve.PoolV2
}

func newReserveManagerV2(admission, plan, emergency *recoveryreserve.PoolV2) (*v2ReserveManager, error) {
	m := &v2ReserveManager{admission: admission, plan: plan, emergency: emergency}
	if m.validateProfiles() != nil {
		return nil, ErrInvalid
	}
	return m, nil
}

func (m *v2ReserveManager) pool(role recoveryreserve.RoleV2) *recoveryreserve.PoolV2 {
	if m == nil {
		return nil
	}
	switch role {
	case recoveryreserve.AdmissionV2:
		return m.admission
	case recoveryreserve.PlanV2:
		return m.plan
	case recoveryreserve.EmergencyV2:
		return m.emergency
	default:
		return nil
	}
}

func (m *v2ReserveManager) validateProfiles() error {
	if m == nil || m.admission == nil || m.plan == nil || m.emergency == nil || m.admission == m.plan || m.admission == m.emergency || m.plan == m.emergency {
		return ErrInvalid
	}
	ids := map[string]bool{}
	for _, item := range []struct {
		role     recoveryreserve.RoleV2
		capacity int
	}{{recoveryreserve.AdmissionV2, 4096}, {recoveryreserve.PlanV2, 16384}, {recoveryreserve.EmergencyV2, 8192}} {
		profile, err := m.pool(item.role).Profile()
		if err != nil || profile.Role != item.role || profile.Slots != 18 || profile.Capacity != item.capacity || ids[profile.ID] {
			return ErrInvalid
		}
		ids[profile.ID] = true
	}
	return nil
}

func (m *v2ReserveManager) validateClaims(claims v2ReserveClaims, class recoveryreserve.ClassV2) error {
	owner := ""
	for _, claim := range claims.all() {
		profile, err := m.pool(claim.Role).Profile()
		if err != nil || claim.Validate() != nil || claim.Pool != profile.ID || claim.Capacity != profile.Capacity || (owner != "" && owner != claim.Owner) {
			return ErrRecovery
		}
		owner = claim.Owner
		validSlot := class == recoveryreserve.OrdinaryV2 && claim.Slot < 8 || class == recoveryreserve.ClosingV2 && claim.Slot >= 8 && claim.Slot < 16 || class == recoveryreserve.SystemV2 && claim.Slot >= 16 && claim.Slot < 18
		if !validSlot {
			return ErrRecovery
		}
	}
	if claims.Admission.Role != recoveryreserve.AdmissionV2 || claims.Plan.Role != recoveryreserve.PlanV2 || claims.Emergency.Role != recoveryreserve.EmergencyV2 {
		return ErrRecovery
	}
	return nil
}

func (m *v2ReserveManager) claim(class recoveryreserve.ClassV2, sequence uint64) (v2ReserveClaims, error) {
	owner, err := v2ID("reserve", sequence)
	if err != nil {
		return v2ReserveClaims{}, err
	}
	return m.claimOwner(class, owner)
}

func (m *v2ReserveManager) claimOwner(class recoveryreserve.ClassV2, owner string) (v2ReserveClaims, error) {
	var claims v2ReserveClaims
	var err error
	for _, item := range []struct {
		role   recoveryreserve.RoleV2
		target *recoveryreserve.SlotClaimV2
	}{{recoveryreserve.AdmissionV2, &claims.Admission}, {recoveryreserve.PlanV2, &claims.Plan}, {recoveryreserve.EmergencyV2, &claims.Emergency}} {
		*item.target, err = m.pool(item.role).ClaimClass(owner, class)
		if err != nil {
			return v2ReserveClaims{}, errV2Limited
		}
	}
	return claims, m.validateClaims(claims, class)
}

func (m *v2ReserveManager) prepareAdmission(s *v2Store, st *v2State, op *v2Operation) error {
	if s.state.RecoveryReserveVersion != 1 {
		return nil
	}
	if m == nil || m.validateProfiles() != nil || op == nil || op.Reserve != nil || len(st.ActiveReserves) >= 16 {
		return errV2Unavailable
	}
	if err := s.reserveMaintenanceReadyV2(op.Request.Origin); err != nil {
		return err
	}
	class := recoveryreserve.OrdinaryV2
	var claims v2ReserveClaims
	var escrow *v2ReserveClaims
	var err error
	if op.ClosingCredit != "" {
		class = recoveryreserve.ClosingV2
		origin, e := s.lookupRetained(op.Subject, op.Request.Origin)
		if e != nil || origin.Reserve == nil || origin.Reserve.ClosingEscrow == nil {
			return ErrRecovery
		}
		claims = *origin.Reserve.ClosingEscrow
		if m.validateClaims(claims, class) != nil {
			return ErrRecovery
		}
	} else {
		owner, e := v2ID("reserve", op.Sequence)
		if e != nil {
			return e
		}
		if e = m.operationProfile(s, *op, owner); e != nil {
			return e
		}
		claims, err = m.claimOwner(class, owner)
		if err != nil {
			return err
		}
		if closingPotentialV2(op.Request) {
			value, e := m.claim(recoveryreserve.ClosingV2, op.Sequence)
			if e != nil {
				return e
			}
			escrow = &value
		}
	}
	generation := uint64(1)
	if st.Configuration != nil {
		generation = domainSnapshotV2(st.Configuration, op.Domain).Generation
	}
	scope := recoveryreserve.ScopeV2{Kind: "operation", Lineage: st.Lineage, Bundle: claims.Admission.Owner, Operation: op.ID, Namespace: op.Namespace, Subject: op.Subject, Domain: op.Domain, Fingerprint: op.Fingerprint, Global: op.Expected, Generation: generation}
	if op.ClosingCredit != "" {
		origin, e := s.lookupRetained(op.Subject, op.Request.Origin)
		if e != nil || origin.Outcome == nil || origin.Outcome.ConfirmationDeadline == nil {
			return ErrRecovery
		}
		scope.Origin, scope.Lease, scope.Deadline = origin.ID, origin.Outcome.ConfirmationLease, *origin.Outcome.ConfirmationDeadline
	}
	capsule := v2ReserveAdmission{Format: v2Format, Version: 1, Scope: scope, Claims: claims, ClosingEscrow: escrow}
	data, _, err := v2Canonical(capsule)
	if err != nil || len(data) > claims.Admission.Capacity {
		return errV2Limited
	}
	binding, err := m.admission.WriteOnce(claims.Admission, data, scope)
	if err != nil {
		return errV2Unavailable
	}
	if actual, e := m.admission.ReadBound(binding); e != nil || !bytes.Equal(actual, data) {
		return errV2Unavailable
	}
	bundle := &v2ReserveBundle{Scope: scope, Claims: claims, Admission: binding, ClosingEscrow: escrow}
	op.Reserve = clone(bundle)
	st.ActiveReserves = append(st.ActiveReserves, v2ActiveReserve{Work: op.ID, Bundle: clone(bundle)})
	return s.point("reserve_admission_verified")
}

func (s *v2Store) reserveMaintenanceReadyV2(exceptOrigin string) error {
	closing := exceptOrigin != "" && s.state.Configuration != nil && s.state.Configuration.Pending != nil && s.state.Configuration.Pending.OriginCommit == exceptOrigin
	for _, active := range s.state.ActiveReserves {
		if active.Work == exceptOrigin {
			continue
		}
		if active.CanonicalHeld && !closing {
			return ErrRecovery
		}
	}
	if s.state.SystemBundle != nil {
		return ErrRecovery
	}
	return nil
}

func reserveAdmissionBytesV2(bundle *v2ReserveBundle) ([]byte, error) {
	if bundle == nil {
		return nil, ErrRecovery
	}
	data, _, err := v2Canonical(v2ReserveAdmission{Format: v2Format, Version: 1, Scope: bundle.Scope, Claims: bundle.Claims, ClosingEscrow: bundle.ClosingEscrow})
	return data, err
}

func (m *v2ReserveManager) readBinding(s *v2Store, binding recoveryreserve.BindingV2, scope recoveryreserve.ScopeV2) ([]byte, error) {
	if binding.Validate() != nil {
		return nil, ErrRecovery
	}
	if data, err := m.pool(binding.Claim.Role).ReadBound(binding); err == nil {
		return data, nil
	}
	entry := v2ReserveArchiveEntry{Claim: binding.Claim, Binding: &binding, Scope: &scope}
	archive, ok, err := s.reserveArchiveBundleLookupV2(s.state.ReserveArchiveRoot, entry, "binding")
	if err != nil || !ok || validateArchiveFinalityV2(archive, s.state, s.readObject) != nil {
		return nil, ErrRecovery
	}
	for _, archived := range archive.Entries {
		if archived.Binding != nil && *archived.Binding == binding {
			return append([]byte{}, archived.Raw...), nil
		}
	}
	return nil, ErrRecovery
}

func (m *v2ReserveManager) verifyBundle(s *v2Store, bundle *v2ReserveBundle) error {
	if !validReserveBundleV2(bundle) {
		return ErrRecovery
	}
	class := recoveryreserve.OrdinaryV2
	if bundle.Scope.Kind != "operation" {
		class = recoveryreserve.SystemV2
	} else if bundle.Claims.Admission.Slot >= 8 {
		class = recoveryreserve.ClosingV2
	}
	if m.validateClaims(bundle.Claims, class) != nil {
		return ErrRecovery
	}
	expected, err := reserveAdmissionBytesV2(bundle)
	actual, e := m.readBinding(s, bundle.Admission, bundle.Scope)
	if err != nil || e != nil || !bytes.Equal(actual, expected) {
		return ErrRecovery
	}
	if (bundle.Plan == nil) != (bundle.PlanScope == nil) || (bundle.Plan == nil) != (bundle.PlanIntent == nil) {
		return ErrRecovery
	}
	if bundle.Plan != nil {
		actual, err = m.readBinding(s, *bundle.Plan, *bundle.PlanScope)
		var plan v2ReservePlan
		if err != nil || checkpointDecode(actual, &plan) != nil || plan.Format != v2Format || plan.Version != 1 || plan.Admission != bundle.Admission || !reflect.DeepEqual(plan.Scope, *bundle.PlanScope) || !reflect.DeepEqual(plan.Intent, *bundle.PlanIntent) || plan.Intent.Operation != reserveWorkV2(bundle) {
			return ErrRecovery
		}
	}
	return nil
}

func (m *v2ReserveManager) verifySelected(s *v2Store) error {
	if m.validateProfiles() != nil || len(s.state.ActiveReserves) > 16 {
		return ErrRecovery
	}
	seen := map[string]bool{}
	for _, active := range s.state.ActiveReserves {
		if active.Work == "" || seen[active.Work] || reserveWorkV2(active.Bundle) != active.Work || m.verifyBundle(s, active.Bundle) != nil {
			return ErrRecovery
		}
		seen[active.Work] = true
		op, err := s.lookupRetained(active.Bundle.Scope.Subject, active.Work)
		if err != nil || !reserveScopeMatchesOperationV2(active.Bundle, op) || !reflect.DeepEqual(op.Reserve, active.Bundle) || (active.CanonicalHeld && (op.State != "final" || op.Pinned)) {
			return ErrRecovery
		}
	}
	for _, ns := range s.state.Namespaces {
		for _, id := range namespaceOpenIDsV2(ns) {
			if !seen[id] {
				return ErrRecovery
			}
		}
	}
	if active := s.state.SystemBundle; active != nil {
		if active.Bundle == nil || reserveWorkV2(active.Bundle) != active.Work || active.Bundle.Scope.Kind == "operation" || m.verifyBundle(s, active.Bundle) != nil {
			return ErrRecovery
		}
		record, err := (&v2Coordinator{store: s}).recoveryLookupLocked(active.Work)
		if err != nil || record.Kind != v2BootKind || record.BootID == nil || string(*record.BootID) != active.Bundle.Scope.Boot || reserveRecoveryFingerprintV2(record) != active.Bundle.Scope.Fingerprint || !reflect.DeepEqual(record.Reserve, active.Bundle) || (active.CanonicalHeld && (record.State != "final" || record.Pinned)) {
			return ErrRecovery
		}
	}
	return nil
}

func reserveScopeMatchesOperationV2(bundle *v2ReserveBundle, op v2Operation) bool {
	return bundle != nil && bundle.Scope.Kind == "operation" && bundle.Scope.Operation == op.ID && bundle.Scope.Subject == op.Subject && bundle.Scope.Namespace == op.Namespace && bundle.Scope.Domain == op.Domain && bundle.Scope.Lineage == op.Lineage && bundle.Scope.Fingerprint == op.Fingerprint && bundle.Scope.Global == op.Expected
}

func (m *v2ReserveManager) selectedPlan(s *v2Store, op *v2Operation, st *v2State, intent v2CoordinatorIntent, target v2Configuration) error {
	if s.state.RecoveryReserveVersion != 1 {
		return nil
	}
	if op.Reserve == nil || m.verifyBundle(s, op.Reserve) != nil {
		return ErrRecovery
	}
	bundle := clone(op.Reserve)
	scope := bundle.Scope
	if target.Pending != nil {
		scope.Origin, scope.Lease, scope.Deadline = target.Pending.OriginCommit, target.Pending.Lease, target.Pending.Deadline
	}
	data, _, err := v2Canonical(v2ReservePlan{Format: v2Format, Version: 1, Scope: scope, Admission: bundle.Admission, Intent: intent})
	if err != nil || len(data) > bundle.Claims.Plan.Capacity {
		return errV2Limited
	}
	binding, err := m.plan.WriteOnce(bundle.Claims.Plan, data, scope)
	if err != nil {
		return ErrRecovery
	}
	if actual, e := m.plan.ReadBound(binding); e != nil || !bytes.Equal(actual, data) {
		return ErrRecovery
	}
	bundle.Plan, bundle.PlanScope = &binding, &scope
	intentCopy := intent
	bundle.PlanIntent = &intentCopy
	op.Reserve = bundle
	i := reserveActiveIndexV2(st, op.ID)
	if i < 0 {
		return ErrRecovery
	}
	st.ActiveReserves[i].Bundle = clone(bundle)
	return s.point("reserve_plan_verified")
}

func (m *v2ReserveManager) emergencyCandidate(s *v2Store, bundle *v2ReserveBundle, code string) (result error) {
	if s == nil {
		return ErrRecovery
	}
	if s.state.Configuration == nil || s.state.Configuration.Intent == nil {
		return nil
	}
	defer func() {
		if result != nil {
			s.blocked = true
		}
	}()
	if m == nil || bundle == nil || bundle.Plan == nil || bundle.PlanScope == nil || bundle.PlanIntent == nil {
		return ErrRecovery
	}
	if code != "storage_uncertain" && code != "recovery_uncertain" {
		return ErrRecovery
	}
	_, intentHash, err := v2Canonical(*bundle.PlanIntent)
	if err != nil {
		return ErrRecovery
	}
	capsule := v2ReserveEmergency{Format: v2Format, Version: 1, Scope: *bundle.PlanScope, Admission: bundle.Admission, Plan: *bundle.Plan, Selection: s.selector.Current, SelectionSequence: s.selection.Sequence, Intent: intentHash, Code: code}
	data, _, err := v2Canonical(capsule)
	if err != nil || len(data) > bundle.Claims.Emergency.Capacity {
		return ErrRecovery
	}
	// A lost reply or an existing first candidate never authorizes a second write.
	if candidate, e := m.emergency.InspectClaimed(bundle.Claims.Emergency); e == nil {
		var previous v2ReserveEmergency
		if checkpointDecode(candidate.Bytes, &previous) != nil || previous.Format != v2Format || previous.Version != 1 || previous.Plan != *bundle.Plan || previous.Admission != bundle.Admission || !reflect.DeepEqual(previous.Scope, *bundle.PlanScope) || previous.Intent != intentHash || (previous.Code != "storage_uncertain" && previous.Code != "recovery_uncertain") {
			return ErrRecovery
		}
		return nil
	}
	binding, err := m.emergency.WriteOnce(bundle.Claims.Emergency, data, *bundle.PlanScope)
	if err != nil {
		return ErrRecovery
	}
	actual, err := m.emergency.ReadBound(binding)
	if err != nil || !bytes.Equal(actual, data) {
		return ErrRecovery
	}
	return nil
}

func reserveJSONEqualV2(left, right any) bool {
	a, e1 := json.Marshal(left)
	b, e2 := json.Marshal(right)
	return e1 == nil && e2 == nil && bytes.Equal(a, b)
}
