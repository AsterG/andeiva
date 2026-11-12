package configpoc

import (
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func reserveRecoveryFingerprintV2(record v2RecoveryRecord) string {
	_, hash, _ := v2Canonical(struct {
		ID, Origin, Lease, Kind, Previous, Target, Subject, Lineage string
		Boot                                                        *v2BootID
		Started                                                     time.Time
	}{record.ID, record.Origin, record.Lease, record.Kind, record.Previous, record.Target, record.Subject, record.Lineage, record.BootID, record.Started.UTC()})
	return hash
}

func (m *v2ReserveManager) prepareBoot(s *v2Store, st *v2State, record *v2RecoveryRecord, intent v2CoordinatorIntent) error {
	if s.state.RecoveryReserveVersion != 1 {
		return nil
	}
	if m == nil || st.SystemBundle != nil || record.BootID == nil {
		return ErrRecovery
	}
	owner, err := v2ID("reserve", s.selection.Sequence+1)
	if err != nil {
		return err
	}
	var target v2Configuration
	if s.readObject(record.Target, &target) != nil {
		return ErrRecovery
	}
	if err = m.bootProfile(s, *record, target, owner, st.RoutedBootBoundary); err != nil {
		return err
	}
	claims, err := m.claimOwner(recoveryreserve.SystemV2, owner)
	if err != nil {
		return err
	}
	scope := recoveryreserve.ScopeV2{Kind: "boot", Lineage: st.Lineage, Bundle: claims.Admission.Owner, Recovery: record.ID, Boot: string(*record.BootID), Domain: "firewall", Fingerprint: reserveRecoveryFingerprintV2(*record), Global: st.Generation, Generation: st.Configuration.Firewall.Generation}
	if intent.Domain == "routed" {
		scope.Domain = "routed"
	}
	data, _, err := v2Canonical(v2ReserveAdmission{Format: v2Format, Version: 1, Scope: scope, Claims: claims})
	if err != nil || len(data) > claims.Admission.Capacity {
		return errV2Limited
	}
	admission, err := m.admission.WriteOnce(claims.Admission, data, scope)
	if err != nil {
		return ErrRecovery
	}
	if _, err = m.admission.ReadBound(admission); err != nil {
		return ErrRecovery
	}
	planData, _, err := v2Canonical(v2ReservePlan{Format: v2Format, Version: 1, Scope: scope, Admission: admission, Intent: intent})
	if err != nil || len(planData) > claims.Plan.Capacity {
		return errV2Limited
	}
	plan, err := m.plan.WriteOnce(claims.Plan, planData, scope)
	if err != nil {
		return ErrRecovery
	}
	if _, err = m.plan.ReadBound(plan); err != nil {
		return ErrRecovery
	}
	intentCopy := intent
	bundle := &v2ReserveBundle{Scope: scope, Claims: claims, Admission: admission, Plan: &plan, PlanScope: &scope, PlanIntent: &intentCopy}
	record.Reserve = clone(bundle)
	st.SystemBundle = &v2ActiveReserve{Work: record.ID, Bundle: bundle}
	return s.point("reserve_system_verified")
}
