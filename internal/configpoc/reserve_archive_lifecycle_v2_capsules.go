package configpoc

import (
	"reflect"
	"sort"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func validReserveClaimsV2(claims v2ReserveClaims) bool {
	owner := ""
	pools := map[string]bool{}
	for _, claim := range claims.all() {
		if claim.Validate() != nil || pools[claim.Pool] || (owner != "" && owner != claim.Owner) {
			return false
		}
		pools[claim.Pool] = true
		owner = claim.Owner
	}
	return claims.Admission.Role == recoveryreserve.AdmissionV2 && claims.Plan.Role == recoveryreserve.PlanV2 && claims.Emergency.Role == recoveryreserve.EmergencyV2
}

func validReserveBundleV2(bundle *v2ReserveBundle) bool {
	if bundle == nil || bundle.Scope.Validate() != nil || !validReserveClaimsV2(bundle.Claims) || bundle.Claims.Admission.Owner != bundle.Scope.Bundle || bundle.Admission.Validate() != nil || bundle.Admission.Claim != bundle.Claims.Admission {
		return false
	}
	scopeHash, err := bundle.Scope.Hash()
	if err != nil || scopeHash != bundle.Admission.ScopeHash || (bundle.Plan == nil) != (bundle.PlanScope == nil) || (bundle.Plan == nil) != (bundle.PlanIntent == nil) {
		return false
	}
	if bundle.Plan != nil {
		if !validGuardDeadlineShapeV2(bundle.PlanIntent) || (bundle.PlanIntent.GuardDeadline != nil && !bundle.PlanScope.Deadline.IsZero()) {
			return false
		}
		hash, e := bundle.PlanScope.Hash()
		if e != nil || bundle.Plan.Validate() != nil || bundle.Plan.Claim != bundle.Claims.Plan || bundle.Plan.ScopeHash != hash {
			return false
		}
		base, want := *bundle.PlanScope, bundle.Scope
		base.Origin, base.Lease, base.Deadline = "", "", time.Time{}
		want.Origin, want.Lease, want.Deadline = "", "", time.Time{}
		if !reflect.DeepEqual(base, want) || bundle.PlanIntent.Operation != reserveWorkV2(bundle) || bundle.PlanIntent.Subject != bundle.Scope.Subject || bundle.PlanIntent.Domain != bundle.Scope.Domain || bundle.PlanIntent.TargetGeneration < bundle.Scope.Global || bundle.PlanIntent.TargetGeneration-bundle.Scope.Global > 1 {
			return false
		}
	}
	if bundle.ClosingEscrow != nil {
		if !validReserveClaimsV2(*bundle.ClosingEscrow) || bundle.ClosingEscrow.Admission.Owner == bundle.Scope.Bundle {
			return false
		}
		for i, claim := range bundle.Claims.all() {
			escrow := bundle.ClosingEscrow.all()[i]
			if escrow.Pool != claim.Pool || escrow.Slot < 8 || escrow.Slot >= 16 {
				return false
			}
		}
	}
	return true
}

func validateArchiveCapsulesV2(archive v2ReserveArchive) error {
	_, err := archiveCapsuleDependenciesV2(archive)
	return err
}

func archiveCapsuleDependenciesV2(archive v2ReserveArchive) ([]string, error) {
	if validateReserveArchiveV2(archive) != nil {
		return nil, errV2Unavailable
	}
	admissions := map[string]recoveryreserve.BindingV2{}
	plans := map[string]recoveryreserve.BindingV2{}
	planCapsules := map[string]v2ReservePlan{}
	emergencyCapsules := map[string]v2ReserveEmergency{}
	deps := map[string]bool{}
	for _, entry := range archive.Entries {
		if entry.Binding == nil {
			continue
		}
		owner := entry.Claim.Owner
		switch entry.Claim.Role {
		case recoveryreserve.AdmissionV2:
			var capsule v2ReserveAdmission
			if checkpointDecode(entry.Raw, &capsule) != nil || capsule.Format != v2Format || capsule.Version != 1 || entry.Scope == nil || !reflect.DeepEqual(capsule.Scope, *entry.Scope) || !validReserveClaimsV2(capsule.Claims) || capsule.Claims.Admission != entry.Claim {
				return nil, errV2Unavailable
			}
			if capsule.ClosingEscrow != nil && (!validReserveClaimsV2(*capsule.ClosingEscrow) || capsule.ClosingEscrow.Admission.Owner == owner) {
				return nil, errV2Unavailable
			}
			admissions[owner] = *entry.Binding
		case recoveryreserve.PlanV2:
			var capsule v2ReservePlan
			if checkpointDecode(entry.Raw, &capsule) != nil || capsule.Format != v2Format || capsule.Version != 1 || entry.Scope == nil || !reflect.DeepEqual(capsule.Scope, *entry.Scope) || capsule.Admission.Validate() != nil || capsule.Admission.Claim.Owner != owner || capsule.Admission.Claim.Role != recoveryreserve.AdmissionV2 || !validHash(capsule.Intent.Previous) || !validHash(capsule.Intent.Target) || capsule.Intent.Domain != capsule.Scope.Domain {
				return nil, errV2Unavailable
			}
			work := capsule.Scope.Operation
			if capsule.Scope.Kind != "operation" {
				work = capsule.Scope.Recovery
			}
			if capsule.Intent.Operation != work || capsule.Intent.Subject != capsule.Scope.Subject || capsule.Intent.TargetGeneration < capsule.Scope.Global || capsule.Intent.TargetGeneration-capsule.Scope.Global > 1 {
				return nil, errV2Unavailable
			}
			if !validGuardDeadlineShapeV2(&capsule.Intent) || (capsule.Intent.GuardDeadline != nil && !capsule.Scope.Deadline.IsZero()) {
				return nil, errV2Unavailable
			}
			if capsule.Scope.Kind == "boot" {
				if !validBootIntentV2(&capsule.Intent) || string(*capsule.Intent.BootID) != capsule.Scope.Boot {
					return nil, errV2Unavailable
				}
			}
			plans[owner] = *entry.Binding
			planCapsules[owner] = capsule
			deps[capsule.Intent.Previous], deps[capsule.Intent.Target] = true, true
		case recoveryreserve.EmergencyV2:
			var capsule v2ReserveEmergency
			if checkpointDecode(entry.Raw, &capsule) != nil || capsule.Format != v2Format || capsule.Version != 1 || entry.Scope == nil || !reflect.DeepEqual(capsule.Scope, *entry.Scope) || !validHash(capsule.Selection) || capsule.SelectionSequence == 0 || !validHash(capsule.Intent) || (capsule.Code != "storage_uncertain" && capsule.Code != "recovery_uncertain") {
				return nil, errV2Unavailable
			}
			emergencyCapsules[owner] = capsule
		default:
			return nil, errV2Unavailable
		}
	}
	for owner, plan := range planCapsules {
		if admissions[owner] != plan.Admission {
			return nil, errV2Unavailable
		}
	}
	for owner, emergency := range emergencyCapsules {
		if admissions[owner] != emergency.Admission || plans[owner] != emergency.Plan {
			return nil, errV2Unavailable
		}
		plan := planCapsules[owner]
		_, intentHash, err := v2Canonical(plan.Intent)
		if err != nil || intentHash != emergency.Intent || !reflect.DeepEqual(plan.Scope, emergency.Scope) {
			return nil, errV2Unavailable
		}
	}
	result := make([]string, 0, len(deps))
	for hash := range deps {
		result = append(result, hash)
	}
	sort.Strings(result)
	if !reflect.DeepEqual(result, archive.Dependencies) {
		return nil, errV2Unavailable
	}
	return result, nil
}

func archiveMatchesBundleV2(archive v2ReserveArchive, bundle *v2ReserveBundle, noEffects bool) bool {
	if !validReserveBundleV2(bundle) {
		return false
	}
	for _, claim := range bundle.Claims.all() {
		found := false
		for _, entry := range archive.Entries {
			if entry.Claim != claim {
				continue
			}
			found = true
			switch claim.Role {
			case recoveryreserve.AdmissionV2:
				if entry.Binding == nil || *entry.Binding != bundle.Admission || entry.Scope == nil || !reflect.DeepEqual(*entry.Scope, bundle.Scope) {
					return false
				}
			case recoveryreserve.PlanV2:
				if bundle.Plan != nil {
					var plan v2ReservePlan
					if entry.Binding == nil || *entry.Binding != *bundle.Plan || entry.Scope == nil || !reflect.DeepEqual(*entry.Scope, *bundle.PlanScope) || checkpointDecode(entry.Raw, &plan) != nil || !reflect.DeepEqual(plan.Intent, *bundle.PlanIntent) {
						return false
					}
				} else if entry.Binding != nil && !noEffects {
					return false
				}
			case recoveryreserve.EmergencyV2:
				if entry.Binding != nil && bundle.Plan == nil {
					return false
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}
