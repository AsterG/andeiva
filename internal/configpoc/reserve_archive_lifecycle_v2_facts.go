package configpoc

import (
	"reflect"
	"time"
)

type v2ReserveWorkRef struct {
	ID     string `json:"id"`
	Object string `json:"object"`
}

type v2ReserveFinality struct {
	Format     string            `json:"format"`
	Version    uint8             `json:"version"`
	Lineage    string            `json:"lineage"`
	Kind       string            `json:"kind"`
	Origin     v2ReserveWorkRef  `json:"origin"`
	Child      *v2ReserveWorkRef `json:"child,omitempty"`
	Recovery   *v2ReserveWorkRef `json:"recovery,omitempty"`
	Resolution string            `json:"resolution,omitempty"`
}

type v2ReserveLeaseResolution struct {
	Format   string    `json:"format"`
	Version  uint8     `json:"version"`
	Origin   string    `json:"origin"`
	Lease    string    `json:"lease"`
	Deadline time.Time `json:"deadline"`
	Child    string    `json:"child,omitempty"`
	Recovery string    `json:"recovery,omitempty"`
}

func validReserveWorkRefV2(ref v2ReserveWorkRef) bool {
	return ref.ID != "" && len(ref.ID) <= 128 && validHash(ref.Object)
}

func terminalReserveOperationV2(op v2Operation, state v2State) bool {
	return op.ID != "" && len(op.ID) <= 128 && op.Sequence != 0 && op.Sequence <= state.HighWater && op.Lineage == state.Lineage && op.Expected != 0 && v2RequestValid(op.Domain, op.Request) && op.Fingerprint == v2OperationFingerprint(op) && op.State == "final" && !op.Pinned && op.Completed != nil && op.RetainUntil != nil && !op.RetainUntil.Before(op.Completed.Add(30*24*time.Hour)) && op.Outcome != nil && validHash(op.Outcome.AuditHash)
}

// This proves immutable canonical facts only. The caller separately verifies
// the live selected closure and the exact physical binding before retirement.
func validateArchiveFinalityV2(archive v2ReserveArchive, state v2State, load func(string, any) error) error {
	var facts v2ReserveFinality
	if validateArchiveCapsulesV2(archive) != nil || load == nil || load(archive.FinalWork, &facts) != nil || facts.Format != v2Format || (facts.Version != 1 && facts.Version != 2) || (facts.Version == 2 && !hasFeatureV2(state, v2ReserveCompensationFeature)) || facts.Lineage != state.Lineage || archive.Lineage != state.Lineage || !validReserveWorkRefV2(facts.Origin) || facts.Origin.ID != archive.Origin || facts.Resolution != archive.LeaseResolution {
		return errV2Unavailable
	}
	if facts.Kind == "system" {
		var record v2RecoveryRecord
		if facts.Version != 1 || facts.Child != nil || facts.Recovery != nil || facts.Resolution != "" || archive.Child != "" || load(facts.Origin.Object, &record) != nil || !validRecoveryRecordV2(record, state.Lineage) || record.ID != facts.Origin.ID || record.State != "final" || record.Pinned || record.Audit != archive.Audit {
			return errV2Unavailable
		}
		if !archiveMatchesBundleV2(archive, record.Reserve, false) || len(archive.UnusedEscrow) != 0 {
			return errV2Unavailable
		}
		return nil
	}
	if facts.Kind != "operation" {
		return errV2Unavailable
	}
	var origin v2Operation
	if load(facts.Origin.Object, &origin) != nil || origin.ID != facts.Origin.ID || !terminalReserveOperationV2(origin, state) {
		return errV2Unavailable
	}
	audit := origin.Outcome.AuditHash
	var child v2Operation
	if facts.Child != nil {
		if !validReserveWorkRefV2(*facts.Child) || facts.Child.ID != archive.Child || load(facts.Child.Object, &child) != nil || child.ID != facts.Child.ID || !terminalReserveOperationV2(child, state) || child.Subject != origin.Subject || child.Domain != origin.Domain || child.Request.Kind != OpConfirm || child.Request.Origin != origin.ID {
			return errV2Unavailable
		}
		audit = child.Outcome.AuditHash
	} else if archive.Child != "" {
		return errV2Unavailable
	}
	var recovery v2RecoveryRecord
	if facts.Recovery != nil {
		if !validReserveWorkRefV2(*facts.Recovery) || load(facts.Recovery.Object, &recovery) != nil || !validRecoveryRecordV2(recovery, state.Lineage) || recovery.ID != facts.Recovery.ID || recovery.State != "final" || recovery.Pinned || recovery.Origin != origin.ID || recovery.Subject != origin.Subject {
			return errV2Unavailable
		}
		audit = recovery.Audit
	}
	if audit != archive.Audit {
		return errV2Unavailable
	}
	if !archiveMatchesBundleV2(archive, origin.Reserve, reserveNeverAppliedV2(origin)) {
		return errV2Unavailable
	}
	if facts.Child != nil {
		if origin.Reserve == nil || origin.Reserve.ClosingEscrow == nil || child.Reserve == nil || !reflect.DeepEqual(child.Reserve.Claims, *origin.Reserve.ClosingEscrow) || !archiveMatchesBundleV2(archive, child.Reserve, reserveNeverAppliedV2(child)) || len(archive.UnusedEscrow) != 0 {
			return errV2Unavailable
		}
	} else if origin.Reserve != nil && origin.Reserve.ClosingEscrow != nil {
		expected := origin.Reserve.ClosingEscrow.all()
		sortReserveClaimsV2(expected)
		if !reflect.DeepEqual(expected, archive.UnusedEscrow) {
			return errV2Unavailable
		}
	} else if len(archive.UnusedEscrow) != 0 {
		return errV2Unavailable
	}
	if facts.Version == 2 {
		return validateReserveCompensationV2(archive, facts, origin, load)
	}
	if origin.Outcome.ConfirmationLease == "" {
		if facts.Resolution != "" || facts.Child != nil || facts.Recovery != nil || (origin.Reserve != nil && origin.Reserve.PlanScope != nil && origin.Reserve.PlanScope.Lease != "") {
			return errV2Unavailable
		}
		return nil
	}
	if !validHash(facts.Resolution) || origin.Outcome.ConfirmationDeadline == nil {
		return errV2Unavailable
	}
	var resolution v2ReserveLeaseResolution
	if load(facts.Resolution, &resolution) != nil || resolution.Format != v2Format || resolution.Version != 1 || resolution.Origin != origin.ID || resolution.Lease != origin.Outcome.ConfirmationLease || !resolution.Deadline.Equal(*origin.Outcome.ConfirmationDeadline) {
		return errV2Unavailable
	}
	if facts.Child == nil {
		if resolution.Child != "" {
			return errV2Unavailable
		}
	} else if resolution.Child != facts.Child.ID {
		return errV2Unavailable
	}
	if facts.Recovery == nil {
		if resolution.Recovery != "" || facts.Child == nil || (child.Outcome.Code != "applied" && child.Outcome.Code != "failed_rolled_back") {
			return errV2Unavailable
		}
	} else if resolution.Recovery != facts.Recovery.ID || recovery.Lease != resolution.Lease {
		return errV2Unavailable
	}
	return nil
}

func reserveNeverAppliedV2(op v2Operation) bool {
	return op.Reserve != nil && op.Reserve.Plan == nil && op.State == "final" && op.Outcome != nil && (op.Outcome.Code == "expired_without_effects" || (op.Outcome.Code == "rejected" && op.Outcome.ErrorCode == "ANDEIVA_NAMESPACE_CLOSED") || (op.Outcome.Code == "confirmation_resolved_without_effects" && op.Outcome.ErrorCode == "ANDEIVA_CONFIRMATION_RESOLVED") || (op.Outcome.Code == "profile_changed_without_effects" && op.Outcome.ErrorCode == "ANDEIVA_RESERVE_PROFILE_CHANGED"))
}
