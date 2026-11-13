package configpoc

import (
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

const v2ReserveCompensationFeature = "reserve_compensation.v1"

// Version 2 proves a selected plan was compensated before a confirmation lease
// became a published outcome. It is not a confirmation or a recovery operation.
type v2ReserveCompensationResolution struct {
	Format   string                    `json:"format"`
	Version  uint8                     `json:"version"`
	Kind     string                    `json:"kind"`
	Origin   string                    `json:"origin"`
	Lease    string                    `json:"lease"`
	Deadline time.Time                 `json:"deadline"`
	Plan     recoveryreserve.BindingV2 `json:"plan"`
	Previous string                    `json:"previous"`
	Target   string                    `json:"target"`
	Audit    string                    `json:"audit"`
}

func reserveCompensationResolutionV2(op v2Operation) (v2ReserveCompensationResolution, error) {
	b := op.Reserve
	if op.Outcome == nil || op.Outcome.Code != "failed_rolled_back" || op.Outcome.ConfirmationLease != "" || op.Outcome.ConfirmationDeadline != nil || !validReserveBundleV2(b) || !reserveScopeMatchesOperationV2(b, op) || b.Plan == nil || b.PlanScope.Lease == "" || b.PlanScope.Origin != op.ID || b.PlanScope.Operation != op.ID || b.PlanIntent.Recovery || b.PlanIntent.BootID != nil || b.PlanIntent.Kind != op.Request.Kind || (op.Request.Kind != OpCommit && op.Request.Kind != OpRollback) {
		return v2ReserveCompensationResolution{}, errV2Unavailable
	}
	return v2ReserveCompensationResolution{Format: v2Format, Version: 2, Kind: "operation_compensated", Origin: op.ID, Lease: b.PlanScope.Lease, Deadline: b.PlanScope.Deadline, Plan: *b.Plan, Previous: b.PlanIntent.Previous, Target: b.PlanIntent.Target, Audit: op.Outcome.AuditHash}, nil
}

func validateReserveCompensationV2(archive v2ReserveArchive, facts v2ReserveFinality, op v2Operation, load func(string, any) error) error {
	want, err := reserveCompensationResolutionV2(op)
	if err != nil || facts.Child != nil || facts.Recovery != nil || archive.Child != "" || !validHash(facts.Resolution) {
		return errV2Unavailable
	}
	var got v2ReserveCompensationResolution
	if load(facts.Resolution, &got) != nil || !got.Deadline.Equal(want.Deadline) {
		return errV2Unavailable
	}
	same := got
	same.Deadline = want.Deadline
	if same != want {
		return errV2Unavailable
	}
	if archive.Audit != got.Audit {
		return errV2Unavailable
	}
	return validateReserveCompensationEvidenceV2(op, want, load)
}

// The same facts qualify a retained prospective snapshot before its terminal
// archive is published. This never claims that the prospective lease was live.
func reserveCompensatedSnapshotV2(cfg v2Configuration, state v2State, op v2Operation, load func(string, any) error) bool {
	if !hasFeatureV2(state, v2ReserveCompensationFeature) || !terminalReserveOperationV2(op, state) {
		return false
	}
	proof, err := reserveCompensationResolutionV2(op)
	if err != nil {
		return false
	}
	_, hash, err := v2Canonical(cfg)
	return err == nil && hash == proof.Target && validateReserveCompensationEvidenceV2(op, proof, load) == nil
}

func validateReserveCompensationEvidenceV2(op v2Operation, proof v2ReserveCompensationResolution, load func(string, any) error) error {
	if load == nil {
		return errV2Unavailable
	}
	// These immutable snapshots are also explicit archive dependencies. Audit
	// binds the verified rollback to the original plan, not merely a lease ID.
	var previous, target v2Configuration
	var audit v2CoordinatorAudit
	if load(proof.Previous, &previous) != nil || load(proof.Target, &target) != nil || load(proof.Audit, &audit) != nil || !validV2Configuration(&previous) || !validV2Configuration(&target) || previous.Intent != nil || previous.Pending != nil || previous.RecoveryRequired || target.Intent != nil || target.RecoveryRequired || target.Pending == nil {
		return errV2Unavailable
	}
	pending := target.Pending
	if pending.Previous != proof.Previous || pending.OriginCommit != op.ID || pending.Lease != proof.Lease || !pending.Deadline.Equal(op.Reserve.PlanScope.Deadline) || pending.Owner != op.Subject || pending.Domain != op.Domain || pending.Target != target.Running.Hash {
		return errV2Unavailable
	}
	if op.Outcome.Generation != op.Expected || op.Outcome.DomainGeneration != domainSnapshotV2(&previous, op.Domain).Generation || op.Outcome.RunningRevision != previous.Running.Hash || op.Outcome.StartupRevision != previous.Startup.Hash || previous.AuditSequence == ^uint64(0) || op.Outcome.AuditFirst != previous.AuditSequence+1 || op.Outcome.AuditLast != op.Outcome.AuditFirst {
		return errV2Unavailable
	}
	if audit.Format != v2Format || audit.Operation != op.ID || audit.Subject != op.Subject || audit.Kind != op.Request.Kind || audit.Result != "failed_rolled_back" || audit.OriginCommit != "" || audit.Lease != "" || audit.Generation != op.Outcome.Generation || audit.Running != previous.Running.Hash || audit.Startup != previous.Startup.Hash || audit.Sequence != op.Outcome.AuditLast || audit.Previous != previous.AuditTip || op.Completed == nil || !audit.At.Equal(*op.Completed) {
		return errV2Unavailable
	}
	return nil
}
