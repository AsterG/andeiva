package adminapi

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

// DecimalV2 rejects JSON numbers and noncanonical/overflowing decimal strings.
type DecimalV2 uint64

func (n DecimalV2) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(n), 10))
}
func (n *DecimalV2) UnmarshalJSON(data []byte) error {
	var value string
	if json.Unmarshal(data, &value) != nil {
		return configpoc.ErrInvalid
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return configpoc.ErrInvalid
	}
	*n = DecimalV2(parsed)
	return nil
}

type OperationRequestV2 struct {
	ExpectedCandidateStage string            `json:"expected_candidate_stage_operation_id,omitempty"`
	LocalServicesConfig    *configpoc.Config `json:"local_services_config,omitempty"`
	Operation              string            `json:"operation"`
	Config                 *configpoc.Config `json:"config,omitempty"`
	ConfirmSeconds         *DecimalV2        `json:"confirm_seconds,omitempty"`
	Target                 string            `json:"target_revision,omitempty"`
	Origin                 string            `json:"origin_commit_operation_id,omitempty"`
	Subject                string            `json:"target_subject_id,omitempty"`
}

func (r OperationRequestV2) canonical() configpoc.OperationRequestV2 {
	request := configpoc.OperationRequestV2{Kind: r.Operation, Config: r.Config, Target: r.Target, Origin: r.Origin, Subject: r.Subject, LocalServicesConfig: r.LocalServicesConfig, ExpectedCandidateStage: r.ExpectedCandidateStage}
	if r.ConfirmSeconds != nil {
		seconds := uint64(*r.ConfirmSeconds)
		request.ConfirmSeconds = &seconds
	}
	return request
}

type AdmitRequestV2 struct {
	Namespace string             `json:"namespace_id"`
	Expected  DecimalV2          `json:"expected_generation"`
	Request   OperationRequestV2 `json:"request"`
}
type NamespaceResponseV2 struct {
	SchemaVersion int       `json:"schema_version"`
	Namespace     string    `json:"namespace_id"`
	State         string    `json:"state"`
	AdmitUntil    time.Time `json:"admit_until"`
}
type OutcomeV2 struct {
	Code             string     `json:"code"`
	ErrorCode        string     `json:"error_code,omitempty"`
	GlobalGeneration DecimalV2  `json:"global_generation"`
	DomainGeneration DecimalV2  `json:"domain_generation,omitempty"`
	Running          string     `json:"running_revision,omitempty"`
	Startup          string     `json:"startup_revision,omitempty"`
	Deadline         *time.Time `json:"confirmation_deadline,omitempty"`
	AuditFirst       DecimalV2  `json:"audit_first_sequence,omitempty"`
	AuditLast        DecimalV2  `json:"audit_last_sequence,omitempty"`
}
type OperationV2 struct {
	ID            string     `json:"id"`
	Namespace     string     `json:"namespace_id"`
	Domain        string     `json:"domain"`
	Kind          string     `json:"kind"`
	State         string     `json:"state"`
	Expected      DecimalV2  `json:"expected_generation"`
	Fingerprint   string     `json:"request_fingerprint"`
	Accepted      time.Time  `json:"accepted_at"`
	ExecuteBefore time.Time  `json:"execute_before"`
	Completed     *time.Time `json:"completed_at,omitempty"`
	RetainUntil   *time.Time `json:"retain_until,omitempty"`
	Target        string     `json:"target_revision,omitempty"`
	Origin        string     `json:"origin_commit_operation_id,omitempty"`
	Outcome       *OutcomeV2 `json:"outcome,omitempty"`
}
type OperationResponseV2 struct {
	SchemaVersion int         `json:"schema_version"`
	Operation     OperationV2 `json:"operation"`
	Current       CurrentV2   `json:"current"`
}
type OperationPageV2 struct {
	SchemaVersion int           `json:"schema_version"`
	Operations    []OperationV2 `json:"operations"`
	NextCursor    DecimalV2     `json:"next_cursor"`
	Current       CurrentV2     `json:"current"`
}
type GlobalV2 struct {
	Lineage    string    `json:"lineage_id"`
	Generation DecimalV2 `json:"generation"`
	Running    string    `json:"running_revision"`
	Startup    string    `json:"startup_revision"`
}
type SnapshotV2 struct {
	Generation       DecimalV2            `json:"generation"`
	Candidate        *configpoc.Candidate `json:"candidate"`
	Running          configpoc.Revision   `json:"running"`
	Startup          configpoc.Revision   `json:"startup"`
	LastGood         configpoc.Revision   `json:"last_good"`
	Pending          *configpoc.Pending   `json:"pending"`
	RecoveryRequired bool                 `json:"recovery_required"`
	// Revoked contains durable retired subject IDs in v2, never legacy usernames.
	Revoked []string `json:"revoked"`
}
type CurrentV2 struct {
	DomainGenerations *DomainGenerationsV2 `json:"domain_generations,omitempty"`
	Routed            *RoutedCurrentV2     `json:"routed,omitempty"`
	Global            GlobalV2             `json:"global"`
	Domain            string               `json:"domain"`
	Snapshot          SnapshotV2           `json:"snapshot"`
}

type DomainGenerationsV2 struct {
	Firewall      DecimalV2 `json:"firewall"`
	LocalServices DecimalV2 `json:"local_services"`
	Network       DecimalV2 `json:"network"`
}

type RoutedCurrentV2 struct {
	Confirmation   *configpoc.RoutedConfirmationV2 `json:"confirmation,omitempty"`
	SchemaVersion  int                             `json:"schema_version"`
	LocalServices  SnapshotV2                      `json:"local_services"`
	Running        configpoc.CompositeRevisionV1   `json:"running"`
	Startup        configpoc.CompositeRevisionV1   `json:"startup"`
	LastGood       configpoc.CompositeRevisionV1   `json:"last_good"`
	Candidate      *configpoc.CompositeRevisionV1  `json:"candidate,omitempty"`
	CandidateGroup *configpoc.CandidateGroupV2     `json:"candidate_group,omitempty"`
}

func currentDTOv2(current configpoc.CurrentV2) CurrentV2 {
	result := CurrentV2{Global: GlobalV2{Lineage: current.Global.Lineage, Generation: DecimalV2(current.Global.Generation), Running: current.Global.Running, Startup: current.Global.Startup}, Domain: current.Domain, Snapshot: snapshotDTOv2(current.Snapshot)}
	if d := current.DomainGenerations; d != nil {
		result.DomainGenerations = &DomainGenerationsV2{Firewall: DecimalV2(d.Firewall), LocalServices: DecimalV2(d.LocalServices), Network: DecimalV2(d.Network)}
	}
	if r := current.Routed; r != nil {
		result.Routed = &RoutedCurrentV2{SchemaVersion: r.SchemaVersion, LocalServices: snapshotDTOv2(r.LocalServices), Running: r.Running, Startup: r.Startup, LastGood: r.LastGood, Candidate: r.Candidate, CandidateGroup: r.CandidateGroup, Confirmation: r.Confirmation}
	}
	return result
}

func snapshotDTOv2(s configpoc.Snapshot) SnapshotV2 {
	revoked := s.Revoked
	if revoked == nil {
		revoked = []string{}
	}
	return SnapshotV2{Generation: DecimalV2(s.Generation), Candidate: s.Candidate, Running: s.Running, Startup: s.Startup, LastGood: s.LastGood, Pending: s.Pending, RecoveryRequired: s.RecoveryRequired, Revoked: revoked}
}

type NamespaceClosedV2 struct {
	SchemaVersion int    `json:"schema_version"`
	Namespace     string `json:"namespace_id"`
	State         string `json:"state"`
}

func operationDTOv2(op configpoc.OperationV2) OperationV2 {
	result := OperationV2{ID: op.ID, Namespace: op.Namespace, Domain: op.Domain, Kind: op.Request.Kind, State: op.State, Expected: DecimalV2(op.Expected), Fingerprint: op.Fingerprint, Accepted: op.Accepted, ExecuteBefore: op.ExecuteBefore, Completed: op.Completed, RetainUntil: op.RetainUntil, Target: op.Request.Target, Origin: op.Request.Origin}
	if o := op.Outcome; o != nil {
		result.Outcome = &OutcomeV2{Code: o.Code, ErrorCode: o.ErrorCode, GlobalGeneration: DecimalV2(o.Generation), DomainGeneration: DecimalV2(o.DomainGeneration), Running: o.RunningRevision, Startup: o.StartupRevision, Deadline: o.ConfirmationDeadline, AuditFirst: DecimalV2(o.AuditFirst), AuditLast: DecimalV2(o.AuditLast)}
	}
	return result
}
