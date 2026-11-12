package configpoc

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	v2Format            = "andeiva.configuration.store.v2"
	v2ObjectLimit       = 1024 * 1024
	v2PageWidth         = 64
	v2MaximumOperations = 64 * 64 * 64
	v2MaximumSubjects   = 256
	v2MaximumNamespaces = 256
	v2MaximumOpen       = 8
	// Three lifecycle mutations may each publish a full bounded metadata image,
	// an operation, three index pages, an audit object and selector copies.
	// Keep an intentionally conservative allowance; this is not disk allocation.
	v2OperationReserveBytes  = 16 * v2ObjectLimit
	v2OperationReserveInodes = 64
)

var (
	errV2Unavailable = errors.New("ANDEIVA_OPERATION_UNAVAILABLE")
	errV2NotFound    = errors.New("ANDEIVA_OPERATION_NOT_FOUND")
	errV2Invalid     = errors.New("ANDEIVA_OPERATION_INVALID")
	errV2Limited     = errors.New("ANDEIVA_OPERATION_LIMITED")
	errV2Closed      = errors.New("ANDEIVA_NAMESPACE_CLOSED")
	errV2Expired     = errors.New("ANDEIVA_OPERATION_EXPIRED")
	errV2Uncertain   = errors.New("ANDEIVA_OPERATION_UNCERTAIN")
	v2HashPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// These internal types are not transport DTOs or an enabled coordinator.
type v2Subject struct {
	ID                 string `json:"id"`
	Login              string `json:"login"`
	CredentialRevision string `json:"credential_revision"`
	Retired            bool   `json:"retired"`
}
type v2Namespace struct {
	ID         string    `json:"id"`
	Subject    string    `json:"subject"`
	Domain     string    `json:"domain"`
	Closed     bool      `json:"closed"`
	AdmitUntil time.Time `json:"admit_until"`
	Open       []string  `json:"open"`
}
type v2Request struct {
	Kind           string  `json:"kind"`
	Config         *Config `json:"config,omitempty"`
	ConfirmSeconds *uint64 `json:"confirm_seconds,omitempty"`
	Target         string  `json:"target_revision,omitempty"`
	Origin         string  `json:"origin_commit_operation_id,omitempty"`
	Subject        string  `json:"target_subject_id,omitempty"`
}
type v2Outcome struct {
	Code       string `json:"code"`
	ErrorCode  string `json:"error_code,omitempty"`
	Generation uint64 `json:"generation,string"`
	AuditHash  string `json:"audit_hash"`
}
type v2Operation struct {
	ID            string     `json:"id"`
	Namespace     string     `json:"namespace_id"`
	Subject       string     `json:"subject"`
	Lineage       string     `json:"lineage"`
	Domain        string     `json:"domain"`
	Sequence      uint64     `json:"sequence,string"`
	Expected      uint64     `json:"expected_generation,string"`
	Request       v2Request  `json:"request"`
	Fingerprint   string     `json:"fingerprint"`
	State         string     `json:"state"`
	Accepted      time.Time  `json:"accepted_at"`
	ExecuteBefore time.Time  `json:"execute_before"`
	Completed     *time.Time `json:"completed_at,omitempty"`
	RetainUntil   *time.Time `json:"retain_until,omitempty"`
	Outcome       *v2Outcome `json:"outcome,omitempty"`
	Pinned        bool       `json:"pinned"`
	Retired       bool       `json:"retired"`
}
type v2State struct {
	Format            string        `json:"format"`
	Lineage           string        `json:"lineage"`
	Generation        uint64        `json:"generation,string"`
	HighWater         uint64        `json:"operation_high_water,string"`
	LiveSlots         uint64        `json:"live_slots,string"`
	SubjectSlots      uint64        `json:"subject_slots,string"`
	NamespaceSlots    uint64        `json:"namespace_slots,string"`
	NamespaceSequence uint64        `json:"namespace_sequence,string"`
	SubjectSequence   uint64        `json:"subject_sequence,string"`
	Index             string        `json:"index"`
	Subjects          []v2Subject   `json:"subjects"`
	Namespaces        []v2Namespace `json:"namespaces"`
	ReservedBytes     uint64        `json:"reserved_bytes,string"`
	ReservedInodes    uint64        `json:"reserved_inodes,string"`
	Clock             time.Time     `json:"clock"`
	Migration         string        `json:"migration,omitempty"`
	Operational       bool          `json:"operational"`
}
type v2Page struct {
	Format string              `json:"format"`
	Level  int                 `json:"level"`
	Refs   [v2PageWidth]string `json:"refs"`
}
type v2Selection struct {
	Format     string `json:"format"`
	Lineage    string `json:"lineage"`
	Sequence   uint64 `json:"sequence,string"`
	State      string `json:"state"`
	Previous   string `json:"previous"`
	Segment    uint64 `json:"segment,string"`
	Checkpoint bool   `json:"checkpoint"`
}
type v2Selector struct {
	Format   string `json:"format"`
	Current  string `json:"current"`
	Previous string `json:"previous"`
}
type v2Budget struct{ Bytes, Inodes uint64 }

func v2Canonical(value any) ([]byte, string, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > v2ObjectLimit {
		return nil, "", errV2Invalid
	}
	return data, checkpointDigest(data), nil
}
func v2RequestValid(domain string, r v2Request) bool {
	if domain != "firewall" && domain != "local_services" {
		return false
	}
	switch r.Kind {
	case OpStage:
		if r.Config == nil || r.ConfirmSeconds != nil || r.Target != "" || r.Origin != "" || r.Subject != "" {
			return false
		}
		if (domain == "firewall" && r.Config.SchemaVersion != 4) || (domain == "local_services" && r.Config.SchemaVersion != 3) {
			return false
		}
		_, err := Canonical(*r.Config)
		return err == nil
	case OpValidate, OpSave, OpRecover:
		return r.Config == nil && r.ConfirmSeconds == nil && r.Target == "" && r.Origin == "" && r.Subject == ""
	case OpCommit:
		return r.Config == nil && r.ConfirmSeconds != nil && (*r.ConfirmSeconds == 0 || (*r.ConfirmSeconds >= 30 && *r.ConfirmSeconds <= 120)) && r.Target == "" && r.Origin == "" && r.Subject == ""
	case OpConfirm:
		return r.Config == nil && r.ConfirmSeconds == nil && v2HashPattern.MatchString(r.Target) && r.Origin != "" && r.Subject == ""
	case OpRollback:
		return r.Config == nil && r.ConfirmSeconds == nil && v2HashPattern.MatchString(r.Target) && r.Origin == "" && r.Subject == ""
	case OpRevoke:
		return r.Config == nil && r.ConfirmSeconds == nil && r.Target == "" && r.Origin == "" && r.Subject != ""
	}
	return false
}
func v2OperationFingerprint(op v2Operation) string {
	_, hash, _ := v2Canonical(struct {
		ID, Namespace, Subject, Lineage, Domain string
		Expected                                uint64 `json:",string"`
		Request                                 v2Request
	}{op.ID, op.Namespace, op.Subject, op.Lineage, op.Domain, op.Expected, op.Request})
	return hash
}
func v2ObjectName(hash string) (string, error) {
	if !v2HashPattern.MatchString(hash) {
		return "", errV2Unavailable
	}
	return fmt.Sprintf("object-%s.json", hash), nil
}
