package recoveryreserve

import (
	"encoding/json"
	"time"
)

const formatV2 = "andeiva.recovery.reserve.v2"
const headerV2 = 4096

type RoleV2 string

type ClassV2 string

const (
	OrdinaryV2 ClassV2 = "ordinary"
	ClosingV2  ClassV2 = "closing"
	SystemV2   ClassV2 = "system"
)

const (
	AdmissionV2 RoleV2 = "admission"
	PlanV2      RoleV2 = "plan"
	EmergencyV2 RoleV2 = "emergency"
)

func validRoleV2(role RoleV2) bool {
	return role == AdmissionV2 || role == PlanV2 || role == EmergencyV2
}

// ScopeV2 binds bytes to work already authorized by the canonical coordinator.
// It does not authenticate a caller or prove that a configuration was selected.
type ScopeV2 struct {
	Kind        string    `json:"kind"`
	Lineage     string    `json:"lineage"`
	Bundle      string    `json:"bundle"`
	Operation   string    `json:"operation,omitempty"`
	Recovery    string    `json:"recovery,omitempty"`
	Boot        string    `json:"boot,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Domain      string    `json:"domain"`
	Fingerprint string    `json:"fingerprint"`
	Global      uint64    `json:"global_generation,string"`
	Generation  uint64    `json:"domain_generation,string"`
	Origin      string    `json:"origin,omitempty"`
	Lease       string    `json:"lease,omitempty"`
	Deadline    time.Time `json:"deadline"`
}

func (s ScopeV2) Validate() error {
	for _, id := range []string{s.Lineage, s.Bundle} {
		if id == "" || !validOwner(id) {
			return ErrInvalid
		}
	}
	for _, id := range []string{s.Operation, s.Recovery, s.Namespace, s.Subject, s.Origin, s.Lease} {
		if !validOwner(id) {
			return ErrInvalid
		}
	}
	if !digestV2(s.Fingerprint) || s.Global == 0 || s.Generation == 0 || (s.Domain != "firewall" && s.Domain != "local_services") {
		return ErrInvalid
	}
	switch s.Kind {
	case "operation":
		if s.Operation == "" || s.Subject == "" || s.Namespace == "" || s.Recovery != "" || s.Boot != "" {
			return ErrInvalid
		}
	case "recovery":
		if s.Recovery == "" || s.Operation != "" || s.Boot != "" {
			return ErrInvalid
		}
	case "boot":
		if s.Recovery == "" || s.Operation != "" || s.Subject != "" || s.Namespace != "" || !bootV2(s.Boot) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if s.Lease == "" {
		if !s.Deadline.IsZero() {
			return ErrInvalid
		}
	} else if s.Origin == "" || s.Deadline.IsZero() {
		return ErrInvalid
	}
	return nil
}

func (s ScopeV2) Hash() (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	s.Deadline = s.Deadline.UTC()
	data, err := json.Marshal(s)
	if err != nil {
		return "", ErrInvalid
	}
	return digest(data), nil
}

type SlotClaimV2 struct {
	Pool          string `json:"pool"`
	Slot          int    `json:"slot"`
	Epoch         uint64 `json:"epoch,string"`
	Owner         string `json:"owner"`
	Role          RoleV2 `json:"role"`
	ClaimSequence uint64 `json:"claim_sequence,string"`
	Capacity      int    `json:"capacity"`
}

type BindingV2 struct {
	Claim     SlotClaimV2 `json:"claim"`
	Sequence  uint64      `json:"sequence,string"`
	Digest    string      `json:"digest"`
	Length    int         `json:"length"`
	ScopeHash string      `json:"scope_hash"`
}

func (c SlotClaimV2) Validate() error {
	if !validClaimV2(c) {
		return ErrInvalid
	}
	return nil
}

func (b BindingV2) Validate() error {
	if !validBindingV2(b) {
		return ErrInvalid
	}
	return nil
}

type CandidateV2 struct {
	Binding BindingV2
	Bytes   []byte
}

type ExpectedV2 struct {
	Claim   SlotClaimV2 `json:"claim"`
	Written *BindingV2  `json:"written,omitempty"`
}

type SelectionProofV2 struct {
	Selection   string `json:"selection"`
	State       string `json:"state"`
	Sequence    uint64 `json:"sequence,string"`
	Lineage     string `json:"lineage"`
	ArchiveRoot string `json:"archive_root"`
}

// RetirementProofV2 is constructed from a verified canonical selection under
// the coordinator lock. Pool checks its shape, scope and exact record CAS; the
// coordinator must verify canonical membership/finality before calling it.
// No pool callback acquires a store/auth lock. Never decode this from a request.
type RetirementProofV2 struct {
	Scope           ScopeV2          `json:"scope"`
	Archive         string           `json:"archive"`
	FinalAudit      string           `json:"final_audit"`
	FinalWork       string           `json:"final_work"`
	Finality        string           `json:"finality"`
	LeaseResolution string           `json:"lease_resolution,omitempty"`
	Current         SelectionProofV2 `json:"current"`
	Previous        SelectionProofV2 `json:"previous"`
}

func (SlotClaimV2) String() string   { return "<recovery reserve v2 claim>" }
func (SlotClaimV2) GoString() string { return "<recovery reserve v2 claim>" }
func (BindingV2) String() string     { return "<recovery reserve v2 binding>" }
func (BindingV2) GoString() string   { return "<recovery reserve v2 binding>" }
func (CandidateV2) String() string   { return "<recovery reserve v2 candidate>" }
func (CandidateV2) GoString() string { return "<recovery reserve v2 candidate>" }
