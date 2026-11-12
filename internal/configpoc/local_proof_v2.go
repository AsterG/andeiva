package configpoc

import (
	"reflect"
	"time"
)

// LocalProofInputV2 is a prepared, trusted snapshot input, not a transport DTO or
// an authorization grant. F2 must construct and revalidate it under store.mu.
// The resolver performs no I/O and does not enable local domain transitions.
type LocalProofInputV2 struct {
	Operation         OperationV2
	Namespace         NamespaceV2
	Subject           SubjectV2
	Global            GlobalV2
	Firewall, Local   Snapshot
	Confirmation      *ConfirmationV2
	ConfirmationOwner string
	Origin            *OperationV2
	// Historical must already have a verified retained global witness. Its local
	// component alone cannot establish historical provenance.
	Historical *Revision
}

// LocalProofBindingV2 contains no bearer material. Target is the composite hash;
// LocalTarget is the schema3 hash served by a managed listener.
type LocalProofBindingV2 struct {
	Lineage, Namespace, Operation, Fingerprint, Subject, Login, CredentialRevision string
	Kind, Purpose                                                                  string
	Generation, LocalGeneration                                                    uint64
	Current, Target, LocalTarget                                                   string
	Origin, Lease                                                                  string
	Deadline, ExecuteBefore                                                        time.Time
}

// LocalProofScopeV2 can only be produced by the pure resolver. It is not proof of
// storage selection or real endpoint activation. Its zero value is invalid.
type LocalProofScopeV2 struct {
	binding LocalProofBindingV2
	target  Revision
	valid   bool
}

func (s LocalProofScopeV2) Valid() bool                  { return s.valid }
func (s LocalProofScopeV2) Binding() LocalProofBindingV2 { return s.binding }
func (s LocalProofScopeV2) Target() Revision             { return clone(s.target) }

func localProofRevision(r Revision, schema int) bool {
	c, err := Canonical(r.Config)
	return err == nil && r.Config.SchemaVersion == schema && c.Hash == r.Hash && reflect.DeepEqual(c.Config, r.Config)
}

func localProofSnapshot(s Snapshot, schema int) bool {
	if s.Generation == 0 || s.RecoveryRequired || s.Pending != nil {
		return false
	}
	for _, r := range []Revision{s.Running, s.Startup, s.LastGood} {
		if !localProofRevision(r, schema) {
			return false
		}
		if schema == 3 && (len(r.Config.Rules) != 0 || r.Config.DefaultAction != "deny") {
			return false
		}
	}
	return s.Candidate == nil || (s.Candidate.Owner != "" && len(s.Candidate.Owner) <= 128 && validHash(s.Candidate.Base) && localProofRevision(s.Candidate.Revision, schema))
}

// ResolveLocalProofV2 derives the exact operation/global/component tuple. It
// neither authenticates nor verifies a historical witness. Callers must obtain
// those inputs from the existing subject registry and retained-object validator.
// Final/pending replay is deliberately not mapped: it uses existing observation
// without issuing or consuming evidence again.
func ResolveLocalProofV2(in LocalProofInputV2, now time.Time) (LocalProofScopeV2, error) {
	op, ns, subject := in.Operation, in.Namespace, in.Subject
	requestBytes, _, requestErr := v2Canonical(op.Request)
	if op.State != "accepted" || op.Retired || op.Pinned || op.Completed != nil || op.Outcome != nil || op.RetainUntil != nil ||
		op.ID == "" || len(op.ID) > 128 || op.Sequence == 0 || op.Namespace == "" || len(op.Namespace) > 128 ||
		op.Domain != "local_services" || requestErr != nil || len(requestBytes) > 8192 || !v2RequestValid(op.Domain, op.Request) || !v2HashPattern.MatchString(op.Fingerprint) || op.Fingerprint != operationDTOFingerprintV2(op) ||
		op.Lineage == "" || len(op.Lineage) > 128 || op.Lineage != in.Global.Lineage || op.Expected != in.Global.Generation ||
		op.Accepted.IsZero() || now.Before(op.Accepted) || !now.Before(op.ExecuteBefore) || op.ExecuteBefore.After(op.Accepted.Add(15*time.Minute)) ||
		ns.ID != op.Namespace || ns.Subject != op.Subject || ns.Domain != op.Domain || ns.Closed || !ns.AdmitUntil.After(op.Accepted) {
		return LocalProofScopeV2{}, ErrInvalid
	}
	if subject.Retired || subject.ID == "" || len(subject.ID) > 128 || subject.ID != op.Subject || !identifier.MatchString(subject.Login) || subject.Login == "system" || !v2HashPattern.MatchString(subject.CredentialRevision) {
		return LocalProofScopeV2{}, ErrDenied
	}
	open := 0
	for _, id := range ns.Open {
		if id == op.ID {
			open++
		}
	}
	if open != 1 || len(ns.Open) > v2MaximumOpen || !localProofSnapshot(in.Firewall, 4) || !localProofSnapshot(in.Local, 3) {
		return LocalProofScopeV2{}, ErrInvalid
	}
	running, err := v2CompositeFromDomains(in.Firewall.Running, in.Local.Running)
	startup, startupErr := v2CompositeFromDomains(in.Firewall.Startup, in.Local.Startup)
	if err != nil || startupErr != nil || in.Global.Generation == 0 || in.Global.Running != running.Hash || in.Global.Startup != startup.Hash {
		return LocalProofScopeV2{}, ErrInvalid
	}
	b := LocalProofBindingV2{Lineage: op.Lineage, Namespace: op.Namespace, Operation: op.ID, Fingerprint: op.Fingerprint,
		Subject: subject.ID, Login: subject.Login, CredentialRevision: subject.CredentialRevision, Kind: op.Request.Kind, Purpose: "execute",
		Generation: in.Global.Generation, LocalGeneration: in.Local.Generation, Current: running.Hash, ExecuteBefore: op.ExecuteBefore.UTC()}
	target := in.Local.Running
	if in.Confirmation != nil && op.Request.Kind != OpConfirm {
		return LocalProofScopeV2{}, ErrPending
	}
	if in.Historical != nil && op.Request.Kind != OpRollback {
		return LocalProofScopeV2{}, ErrInvalid
	}
	if op.Request.Kind != OpConfirm && (in.Origin != nil || in.ConfirmationOwner != "") {
		return LocalProofScopeV2{}, ErrInvalid
	}
	switch op.Request.Kind {
	case OpStage:
		if in.Local.Candidate != nil && in.Local.Candidate.Owner != subject.ID {
			return LocalProofScopeV2{}, ErrConflict
		}
		target, err = Canonical(*op.Request.Config)
	case OpValidate, OpCommit:
		if in.Local.Candidate == nil || in.Local.Candidate.Owner != subject.ID || in.Local.Candidate.Base != in.Local.Running.Hash {
			return LocalProofScopeV2{}, ErrConflict
		}
		target = in.Local.Candidate.Revision
		if op.Request.Kind == OpCommit && (op.Request.ConfirmSeconds == nil || *op.Request.ConfirmSeconds < 30 || *op.Request.ConfirmSeconds > 120) {
			return LocalProofScopeV2{}, ErrInvalid
		}
	case OpConfirm:
		p := in.Confirmation
		if p == nil || p.Domain != "local_services" || p.Origin == "" || p.Origin != op.Request.Origin || p.Lease == "" || len(p.Lease) > 64 || p.Target != op.Request.Target || p.Target != running.Hash || !now.Before(p.Deadline) || p.Deadline.After(now.Add(120*time.Second)) {
			return LocalProofScopeV2{}, ErrConflict
		}
		o := in.Origin
		if in.ConfirmationOwner != subject.ID || o == nil || o.ID != p.Origin || len(o.ID) > 128 || o.Subject != subject.ID || o.Lineage != op.Lineage || o.Domain != op.Domain || (o.Request.Kind != OpCommit && o.Request.Kind != OpRollback) || !v2RequestValid(o.Domain, o.Request) || !v2HashPattern.MatchString(o.Fingerprint) || o.Fingerprint != operationDTOFingerprintV2(*o) || o.State != "final" || !o.Pinned || o.Retired || o.Completed == nil || o.Outcome == nil || o.Outcome.Code != "applied_pending_confirmation" || o.Outcome.RunningRevision != p.Target || o.Outcome.ConfirmationLease != p.Lease || o.Outcome.ConfirmationDeadline == nil || !o.Outcome.ConfirmationDeadline.Equal(p.Deadline) {
			return LocalProofScopeV2{}, ErrConflict
		}
		b.Purpose, b.Origin, b.Lease, b.Deadline = "confirm", p.Origin, p.Lease, p.Deadline.UTC()
	case OpSave:
	case OpRollback:
		if in.Historical == nil || !localProofRevision(*in.Historical, 3) {
			return LocalProofScopeV2{}, ErrInvalid
		}
		target = *in.Historical
	default:
		return LocalProofScopeV2{}, ErrDenied
	}
	if err != nil || !localProofRevision(target, 3) || len(target.Config.Rules) != 0 || target.Config.DefaultAction != "deny" {
		return LocalProofScopeV2{}, ErrInvalid
	}
	composite, err := v2CompositeFromDomains(in.Firewall.Running, target)
	if err != nil || (op.Request.Kind == OpRollback && composite.Hash != op.Request.Target) {
		return LocalProofScopeV2{}, ErrInvalid
	}
	b.Target, b.LocalTarget = composite.Hash, target.Hash
	return LocalProofScopeV2{binding: b, target: clone(target), valid: true}, nil
}
