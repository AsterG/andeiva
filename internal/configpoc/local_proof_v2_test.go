package configpoc

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/localpolicy"
)

func TestLocalProofV2PreservesUnrelatedStaleCandidate(t *testing.T) {
	for _, kind := range []string{OpCommit, OpValidate, OpSave, OpConfirm} {
		t.Run(kind, func(t *testing.T) {
			in, now := localProofFixtureV2(t, kind)
			in.Firewall.Candidate = &Candidate{Owner: "other-subject", Base: strings.Repeat("f", 64), Revision: in.Firewall.Running}
			before := clone(in)
			if _, err := ResolveLocalProofV2(in, now); err != nil {
				t.Fatal("inactive foreign candidate blocked local mapping", err)
			}
			if !reflect.DeepEqual(before, in) {
				t.Fatal("foreign candidate was rebased or dropped")
			}
			if kind == OpCommit || kind == OpValidate {
				in.Local.Candidate.Base = strings.Repeat("e", 64)
				before = clone(in)
				if _, err := ResolveLocalProofV2(in, now); !errors.Is(err, ErrConflict) {
					t.Fatal("stale local candidate must conflict", err)
				}
				if !reflect.DeepEqual(before, in) {
					t.Fatal("stale local candidate was rebased")
				}
			}
		})
	}
}

// These snapshots are explicit pure-mapper fixtures. The coordinator still
// refuses local transitions; these are not evidence of a running transaction.
func localProofFixtureV2(t testing.TB, kind string) (LocalProofInputV2, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	fw, err := Canonical(Config{SchemaVersion: 4, DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	iface := localpolicy.Interface{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}
	service, err := localpolicy.DefaultManagement("management", "https", iface, iface.Addresses[0], []string{"198.18.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	service.Endpoints = []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: 18443, LastPort: 18443}}
	local, err := Canonical(Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{iface}, Services: []localpolicy.Service{service}}})
	if err != nil {
		t.Fatal(err)
	}
	disabled := clone(local.Config)
	disabled.LocalServices.Services[0].Enabled = false
	previous, err := Canonical(disabled)
	if err != nil {
		t.Fatal(err)
	}
	global, _ := v2CompositeFromDomains(fw, local)
	op := v2Operation{ID: "v2.op.2.fixture", Namespace: "v2.ns.1.fixture", Subject: "subject-a", Lineage: "lineage", Domain: "local_services", Sequence: 2, Expected: 9, State: "accepted", Accepted: now, ExecuteBefore: now.Add(5 * time.Minute), Request: v2Request{Kind: kind}}
	input := LocalProofInputV2{Operation: op, Namespace: v2Namespace{ID: op.Namespace, Subject: op.Subject, Domain: op.Domain, AdmitUntil: now.Add(time.Hour), Open: []string{op.ID}}, Subject: v2Subject{ID: op.Subject, Login: "alice", CredentialRevision: strings.Repeat("a", 64)}, Global: GlobalV2{Lineage: op.Lineage, Generation: 9, Running: global.Hash, Startup: global.Hash}, Firewall: Snapshot{Generation: 3, Running: fw, Startup: fw, LastGood: fw}, Local: Snapshot{Generation: 4, Running: local, Startup: local, LastGood: local}}
	switch kind {
	case OpStage:
		input.Operation.Request.Config = &previous.Config
	case OpValidate, OpCommit:
		input.Local.Candidate = &Candidate{Owner: op.Subject, Base: local.Hash, Revision: previous}
		if kind == OpCommit {
			seconds := uint64(30)
			input.Operation.Request.ConfirmSeconds = &seconds
		}
	case OpConfirm:
		deadline := now.Add(90 * time.Second)
		input.Confirmation = &ConfirmationV2{Origin: "v2.op.1.fixture", Lease: "actual-lease", Domain: op.Domain, Target: global.Hash, Deadline: deadline}
		input.ConfirmationOwner = op.Subject
		input.Operation.Request.Origin = input.Confirmation.Origin
		input.Operation.Request.Target = global.Hash
		seconds := uint64(90)
		origin := clone(op)
		origin.ID, origin.Sequence, origin.Expected, origin.State, origin.Pinned = "v2.op.1.fixture", 1, 8, "final", true
		origin.Request = v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}
		origin.Completed = &now
		origin.Fingerprint = v2OperationFingerprint(origin)
		origin.Outcome = &v2Outcome{Code: "applied_pending_confirmation", RunningRevision: global.Hash, ConfirmationLease: input.Confirmation.Lease, ConfirmationDeadline: &deadline}
		input.Origin = &origin
	case OpRollback:
		input.Historical = &previous
		target, _ := v2CompositeFromDomains(fw, previous)
		input.Operation.Request.Target = target.Hash
	}
	input.Operation.Fingerprint = v2OperationFingerprint(input.Operation)
	return input, now
}

func BenchmarkLocalProofV2Resolve(b *testing.B) {
	in, now := localProofFixtureV2(b, OpConfirm)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ResolveLocalProofV2(in, now); err != nil {
			b.Fatal(err)
		}
	}
}

func TestLocalProofV2PureMapping(t *testing.T) {
	for _, kind := range []string{OpStage, OpValidate, OpCommit, OpConfirm, OpSave, OpRollback} {
		t.Run(kind, func(t *testing.T) {
			in, now := localProofFixtureV2(t, kind)
			before := clone(in)
			scope, err := ResolveLocalProofV2(in, now)
			if err != nil || !scope.Valid() || !reflect.DeepEqual(before, in) {
				t.Fatal("pure resolution", err)
			}
			b := scope.Binding()
			composite, _ := v2CompositeFromDomains(in.Firewall.Running, scope.Target())
			if b.Target != composite.Hash || b.LocalTarget != scope.Target().Hash || b.Target == b.LocalTarget || b.Operation != in.Operation.ID || b.Generation != 9 || b.LocalGeneration != 4 || b.Fingerprint != in.Operation.Fingerprint {
				t.Fatal("incorrect scope", b)
			}
			if kind == OpConfirm {
				if b.Purpose != "confirm" || b.Lease != "actual-lease" || b.Origin != in.Origin.ID {
					t.Fatal("pending scope", b)
				}
			} else if b.Lease != "" || b.Origin != "" || !b.Deadline.IsZero() || b.Purpose != "execute" {
				t.Fatal("invented lease", b)
			}
			r := scope.Target()
			r.Config.LocalServices.Services[0].Enabled = !r.Config.LocalServices.Services[0].Enabled
			if reflect.DeepEqual(r, scope.Target()) {
				t.Fatal("scope exposed mutable target")
			}
			data, err := json.Marshal(scope)
			if err != nil || string(data) != "{}" {
				t.Fatal("opaque scope became durable DTO")
			}
		})
	}
}

func TestLocalProofV2RejectsInvalidMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LocalProofInputV2)
	}{
		{"fingerprint", func(i *LocalProofInputV2) { i.Operation.Fingerprint = strings.Repeat("f", 64) }},
		{"generation", func(i *LocalProofInputV2) { i.Global.Generation++ }},
		{"global-local-confusion", func(i *LocalProofInputV2) { i.Global.Running = i.Local.Running.Hash }},
		{"startup", func(i *LocalProofInputV2) { i.Global.Startup = i.Local.Running.Hash }},
		{"lineage", func(i *LocalProofInputV2) { i.Global.Lineage = "other" }},
		{"closed-namespace", func(i *LocalProofInputV2) { i.Namespace.Closed = true }},
		{"missing-operation", func(i *LocalProofInputV2) { i.Namespace.Open = nil }},
		{"duplicated-operation", func(i *LocalProofInputV2) { i.Namespace.Open = append(i.Namespace.Open, i.Operation.ID) }},
		{"namespace-owner", func(i *LocalProofInputV2) { i.Namespace.Subject = "other" }},
		{"subject", func(i *LocalProofInputV2) { i.Subject.ID = "other" }},
		{"retired", func(i *LocalProofInputV2) { i.Subject.Retired = true }},
		{"credential", func(i *LocalProofInputV2) { i.Subject.CredentialRevision = "" }},
		{"final-replay", func(i *LocalProofInputV2) { i.Operation.State = "final" }},
		{"pending-replay", func(i *LocalProofInputV2) { i.Operation.State = "pending" }},
		{"candidate-owner", func(i *LocalProofInputV2) { i.Local.Candidate.Owner = "other" }},
		{"candidate-base", func(i *LocalProofInputV2) { i.Local.Candidate.Base = i.Local.Candidate.Revision.Hash }},
		{"invalid-component", func(i *LocalProofInputV2) { i.Local.Running.Hash = strings.Repeat("f", 64) }},
		{"local-recovery", func(i *LocalProofInputV2) { i.Local.RecoveryRequired = true }},
		{"other-recovery", func(i *LocalProofInputV2) { i.Firewall.RecoveryRequired = true }},
		{"immediate", func(i *LocalProofInputV2) {
			*i.Operation.Request.ConfirmSeconds = 0
			i.Operation.Fingerprint = v2OperationFingerprint(i.Operation)
		}},
		{"expired", func(i *LocalProofInputV2) { i.Operation.ExecuteBefore = i.Operation.Accepted }},
		{"overlong", func(i *LocalProofInputV2) { i.Operation.ExecuteBefore = i.Operation.Accepted.Add(16 * time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, now := localProofFixtureV2(t, OpCommit)
			tc.change(&in)
			before := clone(in)
			if s, e := ResolveLocalProofV2(in, now); e == nil || s.Valid() {
				t.Fatal("invalid mapping accepted")
			}
			if !reflect.DeepEqual(before, in) {
				t.Fatal("rejection mutated input")
			}
		})
	}
}

func TestLocalProofV2ConfirmationAndHistoricalBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*LocalProofInputV2)
	}{
		{"missing", func(i *LocalProofInputV2) { i.Confirmation = nil }},
		{"foreign-owner", func(i *LocalProofInputV2) { i.ConfirmationOwner = "other" }},
		{"lease", func(i *LocalProofInputV2) { i.Confirmation.Lease = "other" }},
		{"domain", func(i *LocalProofInputV2) { i.Confirmation.Domain = "firewall" }},
		{"target", func(i *LocalProofInputV2) { i.Confirmation.Target = i.Local.Running.Hash }},
		{"expired", func(i *LocalProofInputV2) { i.Confirmation.Deadline = i.Operation.Accepted }},
		{"deadline", func(i *LocalProofInputV2) { i.Confirmation.Deadline = i.Confirmation.Deadline.Add(time.Second) }},
		{"missing-origin", func(i *LocalProofInputV2) { i.Origin = nil }},
		{"origin-unpinned", func(i *LocalProofInputV2) { i.Origin.Pinned = false }},
		{"origin-subject", func(i *LocalProofInputV2) { i.Origin.Subject = "other" }},
		{"origin-outcome", func(i *LocalProofInputV2) { i.Origin.Outcome.Code = "applied" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, now := localProofFixtureV2(t, OpConfirm)
			tc.change(&in)
			if _, e := ResolveLocalProofV2(in, now); e == nil {
				t.Fatal("invalid confirmation accepted")
			}
		})
	}
	in, now := localProofFixtureV2(t, OpRollback)
	in.Operation.Request.Target = in.Historical.Hash
	in.Operation.Fingerprint = v2OperationFingerprint(in.Operation)
	if _, err := ResolveLocalProofV2(in, now); err == nil {
		t.Fatal("domain hash accepted as global rollback")
	}
	for _, kind := range []string{OpRecover, OpRevoke} {
		in, now = localProofFixtureV2(t, kind)
		if _, err := ResolveLocalProofV2(in, now); err == nil {
			t.Fatal("unqualified operation", kind)
		}
	}
}
