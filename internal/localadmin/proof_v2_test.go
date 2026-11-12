package localadmin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type proofFixtureV2 struct {
	book              *PreparedProofBookV2
	auth              *adminauth.Manager
	input             configpoc.LocalProofInputV2
	scope             configpoc.LocalProofScopeV2
	session           adminauth.SessionBinding
	receiver          ProofReceiverV2
	token, credential string
	now               time.Time
}

func proofDigestV2(t testing.TB, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
func proofFingerprintV2(t testing.TB, o configpoc.OperationV2) string {
	return proofDigestV2(t, struct {
		ID, Namespace, Subject, Lineage, Domain string
		Expected                                uint64 `json:",string"`
		Request                                 configpoc.OperationRequestV2
	}{o.ID, o.Namespace, o.Subject, o.Lineage, o.Domain, o.Expected, o.Request})
}
func proofCompositeV2(t testing.TB, fw, local string) string {
	type ref struct {
		Schema   int    `json:"config_schema"`
		Revision string `json:"revision"`
	}
	type domains struct {
		Firewall ref  `json:"firewall"`
		Local    ref  `json:"local_services"`
		Network  *ref `json:"network"`
	}
	return proofDigestV2(t, struct {
		Schema  int     `json:"schema_version"`
		Domains domains `json:"domains"`
	}{5, domains{ref{4, fw}, ref{3, local}, nil}})
}
func newProofFixtureV2(t testing.TB, confirm, enabled bool) *proofFixtureV2 {
	t.Helper()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	credential := hex.EncodeToString(secret[:])
	digest := sha256.Sum256([]byte(credential))
	accounts := []adminauth.Account{}
	for _, name := range []string{"alice", "bob", "viewer"} {
		role := "admin"
		if name == "viewer" {
			role = "viewer"
		}
		accounts = append(accounts, adminauth.Account{Username: name, Role: role, CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: "subject-" + name, CredentialRevision: strings.Repeat("a", 64)})
	}
	auth, err := adminauth.New(accounts, func(adminauth.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := auth.Login("alice", credential)
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.ResolveSession(token)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	recovery := ProofReceiverV2{Run: strings.Repeat("1", 32), Instance: strings.Repeat("2", 32), Endpoint: "recovery", Namespace: 100, Surface: configpoc.API}
	book, err := NewPreparedProofBookV2(auth, recovery, inventory())
	if err != nil {
		t.Fatal(err)
	}
	f := &proofFixtureV2{book: book, auth: auth, session: session, token: token, credential: credential, now: now}
	book.now = func() time.Time { return f.now }
	t.Cleanup(book.Close)
	fw, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	iface := inventory()[0]
	service, err := localpolicy.DefaultManagement("management", "https", iface, iface.Addresses[0], []string{"198.18.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	service.Endpoints = []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: 18443, LastPort: 18443}}
	service.Enabled = enabled
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: inventory(), Services: []localpolicy.Service{service}}})
	if err != nil {
		t.Fatal(err)
	}
	global := proofCompositeV2(t, fw.Hash, local.Hash)
	seconds := uint64(90)
	op := configpoc.OperationV2{ID: "v2.op.2.fixture", Namespace: "v2.ns.1.fixture", Subject: "subject-alice", Lineage: "lineage", Domain: "local_services", Sequence: 2, Expected: 9, State: "accepted", Accepted: now, ExecuteBefore: now.Add(5 * time.Minute), Request: configpoc.OperationRequestV2{Kind: configpoc.OpCommit, ConfirmSeconds: &seconds}}
	in := configpoc.LocalProofInputV2{Operation: op, Namespace: configpoc.NamespaceV2{ID: op.Namespace, Subject: op.Subject, Domain: op.Domain, AdmitUntil: now.Add(time.Hour), Open: []string{op.ID}}, Subject: configpoc.SubjectV2{ID: op.Subject, Login: "alice", CredentialRevision: strings.Repeat("a", 64)}, Global: configpoc.GlobalV2{Lineage: op.Lineage, Generation: 9, Running: global, Startup: global}, Firewall: configpoc.Snapshot{Generation: 3, Running: fw, Startup: fw, LastGood: fw}, Local: configpoc.Snapshot{Generation: 4, Running: local, Startup: local, LastGood: local, Candidate: &configpoc.Candidate{Owner: op.Subject, Base: local.Hash, Revision: local}}}
	if confirm {
		in.Local.Candidate = nil
		deadline := now.Add(90 * time.Second)
		in.Confirmation = &configpoc.ConfirmationV2{Origin: "v2.op.1.fixture", Lease: "actual-lease", Domain: op.Domain, Target: global, Deadline: deadline}
		in.ConfirmationOwner = op.Subject
		origin := op
		origin.ID = "v2.op.1.fixture"
		origin.State = "final"
		origin.Pinned = true
		origin.Completed = &now
		origin.Fingerprint = proofFingerprintV2(t, origin)
		// Outcome is an alias of an internal type; JSON is used ONLY to construct
		// this explicit pure-mapper fixture, not as a trusted production receipt.
		data := fmt.Sprintf(`{"code":"applied_pending_confirmation","running_revision":%q,"confirmation_lease":"actual-lease","confirmation_deadline":%q}`, global, deadline.Format(time.RFC3339Nano))
		if err := json.Unmarshal([]byte(data), &origin.Outcome); err != nil {
			t.Fatal(err)
		}
		in.Origin = &origin
		in.Operation.Request = configpoc.OperationRequestV2{Kind: configpoc.OpConfirm, Target: global, Origin: origin.ID}
	}
	in.Operation.Fingerprint = proofFingerprintV2(t, in.Operation)
	f.input = in
	f.scope, err = configpoc.ResolveLocalProofV2(in, now)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		f.receiver = ProofReceiverV2{Run: recovery.Run, Instance: strings.Repeat("3", 32), Endpoint: BindingEndpointID(expectedListeners(local.Config)[0]), ActivationHash: local.Hash, Namespace: 200, Surface: configpoc.Web}
	}
	return f
}
func (f *proofFixtureV2) identity(t *testing.T, session adminauth.SessionBinding) ProofIdentityV2 {
	t.Helper()
	id, err := f.book.Authenticate(session)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func (f *proofFixtureV2) issue(t *testing.T, r ProofReceiverV2, session adminauth.SessionBinding) Proof {
	t.Helper()
	p, err := f.book.Issue(f.identity(t, session), f.scope, r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (f *proofFixtureV2) login(t *testing.T, name string) adminauth.SessionBinding {
	t.Helper()
	_, token, err := f.auth.Login(name, f.credential)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.auth.ResolveSession(token)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPreparedLocalProofV2RecoveryAndReservation(t *testing.T) {
	f := newProofFixtureV2(t, false, true)
	p := f.issue(t, f.book.recovery, f.session)
	if p.ExpiresAt.Sub(f.now) != ProofTTL || len(p.Token) != 64 {
		t.Fatal("recovery TTL/token")
	}
	evidence := ProofEvidenceV2{Recovery: p.Token}
	id := f.identity(t, f.session)
	bad := evidence
	bad.Endpoints = []string{p.Token}
	if _, err := f.book.Reserve(id, f.scope, bad); err == nil {
		t.Fatal("extra proof")
	}
	r, err := f.book.Reserve(id, f.scope, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.book.Reserve(id, f.scope, evidence); err == nil {
		t.Fatal("concurrent replay")
	}
	r.Finish(false)
	r2, err := f.book.Reserve(id, f.scope, evidence)
	if err != nil {
		t.Fatal("safe release", err)
	}
	r.Finish(false)
	if _, err = f.book.Reserve(id, f.scope, evidence); err == nil {
		t.Fatal("old reservation released new owner")
	}
	r2.Finish(true)
	if _, err = f.book.Reserve(id, f.scope, evidence); err == nil {
		t.Fatal("consumed replay")
	}
	p = f.issue(t, f.book.recovery, f.session)
	f.now = f.now.Add(ProofTTL)
	if _, err = f.book.Reserve(id, f.scope, ProofEvidenceV2{Recovery: p.Token}); err == nil {
		t.Fatal("expiry boundary")
	}
	if len(f.book.entries) > MaxProofs {
		t.Fatal("capacity")
	}
}

func TestPreparedLocalProofV2EndpointPublicationAndSession(t *testing.T) {
	f := newProofFixtureV2(t, true, true)
	id := f.identity(t, f.session)
	if _, err := f.book.Issue(id, f.scope, f.receiver); err == nil {
		t.Fatal("prepublished endpoint")
	}
	if err := f.book.Publish(f.scope, []ProofReceiverV2{f.receiver}); err != nil {
		t.Fatal(err)
	}
	second := f.login(t, "alice")
	p := f.issue(t, f.receiver, second)
	if p.ExpiresAt.Sub(f.now) != EndpointProofTTL {
		t.Fatal("endpoint TTL")
	}
	recovery := f.issue(t, f.book.recovery, f.session)
	bad := ProofEvidenceV2{Recovery: recovery.Token, Endpoints: []string{strings.Repeat("0", 64)}}
	if _, err := f.book.Reserve(id, f.scope, bad); err == nil {
		t.Fatal("missing endpoint accepted")
	}
	if _, err := f.book.Reserve(f.identity(t, second), f.scope, ProofEvidenceV2{Recovery: recovery.Token, Endpoints: []string{p.Token}}); err == nil {
		t.Fatal("recovery borrowed session")
	}
	r, err := f.book.Reserve(id, f.scope, ProofEvidenceV2{Recovery: recovery.Token, Endpoints: []string{p.Token}})
	if err != nil {
		t.Fatal("same subject new endpoint session", err)
	}
	r.Finish(false)
	replacement := f.receiver
	replacement.Instance = strings.Repeat("4", 32)
	if err = f.book.Publish(f.scope, []ProofReceiverV2{replacement}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.book.Reserve(id, f.scope, ProofEvidenceV2{Recovery: recovery.Token, Endpoints: []string{p.Token}}); err == nil {
		t.Fatal("old instance proof")
	}
	if _, err = f.book.Issue(id, f.scope, f.receiver); err == nil {
		t.Fatal("old in-flight receiver")
	}
	if _, err = f.book.Issue(id, f.scope, replacement); err != nil {
		t.Fatal("new instance", err)
	}
}

func TestPreparedLocalProofV2RefreshAndConfidentiality(t *testing.T) {
	f := newProofFixtureV2(t, false, true)
	id := f.identity(t, f.session)
	p := f.issue(t, f.book.recovery, f.session)
	f.now = f.now.Add(ProofTTL)
	fresh := f.issue(t, f.book.recovery, f.session)
	if fresh.Token == p.Token || f.scope.Binding().Operation != f.input.Operation.ID {
		t.Fatal("refresh changed operation/reused token")
	}
	webRecovery := f.book.recovery
	webRecovery.Surface = configpoc.Web
	if _, err := f.book.Issue(id, f.scope, webRecovery); err != nil {
		t.Fatal("shared HTTPS receiver", err)
	}
	r, err := f.book.Reserve(id, f.scope, ProofEvidenceV2{Recovery: fresh.Token})
	if err != nil {
		t.Fatal(err)
	}
	r.Finish(true)
	for _, value := range []any{id, f.book, r, f.scope, ProofEvidenceV2{Recovery: p.Token, Endpoints: []string{fresh.Token}}} {
		data, err := json.Marshal(value)
		if err != nil || string(data) != "{}" {
			t.Fatal("ephemeral internal state serialized")
		}
	}
	if strings.Contains(fmt.Sprintf("%#v", id), "issuer") || strings.Contains(fmt.Sprintf("%#v", ProofEvidenceV2{Recovery: p.Token}), p.Token) {
		t.Fatal("debug exposed evidence")
	}
	bindingBytes, err := json.Marshal(f.scope.Binding())
	if err != nil {
		t.Fatal(err)
	}
	targetBytes, err := json.Marshal(f.scope.Target())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prepared scope binding=%d bytes, target=%d bytes, entry limit=%d; no durable evidence writes", len(bindingBytes), len(targetBytes), MaxProofs)
}

func BenchmarkPreparedLocalProofV2IssueReserve(b *testing.B) {
	for _, retained := range []int{0, MaxProofs - 1} {
		b.Run(fmt.Sprintf("retained_%d", retained), func(b *testing.B) { benchmarkProofBookV2(b, retained) })
	}
}

func benchmarkProofBookV2(b *testing.B, retained int) {
	f := newProofFixtureV2(b, false, true)
	id, err := f.book.Authenticate(f.session)
	if err != nil {
		b.Fatal(err)
	}
	for range retained {
		if _, err := f.book.Issue(id, f.scope, f.book.recovery); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		p, err := f.book.Issue(id, f.scope, f.book.recovery)
		if err != nil {
			b.Fatal(err)
		}
		r, err := f.book.Reserve(id, f.scope, ProofEvidenceV2{Recovery: p.Token})
		if err != nil {
			b.Fatal(err)
		}
		r.Finish(true)
	}
}

func TestPreparedLocalProofV2ExecuteWindowAndProfile(t *testing.T) {
	f := newProofFixtureV2(t, false, true)
	in := copyValue(f.input)
	in.Operation.ExecuteBefore = f.now.Add(3 * time.Second)
	scope, err := configpoc.ResolveLocalProofV2(in, f.now)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.book.Issue(f.identity(t, f.session), scope, f.book.recovery)
	if err != nil || !p.ExpiresAt.Equal(in.Operation.ExecuteBefore) {
		t.Fatal("execute window extended", err)
	}
	// The pure canonical resolver does not replace trusted inventory validation.
	changed := copyValue(f.input)
	config := changed.Local.Candidate.Revision.Config
	config.LocalServices.Interfaces[0].Addresses = append(config.LocalServices.Interfaces[0].Addresses, "198.18.0.10")
	changed.Local.Candidate.Revision, err = configpoc.Canonical(config)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := configpoc.ResolveLocalProofV2(changed, f.now)
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.book.entries)
	if _, err = f.book.Issue(f.identity(t, f.session), bad, f.book.recovery); err == nil || len(f.book.entries) != before {
		t.Fatal("untrusted inventory changed book")
	}
	other := newProofFixtureV2(t, false, true)
	if _, err = f.book.Authenticate(other.session); err == nil {
		t.Fatal("foreign session authority")
	}
	if _, err = f.book.Issue(other.identity(t, other.session), f.scope, f.book.recovery); err == nil {
		t.Fatal("foreign auth observation")
	}
}

func TestPreparedLocalProofV2NilZeroAndClosed(t *testing.T) {
	f := newProofFixtureV2(t, true, true)
	id := f.identity(t, f.session)
	closed := newProofFixtureV2(t, true, true).book
	closed.Close()
	for _, tc := range []struct {
		name string
		book *PreparedProofBookV2
	}{
		{"nil", nil}, {"zero", &PreparedProofBookV2{}}, {"partial", &PreparedProofBookV2{auth: f.auth, initialized: true}}, {"closed", closed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.book
			if _, err := b.Authenticate(f.session); err == nil {
				t.Fatal("unavailable authentication accepted")
			}
			if err := b.Publish(f.scope, []ProofReceiverV2{f.receiver}); err == nil {
				t.Fatal("unavailable publish accepted")
			}
			if _, err := b.Issue(id, f.scope, f.receiver); err == nil {
				t.Fatal("unavailable issue accepted")
			}
			if _, err := b.Reserve(id, f.scope, ProofEvidenceV2{}); err == nil {
				t.Fatal("unavailable reserve accepted")
			}
			b.Invalidate()
			b.Close()
			b.Close()
		})
	}
	var nilReservation *ProofReservationV2
	nilReservation.Finish(true)
	new(ProofReservationV2).Finish(false)
	(&ProofReservationV2{book: &PreparedProofBookV2{}}).Finish(true)
}

func TestPreparedLocalProofV2AuthenticationBoundaryRechecksRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprintf("account_%t", revoke), func(t *testing.T) {
			f := newProofFixtureV2(t, false, true)
			p := f.issue(t, f.book.recovery, f.session)
			var err error
			if revoke {
				err = f.auth.Revoke("alice")
			} else {
				err = f.auth.Logout(f.token)
			}
			if err != nil {
				t.Fatal(err)
			}
			// The actual action boundary reauthenticates; it must not reuse an
			// earlier ProofIdentityV2 after logout/revocation.
			id, err := f.book.Authenticate(f.session)
			if err == nil {
				t.Fatal("revoked session reauthenticated")
			}
			if _, err = f.book.Reserve(id, f.scope, ProofEvidenceV2{Recovery: p.Token}); err == nil {
				t.Fatal("failed authentication authorized reserve")
			}
		})
	}
}

func TestPreparedLocalProofV2ScopeCannotBeBorrowed(t *testing.T) {
	for _, name := range []string{"operation", "generation", "credential", "lease", "lineage", "namespace"} {
		t.Run(name, func(t *testing.T) {
			f := newProofFixtureV2(t, true, true)
			if err := f.book.Publish(f.scope, []ProofReceiverV2{f.receiver}); err != nil {
				t.Fatal(err)
			}
			e := ProofEvidenceV2{Recovery: f.issue(t, f.book.recovery, f.session).Token, Endpoints: []string{f.issue(t, f.receiver, f.session).Token}}
			in := copyValue(f.input)
			switch name {
			case "operation":
				in.Operation.ID = "v2.op.3.fixture"
				in.Namespace.Open = []string{in.Operation.ID}
			case "generation":
				in.Global.Generation++
				in.Operation.Expected++
			case "credential":
				in.Subject.CredentialRevision = strings.Repeat("b", 64)
			case "lease":
				in.Confirmation.Lease = "new-lease"
				in.Origin.Outcome.ConfirmationLease = "new-lease"
			case "lineage":
				in.Global.Lineage = "replacement"
				in.Operation.Lineage = "replacement"
				in.Origin.Lineage = "replacement"
				in.Origin.Fingerprint = proofFingerprintV2(t, *in.Origin)
			case "namespace":
				in.Namespace.ID = "v2.ns.2.fixture"
				in.Operation.Namespace = in.Namespace.ID
			}
			in.Operation.Fingerprint = proofFingerprintV2(t, in.Operation)
			scope, err := configpoc.ResolveLocalProofV2(in, f.now)
			if err != nil {
				t.Fatal("fixture", err)
			}
			if _, err = f.book.Reserve(f.identity(t, f.session), scope, e); err == nil {
				t.Fatal("borrowed evidence", name)
			}
		})
	}
}

func TestPreparedLocalProofV2AuthenticationAndDisabled(t *testing.T) {
	f := newProofFixtureV2(t, true, false)
	if err := f.book.Publish(f.scope, nil); err != nil {
		t.Fatal(err)
	}
	p := f.issue(t, f.book.recovery, f.session)
	r, err := f.book.Reserve(f.identity(t, f.session), f.scope, ProofEvidenceV2{Recovery: p.Token})
	if err != nil {
		t.Fatal("disabled recovery", err)
	}
	r.Finish(true)
	if _, err = f.book.Authenticate(adminauth.SessionBinding{}); err == nil {
		t.Fatal("fabricated session")
	}
	if _, err = f.book.Authenticate(f.login(t, "viewer")); err == nil {
		t.Fatal("viewer")
	}
	other := f.identity(t, f.login(t, "bob"))
	if _, err = f.book.Issue(other, f.scope, f.book.recovery); err == nil {
		t.Fatal("wrong subject")
	}
	if err = f.auth.Logout(f.token); err != nil {
		t.Fatal(err)
	}
	if _, err = f.book.Authenticate(f.session); err == nil {
		t.Fatal("revoked session")
	}
}

func TestPreparedLocalProofV2BoundsInvalidationAndConcurrency(t *testing.T) {
	f := newProofFixtureV2(t, false, true)
	id := f.identity(t, f.session)
	var evidence ProofEvidenceV2
	for range MaxProofs {
		evidence.Recovery = f.issue(t, f.book.recovery, f.session).Token
	}
	if _, err := f.book.Issue(id, f.scope, f.book.recovery); err == nil {
		t.Fatal("unbounded book")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	var winner *ProofReservationV2
	var mu sync.Mutex
	for range 16 {
		wg.Go(func() {
			r, err := f.book.Reserve(id, f.scope, evidence)
			if err == nil {
				wins.Add(1)
				mu.Lock()
				winner = r
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("reservation race", wins.Load())
	}
	winner.Finish(true)
	f.now = f.now.Add(ProofTTL)
	if _, err := f.book.Issue(id, f.scope, f.book.recovery); err != nil {
		t.Fatal("expired cleanup", err)
	}
	f.book.Invalidate()
	if len(f.book.entries) != 0 {
		t.Fatal("retained after invalidation")
	}
	f.book.Close()
	if _, err := f.book.Issue(id, f.scope, f.book.recovery); err == nil {
		t.Fatal("closed book")
	}
}

func TestPreparedLocalProofV2DeadlineAndReceiverNegatives(t *testing.T) {
	f := newProofFixtureV2(t, true, true)
	in := copyValue(f.input)
	deadline := f.now.Add(10 * time.Second)
	in.Confirmation.Deadline = deadline
	in.Origin.Outcome.ConfirmationDeadline = &deadline
	scope, err := configpoc.ResolveLocalProofV2(in, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.scope = scope
	if err = f.book.Publish(scope, []ProofReceiverV2{f.receiver}); err != nil {
		t.Fatal(err)
	}
	p := f.issue(t, f.receiver, f.session)
	if !p.ExpiresAt.Equal(deadline) {
		t.Fatal("deadline extended")
	}
	id := f.identity(t, f.session)
	for _, field := range []string{"run", "namespace", "activation", "endpoint", "instance", "surface"} {
		r := f.receiver
		switch field {
		case "run":
			r.Run = strings.Repeat("5", 32)
		case "namespace":
			r.Namespace++
		case "activation":
			r.ActivationHash = scope.Binding().Target
		case "endpoint":
			r.Endpoint = "forged"
		case "instance":
			r.Instance = strings.Repeat("6", 32)
		case "surface":
			r.Surface = "other"
		}
		if _, err := f.book.Issue(id, scope, r); err == nil {
			t.Fatal("forged receiver", field)
		}
	}
	if _, err := f.book.Issue(id, configpoc.LocalProofScopeV2{}, f.book.recovery); err == nil {
		t.Fatal("zero scope")
	}
}
