package localadmin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

// ProofReceiverV2 is registered by a trusted listener factory, never decoded
// from a caller or proxy header. Instance must change when a listener is replaced.
type ProofReceiverV2 struct {
	Run, Instance, Endpoint, ActivationHash string
	Namespace                               uint64
	Surface                                 configpoc.Surface
}

// ProofEvidenceV2 is an ephemeral internal argument, not a durable request DTO.
type ProofEvidenceV2 struct {
	Recovery  string   `json:"-"`
	Endpoints []string `json:"-"`
}

func (ProofEvidenceV2) String() string   { return "<local proof evidence>" }
func (ProofEvidenceV2) GoString() string { return "<local proof evidence>" }

type proofEntryV2 struct {
	scope    configpoc.LocalProofBindingV2
	session  adminauth.SessionBinding
	receiver ProofReceiverV2
	expires  time.Time
	reserved bool
}

type activeProofV2 struct {
	lineage, origin, lease, target, local, subject, revision string
	generation                                               uint64
	deadline                                                 time.Time
}

// PreparedProofBookV2 is deliberately not connected to ServiceV2 or a receiver.
// It reuses v1 proof limits/profile helpers, not a second transaction coordinator.
// F2 must revalidate scopes and reserve under the same coordinator lock. Auth
// verification must finish BEFORE taking that lock; see Authenticate below.
type PreparedProofBookV2 struct {
	mu          sync.Mutex
	auth        *adminauth.Manager
	run         string
	recovery    ProofReceiverV2
	inventory   []localpolicy.Interface
	entries     map[[32]byte]proofEntryV2
	active      activeProofV2
	receivers   map[string]ProofReceiverV2
	now         func() time.Time
	closed      bool
	initialized bool
}

// ProofIdentityV2 is a short-lived auth observation, not a lasting capability.
// No exported fields permit creation of a verified identity by a transport DTO.
type ProofIdentityV2 struct {
	book    *PreparedProofBookV2
	session adminauth.SessionBinding
	subject adminauth.VerifiedSubject
}

func (ProofIdentityV2) String() string   { return "<verified local proof identity>" }
func (ProofIdentityV2) GoString() string { return "<verified local proof identity>" }

func NewPreparedProofBookV2(auth *adminauth.Manager, recovery ProofReceiverV2, inventory []localpolicy.Interface) (*PreparedProofBookV2, error) {
	if auth == nil || !validHex(recovery.Run, 16) || !validHex(recovery.Instance, 16) || !identifier.MatchString(recovery.Endpoint) || recovery.ActivationHash != "" || recovery.Namespace == 0 || !proofSurfaceV2(recovery.Surface) || len(inventory) == 0 || len(inventory) > 2 {
		return nil, configpoc.ErrInvalid
	}
	canonical, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: localpolicy.SchemaVersion, Interfaces: inventory})
	if err != nil {
		return nil, configpoc.ErrInvalid
	}
	return &PreparedProofBookV2{auth: auth, run: recovery.Run, recovery: recovery, inventory: canonical.Config.Interfaces, entries: make(map[[32]byte]proofEntryV2), receivers: make(map[string]ProofReceiverV2), now: time.Now, initialized: true}, nil
}

func (b *PreparedProofBookV2) ready() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.initialized && !b.closed && b.auth != nil && b.now != nil && b.entries != nil && b.receivers != nil && len(b.inventory) != 0
}

func proofSurfaceV2(s configpoc.Surface) bool {
	return s == configpoc.Web || s == configpoc.CLI || s == configpoc.API
}

// Web and API may use the same authenticated HTTPS listener. Surface is a
// validated transport label, not an independent listener identity or authority.
func sameProofReceiverV2(a, b ProofReceiverV2) bool {
	a.Surface, b.Surface = "", ""
	return a == b
}

// Authenticate uses the existing session authority. The result is only for the
// immediately following coordinator-locked action, never a cache or IPC payload.
func (b *PreparedProofBookV2) Authenticate(session adminauth.SessionBinding) (ProofIdentityV2, error) {
	if !b.ready() {
		return ProofIdentityV2{}, configpoc.ErrDenied
	}
	subject, err := b.auth.VerifySession(session)
	if err != nil || subject.Role() != string(configpoc.RoleAdmin) {
		if err == adminauth.ErrUnavailable {
			return ProofIdentityV2{}, configpoc.ErrRecovery
		}
		return ProofIdentityV2{}, configpoc.ErrDenied
	}
	return ProofIdentityV2{book: b, session: session, subject: subject}, nil
}

func (b *PreparedProofBookV2) validIdentity(identity ProofIdentityV2, s configpoc.LocalProofBindingV2) bool {
	return identity.book == b && identity.subject.SubjectID() == s.Subject && identity.subject.Login() == s.Login && identity.subject.CredentialRevision() == s.CredentialRevision
}

func (b *PreparedProofBookV2) validate(scope configpoc.LocalProofScopeV2) bool {
	return scope.Valid() && validateProfile(scope.Target().Config, b.inventory) == nil
}

func activeScopeV2(scope configpoc.LocalProofBindingV2) activeProofV2 {
	return activeProofV2{scope.Lineage, scope.Origin, scope.Lease, scope.Target, scope.LocalTarget, scope.Subject, scope.CredentialRevision, scope.Generation, scope.Deadline}
}

func sameActiveProofV2(a, b activeProofV2) bool {
	equal := a.deadline.Equal(b.deadline)
	a.deadline, b.deadline = time.Time{}, time.Time{}
	return equal && a == b
}

func sameProofBindingV2(a, b configpoc.LocalProofBindingV2) bool {
	equal := a.Deadline.Equal(b.Deadline) && a.ExecuteBefore.Equal(b.ExecuteBefore)
	// Preserve exact comparison of every other field, including future fields.
	a.Deadline, b.Deadline = time.Time{}, time.Time{}
	a.ExecuteBefore, b.ExecuteBefore = time.Time{}, time.Time{}
	return equal && a == b
}

// Publish accepts only a verified pending projection and its actual receiver
// instances from the trusted caller. It does not itself prove kernel/listener
// state. No production caller exists until F2 supplies that barrier under lock.
func (b *PreparedProofBookV2) Publish(scope configpoc.LocalProofScopeV2, receivers []ProofReceiverV2) error {
	if !b.ready() {
		return configpoc.ErrRecovery
	}
	if !b.validate(scope) || scope.Binding().Purpose != "confirm" {
		return configpoc.ErrInvalid
	}
	listeners := expectedListeners(scope.Target().Config)
	if len(receivers) != len(listeners) || len(receivers) > 8 {
		return configpoc.ErrInvalid
	}
	expected := make(map[string]bool, len(listeners))
	for _, l := range listeners {
		expected[BindingEndpointID(l)] = true
	}
	next := make(map[string]ProofReceiverV2, len(receivers))
	for _, r := range receivers {
		if !expected[r.Endpoint] || r.Run != b.run || !validHex(r.Instance, 16) || r.Namespace == 0 || r.ActivationHash != scope.Binding().LocalTarget || !proofSurfaceV2(r.Surface) {
			return configpoc.ErrInvalid
		}
		if _, duplicate := next[r.Endpoint]; duplicate {
			return configpoc.ErrInvalid
		}
		next[r.Endpoint] = r
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return configpoc.ErrRecovery
	}
	if !b.now().Before(scope.Binding().Deadline) {
		return configpoc.ErrExpired
	}
	active := activeScopeV2(scope.Binding())
	for key, entry := range b.entries {
		if !sameProofReceiverV2(entry.receiver, b.recovery) && (!sameActiveProofV2(b.active, active) || !sameProofReceiverV2(next[entry.receiver.Endpoint], entry.receiver)) {
			delete(b.entries, key)
		}
	}
	b.active, b.receivers = active, next
	return nil
}

func (b *PreparedProofBookV2) receiverValid(r ProofReceiverV2, scope configpoc.LocalProofBindingV2) bool {
	if !proofSurfaceV2(r.Surface) {
		return false
	}
	if sameProofReceiverV2(r, b.recovery) {
		return true
	}
	return scope.Purpose == "confirm" && sameActiveProofV2(b.active, activeScopeV2(scope)) && sameProofReceiverV2(b.receivers[r.Endpoint], r) && r.Run == b.run && r.ActivationHash == scope.LocalTarget && validBindingID(r.Endpoint)
}

// Issue requires a freshly authenticated identity and the current locked scope.
// It does not call auth/coordinator/helper while holding the proof mutex.
func (b *PreparedProofBookV2) Issue(identity ProofIdentityV2, scope configpoc.LocalProofScopeV2, receiver ProofReceiverV2) (Proof, error) {
	if !b.ready() {
		return Proof{}, configpoc.ErrRecovery
	}
	if !b.validate(scope) || !b.validIdentity(identity, scope.Binding()) {
		return Proof{}, configpoc.ErrDenied
	}
	s := scope.Binding()
	if s.Kind != configpoc.OpCommit && s.Kind != configpoc.OpRollback && s.Kind != configpoc.OpSave && s.Kind != configpoc.OpConfirm {
		return Proof{}, configpoc.ErrInvalid
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Proof{}, configpoc.ErrRecovery
	}
	now := b.now()
	if !now.Before(s.ExecuteBefore) || !b.receiverValid(receiver, s) || (s.Purpose == "confirm" && !now.Before(s.Deadline)) {
		return Proof{}, configpoc.ErrDenied
	}
	for key, e := range b.entries {
		if !e.reserved && !now.Before(e.expires) {
			delete(b.entries, key)
		}
	}
	if len(b.entries) >= MaxProofs {
		return Proof{}, configpoc.ErrStorage
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Proof{}, configpoc.ErrStorage
	}
	token := hex.EncodeToString(nonce[:])
	ttl := ProofTTL
	if !sameProofReceiverV2(receiver, b.recovery) {
		ttl = EndpointProofTTL
	}
	expires := now.Add(ttl)
	if s.ExecuteBefore.Before(expires) {
		expires = s.ExecuteBefore
	}
	if s.Purpose == "confirm" && s.Deadline.Before(expires) {
		expires = s.Deadline
	}
	b.entries[sha256.Sum256([]byte(token))] = proofEntryV2{scope: s, session: identity.session, receiver: receiver, expires: expires, reserved: false}
	return Proof{Token: token, ExpiresAt: expires.UTC()}, nil
}

type ProofReservationV2 struct {
	book *PreparedProofBookV2
	keys [][32]byte
	done bool
}

// Reserve is atomic for the complete proof set. The caller must already have
// revalidated the current registry, operation and mapping under store.mu.
func (b *PreparedProofBookV2) Reserve(identity ProofIdentityV2, scope configpoc.LocalProofScopeV2, evidence ProofEvidenceV2) (*ProofReservationV2, error) {
	if !b.ready() {
		return nil, configpoc.ErrRecovery
	}
	if !b.validate(scope) || !b.validIdentity(identity, scope.Binding()) {
		return nil, configpoc.ErrDenied
	}
	s := scope.Binding()
	if s.Kind != configpoc.OpCommit && s.Kind != configpoc.OpRollback && s.Kind != configpoc.OpSave && s.Kind != configpoc.OpConfirm {
		return nil, configpoc.ErrInvalid
	}
	listeners := expectedListeners(scope.Target().Config)
	if s.Purpose != "confirm" {
		listeners = nil
	}
	if len(evidence.Endpoints) != len(listeners) || len(evidence.Endpoints) > 8 {
		return nil, configpoc.ErrDenied
	}
	needs := make(map[string]bool, len(listeners)+1)
	needs[b.recovery.Endpoint] = true
	for _, l := range listeners {
		needs[BindingEndpointID(l)] = true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, configpoc.ErrRecovery
	}
	now := b.now()
	if !now.Before(s.ExecuteBefore) || (s.Purpose == "confirm" && !now.Before(s.Deadline)) {
		return nil, configpoc.ErrDenied
	}
	keys := make([][32]byte, 0, 1+len(evidence.Endpoints))
	for i, token := range append([]string{evidence.Recovery}, evidence.Endpoints...) {
		if !validHex(token, 32) {
			return nil, configpoc.ErrDenied
		}
		key := sha256.Sum256([]byte(token))
		entry, ok := b.entries[key]
		if !ok || entry.reserved || !now.Before(entry.expires) || !sameProofBindingV2(entry.scope, s) || !needs[entry.receiver.Endpoint] || !b.receiverValid(entry.receiver, s) ||
			(i == 0 && (!sameProofReceiverV2(entry.receiver, b.recovery) || entry.session != identity.session)) || (i > 0 && sameProofReceiverV2(entry.receiver, b.recovery)) {
			return nil, configpoc.ErrDenied
		}
		delete(needs, entry.receiver.Endpoint)
		keys = append(keys, key)
	}
	if len(needs) != 0 {
		return nil, configpoc.ErrDenied
	}
	for _, key := range keys {
		e := b.entries[key]
		e.reserved = true
		b.entries[key] = e
	}
	return &ProofReservationV2{book: b, keys: keys}, nil
}

// Finish consumes once after durable admission (also on uncertain publication),
// or releases only when the coordinator proves no admitted effects. It performs
// no durable writes. A second call cannot release another reservation.
func (r *ProofReservationV2) Finish(consume bool) {
	if r == nil || r.book == nil {
		return
	}
	b := r.book
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	for _, key := range r.keys {
		if consume {
			delete(b.entries, key)
		} else if e, ok := b.entries[key]; ok {
			e.reserved = false
			b.entries[key] = e
		}
	}
}

func (b *PreparedProofBookV2) Invalidate() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.entries)
	clear(b.receivers)
	b.active = activeProofV2{}
}

func (b *PreparedProofBookV2) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	clear(b.entries)
	clear(b.receivers)
	b.active = activeProofV2{}
}
