package localadmin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

const ProofTTL = 20 * time.Second
const EndpointProofTTL = 60 * time.Second
const MaxProofs = 256

type attestation struct {
	runID    string
	context  Context
	request  ProofRequest
	expires  time.Time
	reserved bool
}

type proofBook struct {
	mu      sync.Mutex
	runID   string
	entries map[[32]byte]attestation
	now     func() time.Time
	closed  bool
	pending *pendingProof
}

type pendingProof struct {
	request   ProofRequest
	owner     string
	deadline  time.Time
	endpoints map[string]bool
}

// publish is called only after the coordinator has returned a verified pending
// revision. Proof emission itself never calls back into the coordinator lock.
func (b *proofBook) publish(snapshot configpoc.Snapshot, recovery string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var next *pendingProof
	if snapshot.Pending != nil && !snapshot.RecoveryRequired {
		next = &pendingProof{request: ProofRequest{Generation: snapshot.Generation, Target: snapshot.Running.Hash, Lease: snapshot.Pending.Lease}, owner: snapshot.Pending.Owner, deadline: snapshot.Pending.Deadline, endpoints: map[string]bool{}}
		for _, listener := range expectedListeners(snapshot.Running.Config) {
			next.endpoints[BindingEndpointID(listener)] = true
		}
	}
	if next == nil || b.pending == nil || next.request != b.pending.request || next.owner != b.pending.owner {
		for key, entry := range b.entries {
			if entry.context.EndpointID != recovery {
				delete(b.entries, key)
			}
		}
	}
	b.pending = next
}

// IssueProof must only be called after actual endpoint authentication. Its
// separate mutex and lack of coordinator calls permit probes during activation.
func (s *Service) IssueProof(c Context, request ProofRequest) (Proof, error) {
	if !validContext(c) || c.Principal.Role != configpoc.RoleAdmin {
		return Proof{}, configpoc.ErrDenied
	}
	if request.Generation == 0 || !validHex(request.Target, 32) || !identifier.MatchString(request.Lease) ||
		(c.EndpointID != s.options.RecoveryEndpointID && !validBindingID(c.EndpointID)) {
		return Proof{}, configpoc.ErrInvalid
	}
	b := &s.proofs
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return Proof{}, configpoc.ErrRecovery
	}
	now := b.now()
	if c.EndpointID != s.options.RecoveryEndpointID && (b.pending == nil || b.pending.request != request || b.pending.owner != c.Principal.ID || !now.Before(b.pending.deadline) || !b.pending.endpoints[c.EndpointID] || c.ActivationHash != request.Target) {
		return Proof{}, configpoc.ErrDenied
	}
	for key, entry := range b.entries {
		if !entry.reserved && !now.Before(entry.expires) {
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
	if c.EndpointID != s.options.RecoveryEndpointID {
		ttl = EndpointProofTTL
	}
	expires := now.Add(ttl)
	if c.EndpointID != s.options.RecoveryEndpointID && b.pending.deadline.Before(expires) {
		expires = b.pending.deadline
	}
	b.entries[sha256.Sum256([]byte(token))] = attestation{runID: s.options.RunID, context: c, request: request, expires: expires}
	return Proof{Token: token, ExpiresAt: expires.UTC()}, nil
}

type proofNeed struct {
	token       string
	endpoint    string
	sameSession bool
}

// reserve checks freshness at admission, before journal I/O. Reserved tokens
// remain valid for this one admitted operation and cannot be issued or reused
// for another request while activation is in progress.
func (b *proofBook) reserve(c Context, request ProofRequest, needs []proofNeed) ([][32]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, configpoc.ErrRecovery
	}
	keys := make([][32]byte, 0, len(needs))
	seen := map[[32]byte]bool{}
	now := b.now()
	for _, need := range needs {
		if !validHex(need.token, 32) {
			return nil, configpoc.ErrDenied
		}
		key := sha256.Sum256([]byte(need.token))
		entry, ok := b.entries[key]
		if !ok || seen[key] || entry.runID != b.runID || entry.reserved || !now.Before(entry.expires) || entry.request != request ||
			entry.context.Principal.ID != c.Principal.ID || entry.context.EndpointID != need.endpoint ||
			(need.sameSession && entry.context.SessionHash != c.SessionHash) ||
			(!need.sameSession && (entry.context.ActivationHash != request.Target || b.pending == nil || b.pending.request != request || !now.Before(b.pending.deadline))) {
			return nil, configpoc.ErrDenied
		}
		seen[key] = true
		keys = append(keys, key)
	}
	for _, key := range keys {
		entry := b.entries[key]
		entry.reserved = true
		b.entries[key] = entry
	}
	return keys, nil
}

func (b *proofBook) finish(keys [][32]byte, consume bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, key := range keys {
		if consume {
			delete(b.entries, key)
		} else if entry, ok := b.entries[key]; ok {
			entry.reserved = false
			b.entries[key] = entry
		}
	}
}

func (b *proofBook) endpoint(token string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.entries[sha256.Sum256([]byte(token))].context.EndpointID
}
