package adminauth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// SessionBinding is a process-local reference to a real authenticated session.
// Its zero value grants nothing. It must not be persisted or sent to clients.
type SessionBinding struct {
	issuer *Manager
	key    [32]byte
}

func (SessionBinding) String() string   { return "<administrative session binding>" }
func (SessionBinding) GoString() string { return "<administrative session binding>" }

// VerifiedSubject is a short-lived authentication observation, not a capability.
// The configuration registry remains authoritative for subject ownership.
type VerifiedSubject struct {
	subject, login, role, revision string
}

func (VerifiedSubject) String() string   { return "<verified administrative subject>" }
func (VerifiedSubject) GoString() string { return "<verified administrative subject>" }

func (s VerifiedSubject) SubjectID() string          { return s.subject }
func (s VerifiedSubject) Login() string              { return s.login }
func (s VerifiedSubject) Role() string               { return s.role }
func (s VerifiedSubject) CredentialRevision() string { return s.revision }

func validSubjectBinding(subject, revision string) bool {
	if subject == "" && revision == "" {
		return true
	}
	if subject == "" || len(subject) > 128 || len(revision) != 64 || strings.IndexAny(revision, "ABCDEF") >= 0 {
		return false
	}
	for _, c := range subject {
		if c < 33 || c > 126 {
			return false
		}
	}
	_, err := hex.DecodeString(revision)
	return err == nil
}

// ResolveSession accepts only the actual session token verified by this manager.
// Caller-supplied Identity values cannot construct a binding.
func (m *Manager) ResolveSession(token string) (SessionBinding, error) {
	if m == nil || len(token) != 64 {
		return SessionBinding{}, ErrDenied
	}
	b := SessionBinding{issuer: m, key: sha256.Sum256([]byte(token))}
	if _, err := b.Verify(); err != nil {
		return SessionBinding{}, err
	}
	return b, nil
}

// VerifySession also pins the session's issuer to the transport's configured
// authority; a binding minted by another Manager is not interchangeable.
func (m *Manager) VerifySession(binding SessionBinding) (VerifiedSubject, error) {
	if m == nil || binding.issuer != m {
		return VerifiedSubject{}, ErrDenied
	}
	return binding.Verify()
}

// Verify must be called for every configuration request, before its store lock.
// Logout, idle/absolute expiry, account revocation or mirror rotation invalidate
// retained bindings. No session lock is held while the caller accesses storage.
func (b SessionBinding) Verify() (VerifiedSubject, error) {
	if b.issuer == nil {
		return VerifiedSubject{}, ErrDenied
	}
	m := b.issuer
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return VerifiedSubject{}, ErrUnavailable
	}
	s, ok := m.sessions[b.key]
	now := m.now()
	if !ok {
		return VerifiedSubject{}, ErrDenied
	}
	a, exists := m.accounts[s.identity.Username]
	if !exists || !now.Before(s.identity.ExpiresAt) || now.Sub(s.last) >= 5*time.Minute ||
		a.subjectID == "" || a.subjectID != s.identity.SubjectID || a.role != s.identity.Role ||
		a.credentialRevision != s.credentialRevision {
		delete(m.sessions, b.key)
		return VerifiedSubject{}, ErrDenied
	}
	s.last = now
	m.sessions[b.key] = s
	return VerifiedSubject{subject: a.subjectID, login: s.identity.Username, role: a.role, revision: a.credentialRevision}, nil
}
