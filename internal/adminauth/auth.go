// Package adminauth authenticates provisioned laboratory credentials and sessions.
package adminauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"time"
)

var (
	ErrDenied      = errors.New("ANDEIVA_AUTH_DENIED")
	ErrLimited     = errors.New("ANDEIVA_AUTH_RATE_LIMITED")
	ErrUnavailable = errors.New("ANDEIVA_AUTH_UNAVAILABLE")
)

type Account struct {
	Username         string `json:"username"`
	Role             string `json:"role"`
	CredentialSHA256 string `json:"credential_sha256"`
}
type Identity struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CSRF      string    `json:"csrf"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Event struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Result string    `json:"result"`
}
type session struct {
	identity Identity
	last     time.Time
}
type account struct {
	role   string
	digest [32]byte
}
type Manager struct {
	mu           sync.Mutex
	accounts     map[string]account
	sessions     map[[32]byte]session
	audit        func(Event) error
	now          func() time.Time
	window       time.Time
	attempts     int
	failed       bool
	denialWindow time.Time
	denials      int
}

var username = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// Credentials must be generated from 32 random bytes, not chosen passwords.
// Their entropy permits SHA-256 storage without introducing password hashing.
func New(accounts []Account, audit func(Event) error) (*Manager, error) {
	if len(accounts) < 1 || len(accounts) > 32 || audit == nil {
		return nil, ErrUnavailable
	}
	m := &Manager{accounts: map[string]account{}, sessions: map[[32]byte]session{}, audit: audit, now: time.Now}
	for _, a := range accounts {
		d, err := hex.DecodeString(a.CredentialSHA256)
		if err != nil || len(d) != 32 || !username.MatchString(a.Username) || a.Username == "system" || (a.Role != "admin" && a.Role != "viewer") {
			return nil, ErrUnavailable
		}
		if _, ok := m.accounts[a.Username]; ok {
			return nil, ErrUnavailable
		}
		var hash [32]byte
		copy(hash[:], d)
		m.accounts[a.Username] = account{a.Role, hash}
	}
	return m, nil
}
func randomSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (m *Manager) record(actor, action, result string) error {
	if !username.MatchString(actor) {
		actor = "unknown"
	}
	if err := m.audit(Event{m.now().UTC(), actor, action, result}); err != nil {
		m.failed = true
		return ErrUnavailable
	}
	return nil
}
func (m *Manager) Login(name, credential string) (Identity, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return Identity{}, "", ErrUnavailable
	}
	now := m.now()
	if now.Sub(m.window) >= time.Second {
		m.window = now
		m.attempts = 0
	}
	if m.attempts >= 4 {
		return Identity{}, "", ErrLimited
	}
	m.attempts++
	known, ok := m.accounts[name]
	sum := sha256.Sum256([]byte(credential))
	valid := subtle.ConstantTimeCompare(sum[:], known.digest[:]) == 1
	decoded, decodeErr := hex.DecodeString(credential)
	if !ok || !valid || decodeErr != nil || len(decoded) != 32 || credential != hex.EncodeToString(decoded) {
		if err := m.record("unknown", "login", "denied"); err != nil {
			return Identity{}, "", err
		}
		return Identity{}, "", ErrDenied
	}
	for key, s := range m.sessions {
		if !now.Before(s.identity.ExpiresAt) || now.Sub(s.last) >= 5*time.Minute {
			delete(m.sessions, key)
		}
	}
	if len(m.sessions) >= 32 {
		return Identity{}, "", ErrLimited
	}
	token, err := randomSecret()
	if err != nil {
		return Identity{}, "", ErrUnavailable
	}
	csrf, err := randomSecret()
	if err != nil {
		return Identity{}, "", ErrUnavailable
	}
	id := Identity{name, known.role, csrf, now.Add(30 * time.Minute).UTC()}
	if err = m.record(name, "login", "ok"); err != nil {
		return Identity{}, "", err
	}
	m.sessions[sha256.Sum256([]byte(token))] = session{id, now}
	return id, token, nil
}
func (m *Manager) Authenticate(token string) (Identity, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return Identity{}, ErrUnavailable
	}
	if len(token) != 64 {
		return Identity{}, ErrDenied
	}
	key := sha256.Sum256([]byte(token))
	s, ok := m.sessions[key]
	now := m.now()
	if !ok {
		return Identity{}, ErrDenied
	}
	if !now.Before(s.identity.ExpiresAt) || now.Sub(s.last) >= 5*time.Minute {
		delete(m.sessions, key)
		return Identity{}, ErrDenied
	}
	s.last = now
	m.sessions[key] = s
	return s.identity, nil
}
func (m *Manager) Logout(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sha256.Sum256([]byte(token))
	s, ok := m.sessions[key]
	delete(m.sessions, key)
	if !ok {
		return ErrDenied
	}
	return m.record(s.identity.Username, "logout", "ok")
}
func (m *Manager) Revoke(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, s := range m.sessions {
		if s.identity.Username == name {
			delete(m.sessions, key)
		}
	}
	delete(m.accounts, name)
	return m.record(name, "revoke", "ok")
}

func CheckCSRF(identity Identity, value string) bool {
	return len(value) == 64 && subtle.ConstantTimeCompare([]byte(identity.CSRF), []byte(value)) == 1
}

// RecordDenied bounds unauthenticated audit pressure. Exhaustion rejects work;
// persistent audit failure latches all authentication closed.
func (m *Manager) RecordDenied(actor, action string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failed {
		return ErrUnavailable
	}
	if action != "write" && action != "csrf" && action != "origin" {
		return ErrDenied
	}
	now := m.now()
	if now.Sub(m.denialWindow) >= time.Second {
		m.denialWindow = now
		m.denials = 0
	}
	if m.denials >= 4 {
		return ErrLimited
	}
	m.denials++
	return m.record(actor, action, "denied")
}
