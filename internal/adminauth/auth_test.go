package adminauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Manager, string, *[]Event) {
	t.Helper()
	secret, err := randomSecret()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(secret))
	events := []Event{}
	m, err := New([]Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(sum[:])}}, func(e Event) error { events = append(events, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	return m, secret, &events
}
func TestLoginExpiryAndRevocation(t *testing.T) {
	m, secret, events := fixture(t)
	clock := time.Now()
	m.now = func() time.Time { return clock }
	id, token, err := m.Login("alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != "admin" || token == secret || !CheckCSRF(id, id.CSRF) || CheckCSRF(id, token) {
		t.Fatal("invalid session")
	}
	if _, err = m.Authenticate(token); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(5 * time.Minute)
	if _, err = m.Authenticate(token); !errors.Is(err, ErrDenied) {
		t.Fatal("idle session accepted")
	}
	_, token, err = m.Login("alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Revoke("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(token); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked session accepted")
	}
	for _, e := range *events {
		if e.Actor == secret || e.Actor == token {
			t.Fatal("secret logged")
		}
	}
}
func TestDeniedRateLimitedAndAuditFailure(t *testing.T) {
	m, secret, events := fixture(t)
	for i := 0; i < 4; i++ {
		if _, _, err := m.Login("alice", secret+"x"); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if _, _, err := m.Login("alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal("rate limit missing")
	}
	if len(*events) != 4 {
		t.Fatal("unexpected audit count")
	}
	m, secret, _ = fixture(t)
	m.audit = func(Event) error { return errors.New("disk full") }
	if _, _, err := m.Login("alice", secret); !errors.Is(err, ErrUnavailable) {
		t.Fatal("audit failure ignored")
	}
}
func TestLogoutAndAbsoluteExpiry(t *testing.T) {
	m, secret, _ := fixture(t)
	clock := time.Now()
	m.now = func() time.Time { return clock }
	_, token, err := m.Login("alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		clock = clock.Add(4 * time.Minute)
		_, err = m.Authenticate(token)
	}
	if !errors.Is(err, ErrDenied) {
		t.Fatal("absolute expiry ignored")
	}
	clock = clock.Add(time.Second)
	_, token, err = m.Login("alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Logout(token); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Authenticate(token); !errors.Is(err, ErrDenied) {
		t.Fatal("logout ignored")
	}
}

func TestDenialAuditBoundsAndFailureLatch(t *testing.T) {
	m, secret, events := fixture(t)
	clock := time.Now()
	m.now = func() time.Time { return clock }
	for i := 0; i < 4; i++ {
		if err := m.RecordDenied("alice", "csrf"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.RecordDenied("alice", "write"); !errors.Is(err, ErrLimited) {
		t.Fatal("unbounded denial audit")
	}
	if len(*events) != 4 {
		t.Fatal("unexpected denial count")
	}
	clock = clock.Add(time.Second)
	if err := m.RecordDenied("alice", "write"); err != nil {
		t.Fatal(err)
	}
	m.audit = func(Event) error { return errors.New("private storage path") }
	if err := m.RecordDenied("alice", "write"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("audit failure ignored")
	}
	if _, _, err := m.Login("alice", secret); !errors.Is(err, ErrUnavailable) {
		t.Fatal("audit failure did not latch closed")
	}
}
