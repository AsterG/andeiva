package adminauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func subjectFixture(t *testing.T, subject, revision string) (*Manager, string) {
	t.Helper()
	credential, err := randomSecret()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(credential))
	m, err := New([]Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: subject, CredentialRevision: revision}}, func(Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := m.Login("alice", credential)
	if err != nil {
		t.Fatal(err)
	}
	return m, token
}

func TestSubjectBindingProvisioningAndLegacy(t *testing.T) {
	for _, account := range []Account{
		{SubjectID: "subject"}, {CredentialRevision: strings.Repeat("a", 64)},
		{SubjectID: "subject", CredentialRevision: strings.Repeat("A", 64)},
		{SubjectID: "subject\n", CredentialRevision: strings.Repeat("a", 64)},
	} {
		account.Username, account.Role, account.CredentialSHA256 = "alice", "admin", strings.Repeat("0", 64)
		if _, err := New([]Account{account}, func(Event) error { return nil }); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid subject binding accepted")
		}
	}
	m, token := subjectFixture(t, "", "")
	if _, err := m.Authenticate(token); err != nil {
		t.Fatal("legacy authentication broken", err)
	}
	if _, err := m.ResolveSession(token); !errors.Is(err, ErrDenied) {
		t.Fatal("legacy session became v2 authority")
	}
	if _, err := m.Authenticate(token); err != nil {
		t.Fatal("rejected v2 binding revoked legacy authentication", err)
	}
	if _, err := (SessionBinding{}).Verify(); !errors.Is(err, ErrDenied) {
		t.Fatal("zero binding accepted")
	}
}

func TestSubjectBindingLegacyRejectionDoesNotExtendSession(t *testing.T) {
	m, token := subjectFixture(t, "", "")
	key := sha256.Sum256([]byte(token))
	last := m.sessions[key].last
	m.now = func() time.Time { return last.Add(4 * time.Minute) }
	if _, err := m.ResolveSession(token); !errors.Is(err, ErrDenied) {
		t.Fatal("legacy session acquired v2 authority")
	}
	if s, exists := m.sessions[key]; !exists || !s.last.Equal(last) {
		t.Fatal("rejected binding changed legacy session lifetime")
	}
	m.now = func() time.Time { return last.Add(5 * time.Minute) }
	if _, err := m.Authenticate(token); !errors.Is(err, ErrDenied) {
		t.Fatal("rejected v2 binding extended idle lifetime")
	}
}

func TestSubjectBindingLifetimeIssuerAndConfidentiality(t *testing.T) {
	for _, end := range []string{"logout", "revoke", "idle", "absolute", "rotation", "recreated", "role"} {
		t.Run(end, func(t *testing.T) {
			m, token := subjectFixture(t, "server-issued-subject", strings.Repeat("a", 64))
			binding, err := m.ResolveSession(token)
			if err != nil {
				t.Fatal(err)
			}
			observed, err := m.VerifySession(binding)
			if err != nil || observed.SubjectID() != "server-issued-subject" || observed.Login() != "alice" || observed.Role() != "admin" || observed.CredentialRevision() != strings.Repeat("a", 64) {
				t.Fatal("binding mismatch", err)
			}
			other, _ := subjectFixture(t, "server-issued-subject", strings.Repeat("a", 64))
			if _, err := other.VerifySession(binding); !errors.Is(err, ErrDenied) {
				t.Fatal("foreign issuer accepted")
			}
			for _, value := range []any{binding, observed} {
				data, err := json.Marshal(value)
				if err != nil || string(data) != "{}" {
					t.Fatal("opaque authentication material serialized")
				}
				if strings.Contains(fmt.Sprintf("%+v %#v", value, value), strings.Repeat("a", 64)) || strings.Contains(fmt.Sprintf("%+v %#v", value, value), token) {
					t.Fatal("authentication material in formatting")
				}
			}
			switch end {
			case "logout":
				err = m.Logout(token)
			case "revoke":
				err = m.Revoke("alice")
			case "idle":
				now := m.now().Add(5 * time.Minute)
				m.now = func() time.Time { return now }
			case "absolute":
				now := m.now().Add(30 * time.Minute)
				m.now = func() time.Time { return now }
			default:
				m.mu.Lock()
				a := m.accounts["alice"]
				if end == "rotation" {
					a.credentialRevision = strings.Repeat("b", 64)
				}
				if end == "recreated" {
					a.subjectID = "another-server-issued-subject"
				}
				if end == "role" {
					a.role = "viewer"
				}
				m.accounts["alice"] = a
				m.mu.Unlock()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.VerifySession(binding); !errors.Is(err, ErrDenied) {
				t.Fatal("stale binding accepted", err)
			}
		})
	}
}

func BenchmarkSessionBindingVerify(b *testing.B) {
	credential, err := randomSecret()
	if err != nil {
		b.Fatal(err)
	}
	digest := sha256.Sum256([]byte(credential))
	m, err := New([]Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: "issued-subject", CredentialRevision: strings.Repeat("a", 64)}}, func(Event) error { return nil })
	if err != nil {
		b.Fatal(err)
	}
	_, token, err := m.Login("alice", credential)
	if err != nil {
		b.Fatal(err)
	}
	binding, err := m.ResolveSession(token)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := m.VerifySession(binding); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSubjectBindingConcurrentRevoke(t *testing.T) {
	m, token := subjectFixture(t, "server-issued-subject", strings.Repeat("a", 64))
	binding, err := m.ResolveSession(token)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 20 {
				if _, err := m.VerifySession(binding); err != nil && !errors.Is(err, ErrDenied) {
					t.Errorf("verify: %v", err)
				}
			}
		})
	}
	if err := m.Revoke("alice"); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := m.VerifySession(binding); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked binding survived")
	}
}
