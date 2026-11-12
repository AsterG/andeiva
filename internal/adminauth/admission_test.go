package adminauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func frozenManager(t *testing.T) (*Manager, string, *[]Event, *time.Time) {
	t.Helper()
	m, secret, events := fixture(t)
	clock := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	return m, secret, events, &clock
}

func originCount(m *Manager) int {
	count := 0
	for _, entry := range m.admission.origins {
		if entry.source.IsValid() {
			count++
		}
	}
	return count
}

func TestLoginOriginFloodDoesNotConsumeVerifiedBudget(t *testing.T) {
	m, secret, events, _ := frozenManager(t)
	a, b := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	for i := 0; i < 10_000; i++ {
		_, _, err := m.LoginFrom(a, "alice", "invalid")
		want := ErrLimited
		if i < loginAttemptsPerSecond {
			want = ErrDenied
		}
		if !errors.Is(err, want) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	for _, source := range []netip.Addr{b, a} {
		if _, _, err := m.LoginFrom(source, "alice", secret); err != nil {
			t.Fatalf("verified login blocked by anonymous attempts: %v", err)
		}
	}
	if len(*events) != 6 || len(m.sessions) != 2 {
		t.Fatal("anonymous audit pressure or verified session count changed")
	}
}

func TestAnonymousGlobalBudgetAndLegacyEntryPointShareAllowance(t *testing.T) {
	m, secret, events, _ := frozenManager(t)
	for i := 0; i < 100; i++ {
		source := netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 1)})
		var err error
		if i%2 == 0 {
			_, _, err = m.Login("alice", "invalid")
		} else {
			_, _, err = m.LoginFrom(source, "alice", "invalid")
		}
		want := ErrLimited
		if i < loginAttemptsPerSecond {
			want = ErrDenied
		}
		if !errors.Is(err, want) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if len(*events) != loginAttemptsPerSecond {
		t.Fatal("legacy entry point or origin count multiplied anonymous audit writes")
	}
	if _, _, err := m.Login("alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal("legacy allowance changed")
	}
	if _, _, err := m.LoginFrom(netip.MustParseAddr("198.18.1.1"), "alice", secret); err != nil {
		t.Fatal("legacy attempts consumed the verified network allowance", err)
	}
}

func TestVerifiedBudgetIncludesLegacyCredentialSuccess(t *testing.T) {
	m, secret, events, clock := frozenManager(t)
	source := netip.MustParseAddr("198.18.0.1")
	if _, _, err := m.Login("alice", secret); err != nil {
		t.Fatal("legacy credential rejected", err)
	}
	for i := 1; i < loginAttemptsPerSecond; i++ {
		if _, _, err := m.LoginFrom(source, "alice", secret); err != nil {
			t.Fatal("shared verified allowance exhausted early", err)
		}
	}
	if _, _, err := m.LoginFrom(source, "alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal("legacy success did not consume the shared verified allowance", err)
	}
	if _, _, err := m.Login("alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal("legacy entry point created another verified allowance", err)
	}
	if len(m.sessions) != loginAttemptsPerSecond || len(*events) != loginAttemptsPerSecond {
		t.Fatal("limited login created a session or audit event")
	}
	*clock = clock.Add(time.Second)
	for i := 0; i < loginAttemptsPerSecond; i++ {
		if _, _, err := m.Login("alice", "invalid"); !errors.Is(err, ErrDenied) {
			t.Fatal("anonymous legacy attempt was not denied", err)
		}
	}
	for i := 0; i < loginAttemptsPerSecond; i++ {
		if _, _, err := m.LoginFrom(source, "alice", secret); err != nil {
			t.Fatal("invalid legacy credentials consumed verified allowance", err)
		}
	}
	if _, _, err := m.LoginFrom(source, "alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal("refilled verified allowance exceeded", err)
	}
	if len(m.sessions) != 2*loginAttemptsPerSecond || len(*events) != 3*loginAttemptsPerSecond {
		t.Fatal("unexpected session or audit counts across admission windows")
	}
}

func TestLoginOriginNormalizationAndIPv6(t *testing.T) {
	m, _, _, _ := frozenManager(t)
	for _, source := range []netip.Addr{netip.MustParseAddr("::ffff:198.18.0.1"), netip.MustParseAddr("198.18.0.1")} {
		if _, _, err := m.LoginFrom(source, "alice", "invalid"); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if originCount(m) != 1 || m.admission.origins[0].source != netip.MustParseAddr("198.18.0.1") || m.admission.origins[0].budget.attempts != 2 {
		t.Fatal("IPv4-mapped source has a different budget")
	}
	for _, source := range []netip.Addr{netip.MustParseAddr("fd42::1"), netip.MustParseAddr("fd42::2")} {
		if _, _, err := m.LoginFrom(source, "alice", "invalid"); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if originCount(m) != 3 {
		t.Fatal("distinct IPv6 origins were combined")
	}
}

func TestOriginWindowCannotBeResetByGlobalRefill(t *testing.T) {
	m, _, events, clock := frozenManager(t)
	base := *clock
	a, b := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("198.18.0.2")
	if _, _, err := m.LoginFrom(b, "alice", "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	*clock = base.Add(900 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if _, _, err := m.LoginFrom(a, "alice", "invalid"); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	*clock = base.Add(time.Second)
	if _, _, err := m.LoginFrom(a, "alice", "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	*clock = base.Add(1100 * time.Millisecond)
	if _, _, err := m.LoginFrom(a, "alice", "invalid"); !errors.Is(err, ErrLimited) {
		t.Fatal("global refill reset the origin's later window")
	}
	if _, _, err := m.LoginFrom(b, "alice", "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal("one origin exhausted another origin's replenished allowance", err)
	}
	if len(*events) != 6 {
		t.Fatal("unexpected admitted denial audit count")
	}
}

func TestLoginInvalidSourcesCannotAuthenticate(t *testing.T) {
	m, secret, events, _ := frozenManager(t)
	sources := []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"), netip.MustParseAddr("::ffff:0.0.0.0"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("ff02::1"), netip.MustParseAddr("::ffff:224.0.0.1"), netip.MustParseAddr("fe80::1%src0")}
	for _, source := range sources {
		if _, _, err := m.LoginFrom(source, "alice", secret); !errors.Is(err, ErrDenied) {
			t.Fatalf("invalid source accepted: %v", source)
		}
	}
	if len(*events) != 0 || len(m.sessions) != 0 || originCount(m) != 0 {
		t.Fatal("invalid source reached authentication state")
	}
}

func TestOriginTableFullStillAllowsVerifiedLoginAndExpiresLazily(t *testing.T) {
	m, secret, events, clock := frozenManager(t)
	base := *clock
	for i := 0; i < loginOriginSlots; i++ {
		*clock = base.Add(time.Duration(i/loginAttemptsPerSecond) * time.Second)
		source := netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 1)})
		if _, _, err := m.LoginFrom(source, "alice", "invalid"); !errors.Is(err, ErrDenied) {
			t.Fatalf("origin %d: %v", i, err)
		}
	}
	*clock = base.Add(32 * time.Second)
	if _, _, err := m.LoginFrom(netip.MustParseAddr("198.19.1.1"), "alice", "invalid"); !errors.Is(err, ErrLimited) {
		t.Fatal("full table evicted an active origin")
	}
	if originCount(m) != loginOriginSlots || len(*events) != loginOriginSlots {
		t.Fatal("origin table or audit is not bounded")
	}
	if _, _, err := m.LoginFrom(netip.MustParseAddr("198.19.1.1"), "alice", secret); err != nil {
		t.Fatal("full anonymous table blocked a verified login", err)
	}
	*clock = base.Add(2 * time.Minute)
	if _, _, err := m.LoginFrom(netip.MustParseAddr("198.19.1.1"), "alice", "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal("expired slots are not reusable", err)
	}
	if originCount(m) != 1 {
		t.Fatal("lazy expiry retained old origin entries")
	}
	if size := unsafe.Sizeof(loginAdmission{}); size > 16*1024 {
		t.Fatalf("admission state exceeds its memory budget: %d", size)
	} else {
		t.Logf("fixed admission state: %d bytes", size)
	}
}

func TestAdmissionClockRollbackDoesNotRefillOrExpire(t *testing.T) {
	m, secret, _, clock := frozenManager(t)
	base := *clock
	source := netip.MustParseAddr("198.18.0.1")
	for i := 0; i < loginAttemptsPerSecond; i++ {
		if _, _, err := m.LoginFrom(source, "alice", "invalid"); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
		if _, _, err := m.LoginFrom(source, "alice", secret); err != nil {
			t.Fatal(err)
		}
	}
	*clock = base.Add(-2 * time.Minute)
	if _, _, err := m.LoginFrom(source, "alice", "invalid"); !errors.Is(err, ErrLimited) {
		t.Fatal("clock rollback refilled anonymous allowance")
	}
	if _, _, err := m.LoginFrom(source, "alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal("clock rollback refilled verified allowance")
	}
	if originCount(m) != 1 {
		t.Fatal("clock rollback expired the origin")
	}
	*clock = base.Add(time.Second)
	if _, _, err := m.LoginFrom(source, "alice", secret); err != nil {
		t.Fatal("forward clock did not replenish verified allowance", err)
	}
}

func TestLoginFromMalformedCredentialsRemainAudited(t *testing.T) {
	for name, credential := range map[string]string{"alice": strings.Repeat("x", 65_536), strings.Repeat("n", 65_536): strings.Repeat("0", 64)} {
		m, _, events, _ := frozenManager(t)
		if _, _, err := m.LoginFrom(netip.MustParseAddr("198.18.0.1"), name, credential); !errors.Is(err, ErrDenied) {
			t.Fatal("malformed credential did not use anonymous admission", err)
		}
		if len(*events) != 1 || (*events)[0].Actor != "unknown" || (*events)[0].Result != "denied" {
			t.Fatal("malformed input omitted denial audit or exposed submitted content")
		}
	}
	upper := strings.Repeat("AB", 32)
	digest := sha256.Sum256([]byte(upper))
	m, err := New([]Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:])}}, func(Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.LoginFrom(netip.MustParseAddr("198.18.0.1"), "alice", upper); !errors.Is(err, ErrDenied) {
		t.Fatal("noncanonical credential accepted")
	}
}

func TestVerifiedBudgetAndSessionLimitRemainEnforced(t *testing.T) {
	m, secret, _, clock := frozenManager(t)
	base := *clock
	source := netip.MustParseAddr("198.18.0.1")
	for i := 0; i < 32; i++ {
		*clock = base.Add(time.Duration(i/loginAttemptsPerSecond) * time.Second)
		if _, _, err := m.LoginFrom(source, "alice", secret); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		if i == loginAttemptsPerSecond-1 {
			if _, _, err := m.LoginFrom(netip.MustParseAddr("198.18.0.2"), "alice", secret); !errors.Is(err, ErrLimited) {
				t.Fatal("verified budget is not process-wide")
			}
		}
	}
	*clock = base.Add(8 * time.Second)
	if _, _, err := m.LoginFrom(source, "alice", secret); !errors.Is(err, ErrLimited) || len(m.sessions) != 32 {
		t.Fatal("session limit changed")
	}
}

func TestAuditFailureStillFailsClosedForEveryLoginLane(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		m, secret, _, _ := frozenManager(t)
		m.audit = func(Event) error { return errors.New("simulated storage failure") }
		credential := secret
		if invalid {
			credential = "invalid"
		}
		source := netip.MustParseAddr("198.18.0.1")
		if _, _, err := m.LoginFrom(source, "alice", credential); !errors.Is(err, ErrUnavailable) {
			t.Fatal("audit failure was ignored")
		}
		for _, next := range []string{secret, "invalid"} {
			if _, _, err := m.LoginFrom(source, "alice", next); !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed audit did not latch every login lane closed")
			}
		}
		if _, _, err := m.Login("alice", secret); !errors.Is(err, ErrUnavailable) || len(m.sessions) != 0 {
			t.Fatal("legacy lane escaped the audit failure latch")
		}
	}
}

func TestConcurrentOriginsAndCredentialChecks(t *testing.T) {
	m, secret, events, _ := frozenManager(t)
	var wg sync.WaitGroup
	var admitted, denied, limited atomic.Int32
	start := make(chan struct{})
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			<-start
			credential := "invalid"
			if i%2 == 0 {
				credential = secret
			}
			_, _, err := m.LoginFrom(netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 1)}), "alice", credential)
			switch {
			case err == nil:
				admitted.Add(1)
			case errors.Is(err, ErrDenied):
				denied.Add(1)
			case errors.Is(err, ErrLimited):
				limited.Add(1)
			default:
				t.Errorf("unexpected concurrent result: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if admitted.Load() != 4 || denied.Load() != 4 || limited.Load() != 92 || len(*events) != 8 || len(m.sessions) != 4 {
		t.Fatal("concurrent admission exceeded its independent bounds")
	}
}

func BenchmarkLoginAdmissionRejected(b *testing.B) {
	for name, credential := range map[string]string{"malformed": "invalid", "canonical": strings.Repeat("0", 64)} {
		b.Run(name, func(b *testing.B) {
			m, err := New([]Account{{Username: "alice", Role: "admin", CredentialSHA256: strings.Repeat("0", 64)}}, func(Event) error { return nil })
			if err != nil {
				b.Fatal(err)
			}
			clock := time.Now()
			m.now = func() time.Time { return clock }
			source := netip.MustParseAddr("198.18.0.1")
			for i := 0; i < loginAttemptsPerSecond; i++ {
				_, _, _ = m.LoginFrom(source, "alice", credential)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := m.LoginFrom(source, "alice", credential); !errors.Is(err, ErrLimited) {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLoginAdmissionOriginTable(b *testing.B) {
	for _, full := range []bool{false, true} {
		name := "available"
		if full {
			name = "full"
		}
		b.Run(name, func(b *testing.B) {
			base := time.Now()
			source := netip.MustParseAddr("198.19.0.1")
			var initial loginAdmission
			if full {
				for i := range initial.origins {
					initial.origins[i] = originBudget{netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 1)}), loginBudget{base, 1}}
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				admission := initial
				// Copy/reset cost is included; this is not a network throughput test.
				if allowed := admission.allowAnonymous(source, base); allowed != !full {
					b.Fatal("unexpected table admission")
				}
			}
		})
	}
}

func BenchmarkLoginAdmissionVerifiedWithLogout(b *testing.B) {
	secret := strings.Repeat("ab", 32)
	digest := sha256.Sum256([]byte(secret))
	m, err := New([]Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:])}}, func(Event) error { return nil })
	if err != nil {
		b.Fatal(err)
	}
	clock := time.Now()
	m.now = func() time.Time { return clock }
	source := netip.MustParseAddr("198.18.0.1")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		clock = clock.Add(time.Second)
		_, token, err := m.LoginFrom(source, "alice", secret)
		if err != nil {
			b.Fatal(err)
		}
		if err = m.Logout(token); err != nil {
			b.Fatal(err)
		}
	}
}
