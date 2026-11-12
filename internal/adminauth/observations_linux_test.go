//go:build linux

package adminauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/authobservations"
)

type observationAdmission struct {
	denied, pressure atomic.Bool
	mu               sync.Mutex
	selected         authobservations.Selection
}

func (a *observationAdmission) Selection(s authobservations.Selection) error {
	if a.denied.Load() || s.Version != 1 || s.Feature != authobservations.Feature || s.Runtime != strings.Repeat("1", 64) || s.Protected != strings.Repeat("2", 64) || s.Backup != s.Protected {
		return errors.New("selector refused")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.selected.Version == 0 {
		a.selected = s
	}
	if a.selected != s {
		return errors.New("selector changed")
	}
	return nil
}
func (a *observationAdmission) Capacity(_ authobservations.AreaIdentity, used, peak uint64) error {
	if a.pressure.Load() || used > authobservations.MaximumBytes || peak > authobservations.MaximumBytes-used {
		return errors.New("isolated observation budget exhausted")
	}
	return nil
}

func observationManager(t *testing.T) (*Manager, string, *authobservations.Store, *observationAdmission, *[]Event) {
	t.Helper()
	legacy, secret, _ := fixture(t)
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	guard := new(observationAdmission)
	if err := authobservations.Prepare(root, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("2", 64), guard); err != nil {
		t.Fatal(err)
	}
	store, err := authobservations.Open(root, guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var accounts []Account
	for name, a := range legacy.accounts {
		accounts = append(accounts, Account{Username: name, Role: a.role, CredentialSHA256: hex.EncodeToString(a.digest[:])})
	}
	viewerDigest := sha256.Sum256([]byte(secret))
	accounts = append(accounts, Account{Username: "viewer", Role: "viewer", CredentialSHA256: hex.EncodeToString(viewerDigest[:])})
	events := []Event{}
	m, err := NewWithAnonymousObservations(accounts, func(e Event) error { events = append(events, e); return nil }, store)
	if err != nil {
		t.Fatal(err)
	}
	return m, secret, store, guard, &events
}

func anonymousTotal(report authobservations.Report) uint64 {
	var total uint64
	for _, i := range report.Intervals {
		total += i.Total
	}
	return total
}

func TestAnonymousObservationCorruptReopenPreservesVerifiedAuth(t *testing.T) {
	_, secret, _ := fixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	guard := new(observationAdmission)
	if err := authobservations.Prepare(root, strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("2", 64), guard); err != nil {
		t.Fatal(err)
	}
	guard.mu.Lock()
	canonical := guard.selected
	guard.mu.Unlock()
	corrupt := []byte("partial snapshot")
	if err := os.WriteFile(dir+"/observations.json", corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := authobservations.Open(root, guard); err == nil {
		t.Fatal("corrupt snapshot admitted normally")
	}
	store, err := authobservations.OpenDegraded(root, canonical, guard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := sha256.Sum256([]byte(secret))
	accounts := []Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(h[:])}}
	events := []Event{{At: time.Now().UTC(), Actor: "unknown", Action: "login", Result: "denied"}}
	historic := events[0]
	m, err := NewWithAnonymousObservations(accounts, func(e Event) error { events = append(events, e); return nil }, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.LoginFrom(netip.MustParseAddr("198.18.0.1"), "alice", "invalid"); !errors.Is(err, ErrDenied) {
		t.Fatal("anonymous was not denied")
	}
	_, token, err := m.LoginFrom(netip.MustParseAddr("198.18.0.1"), "alice", secret)
	if err != nil {
		t.Fatal("verified auth unavailable", err)
	}
	if len(events) != 2 || events[0] != historic || events[1].Actor != "alice" || events[1].Result != "ok" {
		t.Fatal("protected audit changed or skipped")
	}
	r, err := m.AnonymousObservations(token)
	if err != nil || !r.MemoryOnly || !r.Degraded || !r.UnknownGap || anonymousTotal(r) != 1 {
		t.Fatal("collection degradation hidden")
	}
	after, err := root.ReadFile("observations.json")
	if err != nil || string(after) != string(corrupt) {
		t.Fatal("corrupt area rewritten")
	}
	guard.denied.Store(true)
	if _, err := NewWithAnonymousObservations(accounts, func(Event) error { return nil }, store); err == nil {
		t.Fatal("failed guard admitted constructor")
	}
}

func TestAnonymousObservationConstructorAdmission(t *testing.T) {
	m, secret, store, guard, _ := observationManager(t)
	h := sha256.Sum256([]byte(secret))
	accounts := []Account{{Username: "admin", Role: "admin", CredentialSHA256: hex.EncodeToString(h[:])}}
	if _, err := NewWithAnonymousObservations(accounts, func(Event) error { return nil }, nil); err == nil {
		t.Fatal("nil selector")
	}
	guard.denied.Store(true)
	if _, err := NewWithAnonymousObservations(accounts, func(Event) error { return nil }, store); err == nil {
		t.Fatal("unsupported/stale runtime selection")
	}
	guard.denied.Store(false)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithAnonymousObservations(accounts, func(Event) error { return nil }, store); err == nil {
		t.Fatal("closed store")
	}
	if _, _, err := m.LoginFrom(netip.MustParseAddr("198.18.0.1"), "alice", secret); err != nil {
		t.Fatal("collector close latched protected auth", err)
	}
}

func TestAnonymousObservationClassificationAndProtectedFailures(t *testing.T) {
	m, secret, store, guard, events := observationManager(t)
	clock := time.Now()
	m.now = func() time.Time { return clock }
	peer := netip.MustParseAddr("198.18.0.1")
	for i := 0; i < 20; i++ {
		name := "alice"
		if i%2 == 0 {
			name = "nonexistent"
		}
		_, _, err := m.LoginFrom(peer, name, "invalid")
		if !errors.Is(err, ErrDenied) && !errors.Is(err, ErrLimited) {
			t.Fatal(err)
		}
	}
	if len(*events) != 0 || anonymousTotal(store.Report()) != 20 {
		t.Fatal("unverified flow crossed protected boundary")
	}
	guard.pressure.Store(true)
	if store.Flush(context.Background()) == nil || !store.Report().Degraded {
		t.Fatal("pressure hidden")
	}
	var token string
	for i := 0; i < 4; i++ {
		_, v, err := m.LoginFrom(peer, "alice", secret)
		if err != nil {
			t.Fatal(err)
		}
		token = v
	}
	if _, _, err := m.LoginFrom(peer, "alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	if len(*events) != 5 || (*events)[4].Actor != "alice" || (*events)[4].Result != "limited" || anonymousTotal(store.Report()) != 20 {
		t.Fatal("verified rate denial not protected")
	}
	if err := m.RecordDenied("alice", "write"); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordDenied("alice", "csrf"); err != nil {
		t.Fatal(err)
	}
	if err := m.Logout(token); err != nil {
		t.Fatal(err)
	}
	if anonymousTotal(store.Report()) != 20 {
		t.Fatal("administrative event reclassified")
	}
	clock = clock.Add(time.Second)
	m.audit = func(Event) error { return errors.New("protected audit full") }
	if _, _, err := m.LoginFrom(peer, "alice", secret); !errors.Is(err, ErrUnavailable) || !m.failed {
		t.Fatal("protected failure did not fail closed")
	}
}

func TestAnonymousObservationSessionLimitAndReadAuthorization(t *testing.T) {
	m, secret, store, _, events := observationManager(t)
	clock := time.Now()
	m.now = func() time.Time { return clock }
	peer := netip.MustParseAddr("198.18.0.1")
	_, admin, err := m.LoginFrom(peer, "alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	_, viewer, err := m.LoginFrom(peer, "viewer", secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AnonymousObservations(viewer); !errors.Is(err, ErrDenied) {
		t.Fatal("viewer observation access")
	}
	if _, err := m.AnonymousObservations("bad"); !errors.Is(err, ErrDenied) {
		t.Fatal("anonymous observation access")
	}
	if _, err := m.AnonymousObservations(admin); err != nil {
		t.Fatal(err)
	}
	for len(m.sessions) < 32 {
		clock = clock.Add(time.Second)
		if _, _, err := m.LoginFrom(peer, "alice", secret); err != nil {
			t.Fatal(err)
		}
	}
	clock = clock.Add(time.Second)
	if _, _, err := m.LoginFrom(peer, "alice", secret); !errors.Is(err, ErrLimited) {
		t.Fatal(err)
	}
	last := (*events)[len(*events)-1]
	if last.Actor != "alice" || last.Result != "limited" || anonymousTotal(store.Report()) != 0 {
		t.Fatal("verified session-limit reclassified")
	}
}

func TestAnonymousObservationLegacyEventsUnchanged(t *testing.T) {
	m, _, events := fixture(t)
	clock := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return clock }
	peer := netip.MustParseAddr("198.18.0.1")
	for i := 0; i < 5; i++ {
		_, _, _ = m.LoginFrom(peer, "secret-attacker-username", "invalid")
	}
	want := make([]Event, 4)
	for i := range want {
		want[i] = Event{At: clock, Actor: "unknown", Action: "login", Result: "denied"}
	}
	if !reflect.DeepEqual(*events, want) {
		t.Fatal("legacy protected event semantics changed")
	}
}

func TestAnonymousObservationConcurrentAuth(t *testing.T) {
	m, secret, store, _, _ := observationManager(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				_, _, _ = m.LoginFrom(netip.MustParseAddr("198.18.0.1"), "unknown", "bad")
			}
		}()
	}
	_, token, err := m.LoginFrom(netip.MustParseAddr("2001:db8::1"), "alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err := m.Authenticate(token); err != nil || anonymousTotal(store.Report()) != 400 {
		t.Fatal("anonymous pressure changed protected auth")
	}
}
