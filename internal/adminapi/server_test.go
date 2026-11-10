package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
)

type fakeBackend struct {
	calls     int
	err       error
	principal configpoc.Principal
	surface   configpoc.Surface
	revisions []configpoc.RevisionEntry
	audit     []configpoc.Audit
}

func (b *fakeBackend) Execute(_ context.Context, p configpoc.Principal, s configpoc.Surface, _ configpoc.Request) (configpoc.Snapshot, error) {
	b.calls++
	b.principal = p
	b.surface = s
	return configpoc.Snapshot{}, b.err
}
func (b *fakeBackend) History(configpoc.Principal, uint64, int) ([]configpoc.RevisionEntry, error) {
	b.calls++
	return b.revisions, b.err
}
func (b *fakeBackend) Audit(configpoc.Principal) ([]configpoc.Audit, error) {
	b.calls++
	return b.audit, b.err
}

type fixtureAPI struct {
	server  *httptest.Server
	backend *fakeBackend
	auth    *adminauth.Manager
	secret  string
	events  []adminauth.Event
}

func fixtureServer(t *testing.T, role string) *fixtureAPI {
	t.Helper()
	f := &fixtureAPI{secret: strings.Repeat("ab", 32), backend: &fakeBackend{}}
	sum := sha256.Sum256([]byte(f.secret))
	var err error
	f.auth, err = adminauth.New([]adminauth.Account{{Username: "alice", Role: role, CredentialSHA256: hex.EncodeToString(sum[:])}}, func(e adminauth.Event) error { f.events = append(f.events, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewUnstartedServer(nil)
	origin := "https://" + f.server.Listener.Addr().String()
	h, err := New(Options{Origin: origin, Auth: f.auth, Backend: f.backend, Observe: func(context.Context) (Effective, error) { return Effective{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.server.Config.Handler = h
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}
func (f *fixtureAPI) request(t *testing.T, method, path, body string, headers map[string]string) (int, string, http.Header) {
	t.Helper()
	r, err := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		if k == "Host" {
			r.Host = v
		} else {
			r.Header.Set(k, v)
		}
	}
	response, err := f.server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("X-Request-ID") == "" {
		t.Fatal("missing correlation")
	}
	return response.StatusCode, string(data), response.Header
}
func (f *fixtureAPI) login(t *testing.T, client string) (adminauth.Identity, string, http.Header) {
	t.Helper()
	status, body, h := f.request(t, "POST", "/api/v1/auth/login", fmt.Sprintf(`{"username":"alice","credential":%q}`, f.secret), map[string]string{"Content-Type": "application/json", "X-ANDEIVA-Client": client, "Origin": f.server.URL})
	if status != 200 {
		t.Fatalf("login %d %s", status, body)
	}
	var v struct {
		adminauth.Identity
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	return v.Identity, v.Token, h
}
func TestAuthenticationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, path, body string
		headers          map[string]string
		want             int
	}{
		{"unauthenticated", "/api/v1/firewall/transactions", `{}`, nil, 401},
		{"origin", "/api/v1/auth/login", `{}`, map[string]string{"Origin": "https://evil.invalid"}, 403},
		{"host", "/api/v1/auth/login", `{}`, map[string]string{"Host": "evil.invalid"}, 403},
		{"fetch", "/api/v1/auth/login", `{}`, map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"query", "/api/v1/auth/login?unexpected=1", `{}`, nil, 400},
		{"role", "/api/v1/auth/login", `{"username":"alice","credential":"x","role":"admin"}`, map[string]string{"Content-Type": "application/json", "X-ANDEIVA-Client": "cli"}, 400},
		{"duplicate", "/api/v1/auth/login", `{"username":"alice","Username":"bob"}`, map[string]string{"Content-Type": "application/json", "X-ANDEIVA-Client": "cli"}, 400},
		{"oversized", "/api/v1/auth/login", `{"username":"` + strings.Repeat("a", 65536) + `"}`, map[string]string{"Content-Type": "application/json", "X-ANDEIVA-Client": "cli"}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtureServer(t, "admin")
			status, _, _ := f.request(t, "POST", tc.path, tc.body, tc.headers)
			if status != tc.want || f.backend.calls != 0 {
				t.Fatalf("status=%d calls=%d", status, f.backend.calls)
			}
		})
	}
}
func TestCookieCSRFAndBearerSeparation(t *testing.T) {
	f := fixtureServer(t, "admin")
	id, token, h := f.login(t, "web")
	if token != "" {
		t.Fatal("web bearer exposed")
	}
	cookie := h.Get("Set-Cookie")
	for _, flag := range []string{"Secure", "HttpOnly", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(cookie, flag) {
			t.Fatal("cookie missing", flag)
		}
	}
	cookie = strings.Split(cookie, ";")[0]
	headers := map[string]string{"Content-Type": "application/json", "Cookie": cookie}
	status, _, _ := f.request(t, "POST", "/api/v1/firewall/transactions", `{"operation":"validate"}`, headers)
	if status != 403 || f.backend.calls != 0 {
		t.Fatal("missing CSRF accepted")
	}
	headers["Origin"] = f.server.URL
	headers["X-CSRF-Token"] = id.CSRF
	status, _, _ = f.request(t, "POST", "/api/v1/firewall/transactions", `{"operation":"validate"}`, headers)
	if status != 200 || f.backend.calls != 1 {
		t.Fatal("authorized cookie rejected", status)
	}
	headers["Authorization"] = "Bearer " + strings.Repeat("a", 64)
	status, _, _ = f.request(t, "POST", "/api/v1/firewall/transactions", `{}`, headers)
	if status != 401 || f.backend.calls != 1 {
		t.Fatal("mixed credentials accepted")
	}
	if len(f.events) < 3 {
		t.Fatal("denials not audited")
	}
}
func TestViewerNoWriteAndServerIdentity(t *testing.T) {
	f := fixtureServer(t, "viewer")
	_, token, _ := f.login(t, "cli")
	headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json", "X-ANDEIVA-Client": "cli"}
	status, _, _ := f.request(t, "POST", "/api/v1/firewall/transactions", `{"operation":"commit"}`, headers)
	if status != 403 || f.backend.calls != 0 {
		t.Fatal("viewer reached backend")
	}
	status, _, _ = f.request(t, "GET", "/api/v1/firewall", "", headers)
	if status != 200 || f.backend.principal.Role != "viewer" || f.backend.surface != configpoc.CLI {
		t.Fatal("server identity missing")
	}
	status, _, _ = f.request(t, "POST", "/api/v1/auth/logout", `{}`, headers)
	if status != 200 {
		t.Fatal("logout failed")
	}
	status, _, _ = f.request(t, "GET", "/api/v1/auth/session", "", headers)
	if status != 401 {
		t.Fatal("revoked session accepted")
	}
}
func TestQueryAndJSONRejection(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{} {}`, `{"a":1,"\u0061":2}`, `{"a":` + strings.Repeat("[", 33) + `0` + strings.Repeat("]", 33) + `}`, `{"a":{"x":1,"x":2}}`} {
		if validateJSON([]byte(body)) == nil {
			t.Fatal("accepted ambiguous JSON")
		}
	}
	f := fixtureServer(t, "admin")
	_, token, _ := f.login(t, "cli")
	headers := map[string]string{"Authorization": "Bearer " + token}
	for _, path := range []string{"/api/v1/auth/session?x=1", "/api/v1/firewall/history?limit=1&limit=2", "/api/v1/firewall/history?limit=101", "/api/v1/firewall/history?x=1", "/api/v1/firewall/history?before=-1"} {
		status, _, _ := f.request(t, "GET", path, "", headers)
		if status != 400 {
			t.Fatal(path, status)
		}
	}
	if f.backend.calls != 0 {
		t.Fatal("invalid query reached backend")
	}
}
func TestSanitizedErrorsAndTLS(t *testing.T) {
	f := fixtureServer(t, "admin")
	_, token, _ := f.login(t, "cli")
	for _, e := range []error{fmt.Errorf("private /etc/secret: %w", configpoc.ErrConflict), errors.New("private /etc/secret")} {
		f.backend.err = e
		status, body, h := f.request(t, "GET", "/api/v1/firewall", "", map[string]string{"Authorization": "Bearer " + token})
		if status < 400 || strings.Contains(body, "private") || !strings.Contains(body, h.Get("X-Request-ID")) {
			t.Fatal("unsafe error", body)
		}
	}
	req := httptest.NewRequest("GET", f.server.URL+"/api/v1/firewall", nil)
	req.TLS = nil
	rec := httptest.NewRecorder()
	f.server.Config.Handler.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("cleartext accepted")
	}
}

func TestHistoryCommonCursorAndLeaseRedaction(t *testing.T) {
	f := fixtureServer(t, "admin")
	f.backend.revisions = []configpoc.RevisionEntry{{Sequence: 10}, {Sequence: 1}}
	f.backend.audit = []configpoc.Audit{{Sequence: 8}, {Sequence: 9}, {Sequence: 10}}
	_, token, _ := f.login(t, "cli")
	status, body, _ := f.request(t, "GET", "/api/v1/firewall/history?limit=2", "", map[string]string{"Authorization": "Bearer " + token})
	var page struct {
		Revisions []configpoc.RevisionEntry `json:"revisions"`
		Audit     []configpoc.Audit         `json:"audit"`
		Next      uint64                    `json:"next_before"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &page) != nil || page.Next != 9 || len(page.Revisions) != 1 || len(page.Audit) != 2 {
		t.Fatal("cursor skipped records", body)
	}
	h := f.server.Config.Handler.(*handler)
	pending := &configpoc.Pending{Lease: "private-helper-lease"}
	state := h.state(context.Background(), configpoc.Snapshot{Pending: pending})
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-helper-lease") || pending.Lease != "private-helper-lease" {
		t.Fatal("lease disclosure or mutation")
	}
}

func TestAmbiguousCredentialsRejected(t *testing.T) {
	for _, kind := range []string{"duplicate-bearer", "duplicate-cookie", "mixed", "basic", "short"} {
		r := httptest.NewRequest("POST", "https://localhost/api/v1/firewall/transactions", nil)
		token := strings.Repeat("a", 64)
		switch kind {
		case "duplicate-bearer":
			r.Header.Add("Authorization", "Bearer "+token)
			r.Header.Add("Authorization", "Bearer "+token)
		case "duplicate-cookie":
			r.AddCookie(&http.Cookie{Name: cookieName, Value: token})
			r.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		case "mixed":
			r.Header.Set("Authorization", "Bearer "+token)
			r.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		case "basic":
			r.Header.Set("Authorization", "Basic "+token)
		case "short":
			r.Header.Set("Authorization", "Bearer short")
		}
		if _, _, err := requestToken(r); err == nil {
			t.Fatal("ambiguous credentials accepted", kind)
		}
	}
}
