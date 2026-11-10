package adminclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
)

func trustedClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	c, err := New(s.URL, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}
func TestSessionLifecycleAndTransactions(t *testing.T) {
	calls := []string{}
	token := strings.Repeat("a", 64)
	c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.TLS == nil || r.Header.Get("X-ANDEIVA-Client") != "cli" {
			t.Error("transport policy missing")
		}
		if r.URL.Path != "/api/v1/auth/login" && r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("session missing")
		}
		switch r.URL.Path {
		case "/api/v1/auth/login":
			_ = json.NewEncoder(w).Encode(map[string]string{"username": "alice", "role": "admin", "token": token})
		case "/api/v1/auth/logout":
			_, _ = w.Write([]byte(`{"logged_out":true}`))
		case "/api/v1/firewall/transactions":
			var req configpoc.Request
			if json.NewDecoder(r.Body).Decode(&req) != nil || req.Operation != "validate" {
				t.Error("request lost")
			}
			_, _ = w.Write([]byte(`{"snapshot":{"generation":2},"effective":{"state":"verified","rules":[]}}`))
		case "/api/v1/firewall/history":
			if r.URL.Query().Get("before") != "42" || r.URL.Query().Get("limit") != "10" {
				t.Error("query lost")
			}
			_, _ = w.Write([]byte(`{"revisions":[],"audit":[],"next_before":0}`))
		default:
			_, _ = w.Write([]byte(`{"snapshot":{"generation":1},"effective":{"state":"verified","rules":[]}}`))
		}
	}))
	ctx := context.Background()
	if _, err := c.Login(ctx, Credentials{"alice", strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.State(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Execute(ctx, configpoc.Request{Operation: "validate"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.History(ctx, 42, 10); err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(ctx); err != nil {
		t.Fatal(err)
	}
	if c.token != "" || len(calls) != 5 {
		t.Fatal("session not cleared")
	}
}

func TestTrafficCursorAndDecimalCounters(t *testing.T) {
	stream := strings.Repeat("c", 32)
	calls := 0
	c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/firewall/traffic" || r.URL.Query().Get("limit") != "10" {
			t.Error("traffic route lost")
		}
		if calls == 1 && (r.URL.Query().Has("before") || r.URL.Query().Has("stream")) {
			t.Error("first page has cursor")
		}
		if calls == 2 && (r.URL.Query().Get("before") != "42" || r.URL.Query().Get("stream") != stream) {
			t.Error("cursor not bound")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stream":"` + stream + `","records":[{"packets_total":"18446744073709551615","bytes_total":"18446744073709551615"}],"next_before":0,"evicted":0,"capacity":512,"sampling":"on_request","retention":"api_process","truncated":false}`))
	}))
	page, err := c.Traffic(context.Background(), 0, 10, "")
	if err != nil || page.Records[0].PacketsTotal != "18446744073709551615" {
		t.Fatal(page, err)
	}
	if _, err = c.Traffic(context.Background(), 42, 10, stream); err != nil {
		t.Fatal(err)
	}
	for _, args := range []struct {
		before uint64
		limit  int
		stream string
	}{{1, 10, ""}, {0, 10, stream}, {1, 10, "bad"}, {0, 101, ""}} {
		if _, err = c.Traffic(context.Background(), args.before, args.limit, args.stream); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid cursor accepted")
		}
	}
	if calls != 2 {
		t.Fatal("invalid query reached transport")
	}
}
func TestTLSAndRedirectRejection(t *testing.T) {
	c, s := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid", http.StatusFound)
	}))
	if _, err := c.State(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatal("redirect accepted", err)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	for _, base := range []string{"http://127.0.0.1", "https://user:secret@example.invalid", "https://example.invalid/?x=1", "https://example.invalid/path", "https://example.invalid?"} {
		if _, err := New(base, ca); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsafe URL", base)
		}
	}
	if _, err := New(s.URL, []byte("invalid CA")); !errors.Is(err, ErrConfiguration) {
		t.Fatal("invalid CA accepted")
	}
	c, err := New(strings.Replace(s.URL, "127.0.0.1", "localhost", 1), ca)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.State(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatal("invalid hostname accepted", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "untrusted"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err = New(s.URL, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.State(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatal("untrusted CA accepted", err)
	}
}
func TestBoundedSanitizedResponses(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
		want   error
	}{
		{`{"code":"private /etc/secret","request_id":"` + strings.Repeat("a", 32) + `"}`, 503, ErrResponse},
		{`{"code":"ANDEIVA_CONFIG_DENIED","request_id":"bad"}`, 403, ErrResponse},
		{strings.Repeat("a", 1024*1024+1), 200, ErrResponse},
		{`{} {}`, 200, ErrResponse},
	} {
		c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		if _, err := c.State(context.Background()); !errors.Is(err, tc.want) {
			t.Fatal("response accepted", err)
		}
	}
	c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"code":"ANDEIVA_CONFIG_DENIED","request_id":"` + strings.Repeat("a", 32) + `"}`))
	}))
	_, err := c.State(context.Background())
	var api *APIError
	if !errors.As(err, &api) || api.Code != "ANDEIVA_CONFIG_DENIED" {
		t.Fatal("stable error missing")
	}
}
