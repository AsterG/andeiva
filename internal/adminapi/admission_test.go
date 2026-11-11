package adminapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func peerLogin(t *testing.T, f *fixtureAPI, peer, credential, client string, headers map[string]string) int {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, f.server.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"alice","credential":"`+credential+`"}`))
	r.RemoteAddr = peer
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.server.URL)
	r.Header.Set("X-ANDEIVA-Client", client)
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	f.server.Config.Handler.ServeHTTP(w, r)
	return w.Code
}

func TestLoginPeerCannotBeSuppliedByForwardingHeaders(t *testing.T) {
	f := fixtureServer(t, "admin")
	headers := map[string]string{"Forwarded": "for=198.18.0.2", "X-Forwarded-For": "198.18.0.2", "X-Real-IP": "198.18.0.2"}
	for _, peer := range []string{"", "198.18.0.1", "not-an-address:1234", "[fe80::1%src0]:1234", "0.0.0.0:1234", "[::ffff:0.0.0.0]:1234", "224.0.0.1:1234"} {
		if code := peerLogin(t, f, peer, f.secret, "api", headers); code != http.StatusUnauthorized {
			t.Fatalf("invalid socket peer accepted through headers: status %d", code)
		}
	}
	if len(f.events) != 0 {
		t.Fatal("invalid peer reached login audit")
	}
	for _, client := range []string{"web", "cli", "api"} {
		if code := peerLogin(t, f, "[::ffff:198.18.0.1]:1234", f.secret, client, headers); code != http.StatusOK {
			t.Fatalf("forwarding headers replaced a valid socket peer for %s: status %d", client, code)
		}
	}
}

func TestLoginOriginPortAndForwardingHeadersDoNotResetAnonymousBudget(t *testing.T) {
	f := fixtureServer(t, "admin")
	for _, peer := range []string{"198.18.0.1:1000", "198.18.0.1:1001", "[::ffff:198.18.0.1]:1002", "198.18.0.1:1003"} {
		if code := peerLogin(t, f, peer, "invalid", "api", map[string]string{"X-Forwarded-For": peer}); code != http.StatusUnauthorized {
			t.Fatalf("invalid login: status %d", code)
		}
	}
	if code := peerLogin(t, f, "198.18.0.1:1004", "invalid", "api", map[string]string{"Forwarded": "for=198.18.1.1", "X-Forwarded-For": "198.18.1.1", "X-Real-IP": "198.18.1.1"}); code != http.StatusTooManyRequests {
		t.Fatalf("port or header changed the anonymous allowance: status %d", code)
	}
	if code := peerLogin(t, f, "198.18.0.2:1005", f.secret, "api", nil); code != http.StatusOK {
		t.Fatalf("anonymous allowance starved the verified transport: status %d", code)
	}
}
