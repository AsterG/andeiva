package adminapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/productinfo"
)

func TestSystemInfoAuthenticatedReadOnly(t *testing.T) {
	previous := productinfo.Version
	productinfo.Version = "0.1.0~alpha15"
	t.Cleanup(func() { productinfo.Version = previous })
	for _, role := range []string{"admin", "viewer"} {
		t.Run(role, func(t *testing.T) {
			f := fixtureServer(t, role)
			_, token, _ := f.login(t, "cli")
			code, body, headers := f.request(t, http.MethodGet, "/api/v1/system/info", "", map[string]string{"Authorization": "Bearer " + token})
			var info productinfo.Info
			if code != http.StatusOK || json.Unmarshal([]byte(body), &info) != nil || info != productinfo.Current() || headers.Get("Cache-Control") != "no-store" || f.backend.calls != 0 {
				t.Fatalf("product identity failed: status=%d body=%s backend=%d", code, body, f.backend.calls)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(body), &fields); err != nil || len(fields) != 4 {
				t.Fatal("unexpected product identity fields")
			}
			for _, name := range []string{"product", "version", "channel", "update_status"} {
				if _, ok := fields[name]; !ok {
					t.Fatal("missing field", name)
				}
			}
		})
	}
}

func TestSystemInfoBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		headers            map[string]string
		login              bool
		want               int
	}{
		{"anonymous", "GET", "/api/v1/system/info", nil, false, 401},
		{"bad-session", "GET", "/api/v1/system/info", map[string]string{"Authorization": "Bearer " + strings.Repeat("f", 64)}, false, 401},
		{"query", "GET", "/api/v1/system/info?version=private", nil, true, 400},
		{"empty-query", "GET", "/api/v1/system/info?", nil, true, 400},
		{"origin", "GET", "/api/v1/system/info", map[string]string{"Origin": "https://other.invalid"}, true, 403},
		{"host", "GET", "/api/v1/system/info", map[string]string{"Host": "other.invalid"}, true, 403},
		{"cross-site", "GET", "/api/v1/system/info", map[string]string{"Sec-Fetch-Site": "cross-site"}, true, 403},
		{"head", "HEAD", "/api/v1/system/info", nil, true, 405},
		{"post", "POST", "/api/v1/system/info", map[string]string{"Content-Type": "application/json"}, true, 405},
		{"put", "PUT", "/api/v1/system/info", nil, true, 405},
		{"client", "GET", "/api/v1/system/info", map[string]string{"X-ANDEIVA-Client": "arbitrary"}, true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixtureServer(t, "admin")
			headers := map[string]string{}
			for key, value := range tc.headers {
				headers[key] = value
			}
			if tc.login {
				_, token, _ := f.login(t, "cli")
				headers["Authorization"] = "Bearer " + token
			}
			code, body, _ := f.request(t, tc.method, tc.path, "{}", headers)
			if code != tc.want || strings.Contains(body, "\"product\"") || f.backend.calls != 0 {
				t.Fatalf("boundary %s failed: status=%d backend=%d", tc.name, code, f.backend.calls)
			}
		})
	}
}

func TestSystemInfoCookieAndRevokedSession(t *testing.T) {
	f := fixtureServer(t, "viewer")
	id, _, headers := f.login(t, "web")
	cookie := strings.SplitN(headers.Get("Set-Cookie"), ";", 2)[0]
	code, _, _ := f.request(t, "GET", "/api/v1/system/info", "", map[string]string{"Cookie": cookie, "Origin": f.server.URL, "X-ANDEIVA-Client": "web"})
	if code != 200 {
		t.Fatal("viewer cookie read refused", code)
	}
	code, _, _ = f.request(t, "POST", "/api/v1/auth/logout", "{}", map[string]string{"Cookie": cookie, "Origin": f.server.URL, "X-CSRF-Token": id.CSRF, "Content-Type": "application/json"})
	if code != 200 {
		t.Fatal("logout failed", code)
	}
	code, body, _ := f.request(t, "GET", "/api/v1/system/info", "", map[string]string{"Cookie": cookie})
	if code != 401 || strings.Contains(body, "\"product\"") || f.backend.calls != 0 {
		t.Fatal("logged-out session read product metadata")
	}
}

func TestSystemInfoMissingOrInvalidBuildMetadata(t *testing.T) {
	previous := productinfo.Version
	t.Cleanup(func() { productinfo.Version = previous })
	for _, version := range []string{"", "private-build-path", "0.1.0~alpha0", strings.Repeat("x", 4096)} {
		productinfo.Version = version
		f := fixtureServer(t, "admin")
		_, token, _ := f.login(t, "cli")
		code, body, _ := f.request(t, "GET", "/api/v1/system/info", "", map[string]string{"Authorization": "Bearer " + token})
		var info productinfo.Info
		if code != 200 || json.Unmarshal([]byte(body), &info) != nil || info.Version != "" || info.Channel != "development" || info.UpdateStatus != "unavailable" || strings.Contains(body, `"version"`) || f.backend.calls != 0 {
			t.Fatal("missing/invalid package identity was exposed or fabricated")
		}
		f.server.Close()
	}
}
