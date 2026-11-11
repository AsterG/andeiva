//go:build linux

package cli

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AsterG/andeiva/internal/productinfo"
)

func TestSystemInfoOfficialCLIUsesServerAndClosesSession(t *testing.T) {
	for _, scenario := range []string{"success", "invalid-info", "denied", "logout-failed"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			paths := []string{}
			secret, token := strings.Repeat("b", 64), strings.Repeat("a", 64)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.TLS == nil || r.Header.Get("X-ANDEIVA-Client") != "cli" {
					t.Error("transport contract missing")
				}
				switch r.URL.Path {
				case "/api/v1/auth/login":
					var request struct {
						Username   string `json:"username"`
						Credential string `json:"credential"`
					}
					if json.NewDecoder(r.Body).Decode(&request) != nil || request.Username != "alice" || request.Credential != secret {
						t.Error("login contract changed")
					}
					_, _ = fmt.Fprintf(w, `{"username":"alice","role":"viewer","token":%q}`, token)
				case "/api/v1/system/info":
					if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+token {
						t.Error("metadata authentication missing")
					}
					if scenario == "denied" {
						w.WriteHeader(403)
						_, _ = fmt.Fprintf(w, `{"code":"ANDEIVA_AUTH_DENIED","request_id":%q}`, strings.Repeat("c", 32))
					} else if scenario == "invalid-info" {
						_, _ = w.Write([]byte(`{"product":"private","version":"kernel","channel":"stable","update_status":"up-to-date"}`))
					} else {
						_, _ = w.Write([]byte(`{"product":"ANDEIVA Security Gateway","version":"0.1.0~alpha15","channel":"experimental","update_status":"unavailable"}`))
					}
				case "/api/v1/auth/logout":
					if r.Header.Get("Authorization") != "Bearer "+token {
						t.Error("cleanup session missing")
					}
					if scenario == "logout-failed" {
						w.WriteHeader(503)
						_, _ = fmt.Fprintf(w, `{"code":"ANDEIVA_AUTH_UNAVAILABLE","request_id":%q}`, strings.Repeat("c", 32))
					} else {
						_, _ = w.Write([]byte(`{"logged_out":true}`))
					}
				default:
					t.Error("unexpected API operation")
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			ca, credentials := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "credentials.json")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(credentials, []byte(fmt.Sprintf(`{"username":"alice","credential":%q}`, secret)), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run([]string{"sys", "i", "--url", server.URL, "--ca-file", ca, "--credentials-file", credentials}, &out, &errOut)
			if scenario == "success" {
				var info productinfo.Info
				if code != 0 || json.Unmarshal(out.Bytes(), &info) != nil || info.Version != "0.1.0~alpha15" || errOut.Len() != 0 {
					t.Fatal("server-authoritative version unavailable")
				}
			} else if code != 2 || out.Len() != 0 {
				t.Fatal("invalid metadata/cleanup reported success")
			}
			mu.Lock()
			actual := strings.Join(paths, ",")
			mu.Unlock()
			if actual != "/api/v1/auth/login,/api/v1/system/info,/api/v1/auth/logout" {
				t.Fatal("session cleanup or read-only contract lost", actual)
			}
			for _, value := range []string{secret, token, "up-to-date", "kernel"} {
				if strings.Contains(out.String(), value) || strings.Contains(errOut.String(), value) {
					t.Fatal("private or unverified data reached terminal")
				}
			}
		})
	}
}
