//go:build linux

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
)

func TestOfficialCLIHTTPSLifecycle(t *testing.T) {
	secret := strings.Repeat("b", 64)
	hash := sha256.Sum256([]byte(secret))
	events := []adminauth.Event{}
	auth, err := adminauth.New([]adminauth.Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(hash[:])}}, func(e adminauth.Event) error { events = append(events, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	var received configpoc.Request
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/login":
			var request struct {
				Username   string `json:"username"`
				Credential string `json:"credential"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil {
				t.Error("invalid login")
			}
			id, token, loginErr := auth.Login(request.Username, request.Credential)
			if loginErr != nil {
				t.Error(loginErr)
			}
			_ = json.NewEncoder(w).Encode(struct {
				adminauth.Identity
				Token string `json:"token"`
			}{id, token})
		case "/api/v1/auth/logout":
			if err := auth.Logout(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{"logged_out":true}`))
		default:
			if _, err := auth.Authenticate(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); err != nil {
				t.Error("missing authentication")
			}
			if r.URL.Path == "/api/v1/firewall/transactions" {
				calls++
				if json.NewDecoder(r.Body).Decode(&received) != nil {
					t.Error("invalid transaction")
				}
			}
			_, _ = w.Write([]byte(`{"snapshot":{"generation":7},"effective":{"state":"verified","rules":[]}}`))
		}
	}))
	defer s.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	credential := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, []byte(fmt.Sprintf(`{"username":"alice","credential":%q}`, secret)), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"firewall", "comm", "--url", s.URL, "--ca-file", ca, "--credentials-file", credential, "--confirm-seconds", "30"}
	var out, errOut bytes.Buffer
	if code := RunInput(args, nil, &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	if calls != 1 || received.Operation != "commit" || received.ExpectedGeneration != 7 || received.ConfirmFor.Seconds() != 30 || len(received.Key) != 32 {
		t.Fatal("transaction semantics lost", received)
	}
	if len(events) != 2 || events[0].Action != "login" || events[1].Action != "logout" {
		t.Fatal("session leaked", events)
	}
	if strings.Contains(out.String(), secret) || strings.Contains(errOut.String(), secret) {
		t.Fatal("credential exposed")
	}
}
