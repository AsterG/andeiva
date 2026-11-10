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
	runningHash := strings.Repeat("c", 64)
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
				received = configpoc.Request{}
				if json.NewDecoder(r.Body).Decode(&received) != nil {
					t.Error("invalid transaction")
				}
				if received.Operation == "confirm" && received.Target != runningHash {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = fmt.Fprintf(w, `{"code":"ANDEIVA_CONFIG_INVALID","request_id":%q}`, strings.Repeat("a", 32))
					return
				}
			}
			_, _ = fmt.Fprintf(w, `{"snapshot":{"generation":7,"running":{"hash":%q}},"effective":{"state":"verified","rules":[]}}`, runningHash)
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
	out.Reset()
	errOut.Reset()
	args = []string{"firewall", "conf", "--url", s.URL, "--ca-file", ca, "--credentials-file", credential}
	if code := RunInput(args, nil, &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	if calls != 2 || received.Operation != "confirm" || received.Target != runningHash || received.ExpectedGeneration != 7 {
		t.Fatal("confirmation did not bind the observed revision", received)
	}
	if len(events) != 4 || events[3].Action != "logout" {
		t.Fatal("confirmation session leaked")
	}
	out.Reset()
	errOut.Reset()
	explicitTarget := strings.Repeat("d", 64)
	explicitArgs := append(append([]string{}, args...), "--target", explicitTarget)
	if code := RunInput(explicitArgs, nil, &out, &errOut); code != 2 || calls != 3 || received.Target != explicitTarget || out.Len() != 0 || !strings.Contains(errOut.String(), "ANDEIVA_CONFIG_INVALID") {
		t.Fatal("explicit confirmation target was rejected locally or replaced", received, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	explicitArgs[len(explicitArgs)-1] = runningHash
	if code := RunInput(explicitArgs, nil, &out, &errOut); code != 0 || calls != 4 || received.Target != runningHash {
		t.Fatal("matching explicit confirmation target failed", received, errOut.String())
	}
	if len(events) != 8 || events[5].Action != "logout" || events[7].Action != "logout" {
		t.Fatal("explicit confirmation session leaked")
	}
}
