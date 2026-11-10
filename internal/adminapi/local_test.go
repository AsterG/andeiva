package adminapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localadmin"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type localBackendFixture struct {
	calls   int
	caller  localadmin.Context
	request localadmin.Request
	filter  localadmin.Filter
}

func (b *localBackendFixture) Execute(_ context.Context, c localadmin.Context, r localadmin.Request) (configpoc.Snapshot, error) {
	b.calls++
	b.caller = c
	b.request = r
	return configpoc.Snapshot{}, nil
}
func (b *localBackendFixture) IssueProof(c localadmin.Context, _ localadmin.ProofRequest) (localadmin.Proof, error) {
	b.calls++
	b.caller = c
	return localadmin.Proof{Token: strings.Repeat("ab", 32)}, nil
}
func (b *localBackendFixture) Status(_ context.Context, c localadmin.Context) (localadmin.Status, error) {
	b.calls++
	b.caller = c
	return localadmin.Status{}, nil
}
func (b *localBackendFixture) Effective(_ context.Context, c localadmin.Context, f localadmin.Filter) (localadmin.Effective, error) {
	b.calls++
	b.caller = c
	b.filter = f
	return localadmin.Effective{}, nil
}
func (b *localBackendFixture) History(c localadmin.Context, _ uint64, _ int) ([]configpoc.RevisionEntry, error) {
	b.calls++
	b.caller = c
	return []configpoc.RevisionEntry{}, nil
}
func (b *localBackendFixture) Audit(c localadmin.Context) ([]configpoc.Audit, error) {
	b.calls++
	b.caller = c
	return []configpoc.Audit{}, nil
}

func localServer(t *testing.T, role string) (*fixtureAPI, *localBackendFixture) {
	t.Helper()
	f := &fixtureAPI{secret: strings.Repeat("ab", 32)}
	sum := sha256.Sum256([]byte(f.secret))
	var err error
	f.auth, err = adminauth.New([]adminauth.Account{{Username: "alice", Role: role, CredentialSHA256: hex.EncodeToString(sum[:])}}, func(e adminauth.Event) error { f.events = append(f.events, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewUnstartedServer(nil)
	b := &localBackendFixture{}
	f.server.Config.Handler, err = New(Options{Origin: "https://" + f.server.Listener.Addr().String(), Auth: f.auth, Local: b, LocalEndpointID: "recovery", LocalRecovery: true, LocalInventory: []localpolicy.Interface{{Name: "src0", Zone: localpolicy.LAN, Addresses: []string{"198.18.1.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f, b
}

func TestLocalIdentityComesFromAuthenticatedListener(t *testing.T) {
	f, b := localServer(t, "admin")
	_, token, _ := f.login(t, "cli")
	headers := map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json", "X-ANDEIVA-Client": "cli", "X-Endpoint-ID": "forged", "X-Session-Hash": "forged"}
	status, _, _ := f.request(t, "POST", "/api/v1/local-services/proof", `{"generation":1,"target":"x","lease":"commit"}`, headers)
	if status != 200 || b.caller.EndpointID != "recovery" || b.caller.SessionHash != sessionHash(token) || b.caller.Principal.ID != "alice" || b.caller.Surface != configpoc.CLI {
		t.Fatal(status, b.caller)
	}
	if b.caller.SessionHash == token {
		t.Fatal("raw session exposed to domain")
	}
	status, body, _ := f.request(t, "GET", "/api/v1/capabilities", "", headers)
	var capabilities Capabilities
	if status != 200 || json.Unmarshal([]byte(body), &capabilities) != nil || !capabilities.LocalServices || capabilities.Firewall || !capabilities.RecoveryEndpoint || len(capabilities.LocalInterfaces) != 1 {
		t.Fatal(status, body)
	}
	status, _, _ = f.request(t, "GET", "/api/v1/firewall", "", headers)
	if status != 404 {
		t.Fatal("unconfigured forwarding API exposed", status)
	}
}

func TestLocalDenialsNeverReachBackend(t *testing.T) {
	cases := []struct {
		name, role, path, body string
		want                   int
	}{
		{"viewer-write", "viewer", "/api/v1/local-services/transactions", `{"transaction":{"operation":"stage"}}`, 403},
		{"viewer-proof", "viewer", "/api/v1/local-services/proof", `{}`, 403},
		{"injected-principal", "admin", "/api/v1/local-services/proof", `{"principal":"admin"}`, 400},
		{"injected-endpoint", "admin", "/api/v1/local-services/proof", `{"endpoint_id":"recovery"}`, 400},
		{"duplicate-key", "admin", "/api/v1/local-services/proof", `{"target":"a","Target":"b"}`, 400},
		{"unknown-operation", "admin", "/api/v1/local-services/transactions", `{"transaction":{"operation":"recover"}}`, 400},
		{"status-as-write", "admin", "/api/v1/local-services/transactions", `{"transaction":{"operation":"status"}}`, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, b := localServer(t, tc.role)
			_, token, _ := f.login(t, "cli")
			status, _, _ := f.request(t, "POST", tc.path, tc.body, map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"})
			if status != tc.want || b.calls != 0 {
				t.Fatal(status, b.calls)
			}
		})
	}
}

func TestLocalCookieProofRequiresCSRF(t *testing.T) {
	f, b := localServer(t, "admin")
	id, _, headers := f.login(t, "web")
	cookie := strings.Split(headers.Get("Set-Cookie"), ";")[0]
	status, _, _ := f.request(t, "POST", "/api/v1/local-services/proof", `{}`, map[string]string{"Cookie": cookie, "Content-Type": "application/json", "Origin": f.server.URL})
	if status != 403 || b.calls != 0 {
		t.Fatal("proof bypassed CSRF", status, b.calls)
	}
	status, _, _ = f.request(t, "POST", "/api/v1/local-services/proof", `{}`, map[string]string{"Cookie": cookie, "Content-Type": "application/json", "Origin": f.server.URL, "X-CSRF-Token": id.CSRF})
	if status != 200 || b.calls != 1 {
		t.Fatal(status, b.calls)
	}
}

func TestEffectiveFiltersAreBoundedAndReadOnly(t *testing.T) {
	for _, q := range []string{"port=0", "port=08443", "port=65536", "service=https&service=ssh", "unknown=x", "protocol=", "source=" + strings.Repeat("a", 129)} {
		t.Run(q, func(t *testing.T) {
			f, b := localServer(t, "viewer")
			_, token, _ := f.login(t, "cli")
			status, _, _ := f.request(t, "GET", "/api/v1/effective-policies?"+q, "", map[string]string{"Authorization": "Bearer " + token})
			if status != 400 || b.calls != 0 {
				t.Fatal(status, b.calls)
			}
		})
	}
	f, b := localServer(t, "viewer")
	_, token, _ := f.login(t, "cli")
	status, _, _ := f.request(t, "GET", "/api/v1/effective-policies?service=https&interface=src0&protocol=tcp&port=18443&source=198.18.1.2%2F32", "", map[string]string{"Authorization": "Bearer " + token})
	if status != 200 || b.filter.Port != 18443 || b.filter.Source != "198.18.1.2/32" {
		t.Fatal(status, b.filter)
	}
	status, _, _ = f.request(t, "POST", "/api/v1/effective-policies", `{}`, map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"})
	if status != 403 {
		t.Fatal("effective policies writable", status)
	}
}
