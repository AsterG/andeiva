//go:build linux

package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type operationsFixtureV2 struct {
	api        *fixtureAPI
	service    *configpoc.ServiceV2
	headers    map[string]string
	identities map[string]adminauth.Identity
	tokens     map[string]string
	engines    []*configpoc.SimEngine
	retired    string
}

func fixtureOperationsV2(t *testing.T) *operationsFixtureV2 {
	t.Helper()
	ctx := context.Background()
	f := &operationsFixtureV2{identities: map[string]adminauth.Identity{}, tokens: map[string]string{}}
	roots := make([]*os.Root, 3)
	for i := range roots {
		path := t.TempDir()
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		roots[i] = root
		t.Cleanup(func() { _ = root.Close() })
	}
	iface := localpolicy.Interface{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"192.0.2.1"}}
	management, err := localpolicy.DefaultManagement("management", "https", iface, "192.0.2.1", []string{"192.0.2.10/32"})
	if err != nil {
		t.Fatal(err)
	}
	configs := []configpoc.Config{{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}}, {SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{iface}, Services: []localpolicy.Service{management}}}}
	var expected [2]configpoc.LegacyFingerprintV2
	for i, domain := range []string{"firewall", "local_services"} {
		engine := configpoc.NewSimEngine(fmt.Sprintf("qualification-%d", i))
		legacy, err := configpoc.Open(roots[i].Name(), []configpoc.Engine{engine}, configpoc.Options{Initial: &configs[i]})
		if err != nil {
			t.Fatal(err)
		}
		if err = legacy.Close(); err != nil {
			t.Fatal(err)
		}
		f.engines = append(f.engines, engine)
		expected[i], err = configpoc.InspectLegacyV2(roots[i], domain)
		if err != nil {
			t.Fatal(err)
		}
	}
	var subjects []configpoc.SubjectV2
	var accounts []adminauth.Account
	var credentials []string
	for _, name := range []string{"alice", "bob", "viewer"} {
		id, err := configpoc.NewSubjectIDV2()
		if err != nil {
			t.Fatal(err)
		}
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		credential := hex.EncodeToString(raw[:])
		digest := sha256.Sum256([]byte(credential))
		revision := sha256.Sum256([]byte("explicit-binding-" + name))
		role := "admin"
		if name == "viewer" {
			role = "viewer"
		}
		subjects = append(subjects, configpoc.SubjectV2{ID: id, Login: name, CredentialRevision: hex.EncodeToString(revision[:])})
		accounts = append(accounts, adminauth.Account{Username: name, Role: role, CredentialSHA256: hex.EncodeToString(digest[:]), SubjectID: id, CredentialRevision: hex.EncodeToString(revision[:])})
		credentials = append(credentials, credential)
	}
	f.retired, err = configpoc.NewSubjectIDV2()
	if err != nil {
		t.Fatal(err)
	}
	subjects = append(subjects, configpoc.SubjectV2{ID: f.retired, Login: "retired-account", CredentialRevision: strings.Repeat("e", 64), Retired: true})
	bindings := []configpoc.LegacyBindingV2{{Source: expected[0].Source, Actor: "alice", Subject: subjects[0].ID, ReceiptIndex: expected[0].ReceiptIndex}, {Source: expected[1].Source, Actor: "alice", Subject: subjects[0].ID, ReceiptIndex: expected[1].ReceiptIndex}}
	budget := configpoc.BudgetV2{Bytes: 8 << 30, Inodes: 2 << 20}
	if err := configpoc.PrepareMigrationV2(roots[2], roots[0], roots[1], expected, subjects, bindings, budget, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	auth, err := adminauth.New(accounts, func(adminauth.Event) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = configpoc.OpenServiceV2(ctx, roots[2], budget, auth, []configpoc.Engine{f.engines[0]}, []configpoc.Engine{f.engines[1]})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.service.Close() })
	for i, account := range accounts {
		id, token, err := auth.Login(account.Username, credentials[i])
		if err != nil {
			t.Fatal(err)
		}
		f.identities[account.Username] = id
		f.tokens[account.Username] = token
	}
	f.api = &fixtureAPI{auth: auth, backend: &fakeBackend{}}
	f.api.server = httptest.NewUnstartedServer(nil)
	origin := "https://" + f.api.server.Listener.Addr().String()
	h, err := newPreparedOperationsHandler(Options{Origin: origin, Auth: auth, Backend: f.api.backend, Observe: func(context.Context) (Effective, error) { return Effective{}, nil }}, f.service)
	if err != nil {
		t.Fatal(err)
	}
	f.api.server.Config.Handler = h
	f.api.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	f.api.server.StartTLS()
	t.Cleanup(f.api.server.Close)
	f.headers = map[string]string{"Authorization": "Bearer " + f.tokens["alice"], "Content-Type": "application/json", "X-ANDEIVA-Client": "cli"}
	return f
}
func (f *operationsFixtureV2) call(t *testing.T, method, path string, body any, status int, out any) {
	t.Helper()
	data := []byte{}
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	actual, response, _ := f.api.request(t, method, path, string(data), f.headers)
	if actual != status {
		t.Fatalf("%s %s: status %d expected %d: %s", method, path, actual, status, response)
	}
	if out != nil && json.Unmarshal([]byte(response), out) != nil {
		t.Fatal("invalid response")
	}
}
func (f *operationsFixtureV2) namespace(t *testing.T) NamespaceResponseV2 {
	t.Helper()
	var ns NamespaceResponseV2
	f.call(t, "POST", namespacesV2Path, map[string]string{"domain": "firewall"}, 201, &ns)
	return ns
}
func (f *operationsFixtureV2) page(t *testing.T, ns string) OperationPageV2 {
	t.Helper()
	var page OperationPageV2
	f.call(t, "GET", operationsV2Path+"?namespace_id="+url.QueryEscape(ns), nil, 200, &page)
	return page
}
func TestPreparedOperationsV2RealStoreTLSLifecycle(t *testing.T) {
	f := fixtureOperationsV2(t)
	ns := f.namespace(t)
	if again := f.namespace(t); again.Namespace != ns.Namespace {
		t.Fatal("lost namespace response duplicated namespace")
	}
	page := f.page(t, ns.Namespace)
	if page.SchemaVersion != 2 || len(page.Operations) != 0 || page.Current.Global.Generation != 1 || page.Current.Global.Lineage == "" || page.Current.Snapshot.Generation < 1 {
		t.Fatal("empty list missing authoritative current")
	}
	if len(page.Current.Snapshot.Revoked) != 1 || page.Current.Snapshot.Revoked[0] != f.retired {
		t.Fatal("retired subject IDs omitted from current")
	}
	initial := page.Current
	run := func(request OperationRequestV2) OperationResponseV2 {
		t.Helper()
		current := f.page(t, ns.Namespace).Current
		var admitted OperationResponseV2
		f.call(t, "POST", operationsV2Path+"/admit", AdmitRequestV2{Namespace: ns.Namespace, Expected: current.Global.Generation, Request: request}, 201, &admitted)
		if admitted.Operation.State != "accepted" || admitted.Current.Global.Generation != current.Global.Generation {
			t.Fatal("admission changed configuration")
		}
		var executed OperationResponseV2
		f.call(t, "POST", operationsV2Path+"/"+admitted.Operation.ID+"/execute", struct{}{}, 200, &executed)
		return executed
	}
	on := true
	config := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "tls-created", Action: "allow", Enabled: &on, Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}}
	run(OperationRequestV2{Operation: "stage", Config: &config})
	run(OperationRequestV2{Operation: "validate"})
	seconds := DecimalV2(30)
	commit := run(OperationRequestV2{Operation: "commit", ConfirmSeconds: &seconds})
	if commit.Operation.Outcome.Code != "applied_pending_confirmation" || f.engines[0].Current() != commit.Current.Snapshot.Running.Hash {
		t.Fatal("simulated engine not applied")
	}
	if commit.Current.Global.Running == commit.Current.Snapshot.Running.Hash {
		t.Fatal("global/domain revisions collapsed")
	}
	run(OperationRequestV2{Operation: "confirm", Target: commit.Current.Global.Running, Origin: commit.Operation.ID})
	run(OperationRequestV2{Operation: "save"})
	run(OperationRequestV2{Operation: "rollback", Target: initial.Global.Running})
	var replay OperationResponseV2
	f.call(t, "POST", operationsV2Path+"/"+commit.Operation.ID+"/execute", struct{}{}, 200, &replay)
	if replay.Operation.Outcome.GlobalGeneration != commit.Operation.Outcome.GlobalGeneration || replay.Current.Global.Generation <= commit.Current.Global.Generation {
		t.Fatal("historical/current result confused")
	}
	if replay.Current.Snapshot.Running.Hash != initial.Snapshot.Running.Hash {
		t.Fatal("rollback not effective in simulator")
	}
	f.call(t, "POST", namespacesV2Path+"/"+ns.Namespace+"/close", struct{}{}, 200, nil)
	f.call(t, "POST", namespacesV2Path+"/"+ns.Namespace+"/close", struct{}{}, 200, nil)
	f.call(t, "POST", operationsV2Path+"/admit", AdmitRequestV2{Namespace: ns.Namespace, Expected: replay.Current.Global.Generation, Request: OperationRequestV2{Operation: "validate"}}, 410, nil)
	if f.api.backend.calls != 0 {
		t.Fatal("v2 routed through legacy executor")
	}
	status, body, _ := f.api.request(t, "GET", "/api/v1/capabilities", "", f.headers)
	if status != 200 || strings.Contains(body, "configuration_operations") {
		t.Fatal("prepared API advertised capability")
	}
}

func TestPreparedOperationsV2BoundariesRBACAndForeignIDs(t *testing.T) {
	f := fixtureOperationsV2(t)
	ns := f.namespace(t)
	current := f.page(t, ns.Namespace).Current
	for _, body := range []string{
		`{"namespace_id":"` + ns.Namespace + `","expected_generation":1,"request":{"operation":"validate"}}`,
		`{"namespace_id":"` + ns.Namespace + `","expected_generation":"01","request":{"operation":"validate"}}`,
		`{"namespace_id":"` + ns.Namespace + `","expected_generation":"18446744073709551616","request":{"operation":"validate"}}`,
		`{"domain":"firewall","domain":"firewall"}`, `{"Domain":"firewall"}`, `{"domain":"firewall","subject":"forged"}`, `null`, `{} {}`, strings.Repeat(" ", operationV2Limit+1),
	} {
		path := namespacesV2Path
		if strings.Contains(body, "namespace_id") {
			path = operationsV2Path + "/admit"
		}
		status, _, _ := f.api.request(t, "POST", path, body, f.headers)
		if status != 400 {
			t.Fatalf("invalid request status: %d", status)
		}
	}
	var accepted OperationResponseV2
	f.call(t, "POST", operationsV2Path+"/admit", AdmitRequestV2{Namespace: ns.Namespace, Expected: current.Global.Generation, Request: OperationRequestV2{Operation: "validate"}}, 201, &accepted)
	f.call(t, "POST", operationsV2Path+"/admit", AdmitRequestV2{Namespace: ns.Namespace, Expected: current.Global.Generation, Request: OperationRequestV2{Operation: "revoke", Subject: f.identities["bob"].SubjectID}}, 400, nil)
	if got := f.page(t, ns.Namespace); len(got.Operations) != 1 {
		t.Fatal("unimplemented revoke consumed an operation")
	}
	for _, name := range []string{"bob", "viewer"} {
		headers := map[string]string{"Authorization": "Bearer " + f.tokens[name], "Content-Type": "application/json"}
		want := 404
		if name == "viewer" {
			want = 403
		}
		status, _, _ := f.api.request(t, "GET", operationsV2Path+"/"+accepted.Operation.ID, "", headers)
		if status != want {
			t.Fatal("ownership/RBAC", name, status)
		}
	}
	for _, query := range []string{"namespace_id=" + ns.Namespace + "&limit=0", "namespace_id=" + ns.Namespace + "&cursor=01", "namespace_id=" + ns.Namespace + "&state=other", "namespace_id=" + ns.Namespace + "&limit=1&limit=2", "namespace_id=" + ns.Namespace + "&subject=bob"} {
		status, body, _ := f.api.request(t, "GET", operationsV2Path+"?"+query, "", f.headers)
		if status != 400 {
			t.Fatal("invalid filters", status)
		}
		var failure struct {
			Code string `json:"code"`
		}
		if json.Unmarshal([]byte(body), &failure) != nil || failure.Code != "ANDEIVA_OPERATION_INVALID" {
			t.Fatal("inconsistent malformed query error", query, body)
		}
	}
	cookieHeaders := map[string]string{"Cookie": cookieName + "=" + f.tokens["alice"], "Content-Type": "application/json", "Origin": f.api.server.URL}
	status, _, _ := f.api.request(t, "POST", namespacesV2Path, `{"domain":"firewall"}`, cookieHeaders)
	if status != 403 {
		t.Fatal("missing CSRF accepted")
	}
	cookieHeaders["X-CSRF-Token"] = f.identities["alice"].CSRF
	status, _, _ = f.api.request(t, "POST", namespacesV2Path, `{"domain":"firewall"}`, cookieHeaders)
	if status != 201 {
		t.Fatal("valid cookie CSRF denied", status)
	}
	if err := f.api.auth.Logout(f.tokens["alice"]); err != nil {
		t.Fatal(err)
	}
	status, _, _ = f.api.request(t, "POST", operationsV2Path+"/"+accepted.Operation.ID+"/execute", `{}`, f.headers)
	if status != 401 {
		t.Fatal("logout not enforced", status)
	}
}

func TestPreparedOperationsV2AtomicEmptyPagesUnderConcurrency(t *testing.T) {
	f := fixtureOperationsV2(t)
	ns := f.namespace(t)
	var wg sync.WaitGroup
	defer wg.Wait()
	for range 6 {
		wg.Go(func() {
			for range 8 {
				page := f.page(t, ns.Namespace)
				if page.Current.Domain != "firewall" || page.Current.Global.Generation == 0 || page.Current.Snapshot.Generation == 0 {
					t.Error("inconsistent envelope")
				}
			}
		})
	}
	for range 5 {
		current := f.page(t, ns.Namespace).Current
		var op OperationResponseV2
		f.call(t, "POST", operationsV2Path+"/admit", AdmitRequestV2{Namespace: ns.Namespace, Expected: current.Global.Generation, Request: OperationRequestV2{Operation: "save"}}, 201, &op)
		f.call(t, "POST", operationsV2Path+"/"+op.Operation.ID+"/execute", struct{}{}, 200, nil)
	}
	wg.Wait()
}

func TestOperationsV2ProductionRouterStaysDisabled(t *testing.T) {
	f := fixtureServer(t, "admin")
	status, _, _ := f.request(t, "POST", namespacesV2Path, `{"domain":"firewall"}`, map[string]string{"Content-Type": "application/json"})
	if status != 401 {
		t.Fatal("unauthenticated request bypassed middleware")
	}
	_, token, err := f.auth.Login("alice", f.secret)
	if err != nil {
		t.Fatal(err)
	}
	status, _, _ = f.request(t, "POST", namespacesV2Path, `{"domain":"firewall"}`, map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"})
	if status != 404 {
		t.Fatal("production v2 router activated", status)
	}
}

func TestPreparedOperationsV2CannotBypassSecurityMiddleware(t *testing.T) {
	f := fixtureOperationsV2(t)
	h := f.api.server.Config.Handler
	request := httptest.NewRequest("POST", "http://"+strings.TrimPrefix(f.api.server.URL, "https://")+namespacesV2Path, strings.NewReader(`{"domain":"firewall"}`))
	request.Header.Set("Authorization", f.headers["Authorization"])
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("cleartext accepted", response.Code)
	}
	badOrigin := map[string]string{"Authorization": f.headers["Authorization"], "Content-Type": "application/json", "Origin": "https://attacker.invalid"}
	status, _, _ := f.api.request(t, "POST", namespacesV2Path, `{"domain":"firewall"}`, badOrigin)
	if status != 403 {
		t.Fatal("cross-origin accepted", status)
	}
	spoof := map[string]string{"Content-Type": "application/json", "X-Forwarded-User": "alice", "X-Forwarded-Subject": f.identities["alice"].SubjectID, "X-Forwarded-Proto": "https"}
	status, _, _ = f.api.request(t, "POST", namespacesV2Path, `{"domain":"firewall"}`, spoof)
	if status != 401 {
		t.Fatal("forwarded identity accepted", status)
	}
	var ns NamespaceResponseV2
	f.call(t, "POST", namespacesV2Path, map[string]string{"domain": "firewall"}, 201, &ns)
	unknownSurface := map[string]string{"Authorization": f.headers["Authorization"], "X-ANDEIVA-Client": "privileged", "Content-Type": "application/json"}
	status, _, _ = f.api.request(t, "GET", operationsV2Path+"?namespace_id="+ns.Namespace, "", unknownSurface)
	if status != 400 {
		t.Fatal("unknown surface accepted", status)
	}
}
