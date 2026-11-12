//go:build linux

package adminapi

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

func runtimeOperationsFixtureV2(t *testing.T, providers ...func(context.Context) (networkinventory.Snapshot, error)) *operationsFixtureV2 {
	f := fixtureOperationsV2(t)
	f.api.server.Close()
	server := httptest.NewUnstartedServer(nil)
	options := Options{Origin: "https://" + server.Listener.Addr().String(), Auth: f.api.auth, FirewallRuleState: true}
	if len(providers) == 1 {
		options.NetworkInventory = providers[0]
	} else if len(providers) > 1 {
		t.Fatal("one inventory authority required")
	}
	h, err := NewOperationsV2(options, f.service)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = h
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.api.server = server
	return f
}
func TestRuntimeOperationsFactoryCurrentAndNoV1Writer(t *testing.T) {
	f := runtimeOperationsFixtureV2(t)
	var first struct {
		SchemaVersion int       `json:"schema_version"`
		Current       CurrentV2 `json:"current"`
	}
	f.call(t, "GET", "/api/v2/config/current", nil, 200, &first)
	if first.SchemaVersion != 2 || first.Current.Global.Generation == 0 || first.Current.Global.Lineage == "" || first.Current.Snapshot.Running.Hash == "" {
		t.Fatal("current not backed by selected configuration")
	}
	ns := f.namespace(t)
	config := configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}}
	var admitted, executed OperationResponseV2
	f.call(t, "POST", operationsV2Path+"/admit", AdmitRequestV2{Namespace: ns.Namespace, Expected: first.Current.Global.Generation, Request: OperationRequestV2{Operation: "stage", Config: &config}}, 201, &admitted)
	f.call(t, "POST", operationsV2Path+"/"+admitted.Operation.ID+"/execute", struct{}{}, 200, &executed)
	var current struct {
		Current CurrentV2 `json:"current"`
	}
	f.call(t, "GET", "/api/v2/config/current", nil, 200, &current)
	if current.Current.Snapshot.Candidate == nil || current.Current.Global.Generation != executed.Current.Global.Generation || current.Current.Snapshot.Candidate.Revision.Hash != executed.Current.Snapshot.Candidate.Revision.Hash {
		t.Fatal("current omitted real staged change")
	}
	before := f.api.backend.calls
	f.call(t, "POST", "/api/v1/firewall/transactions", map[string]string{"operation": "save"}, 409, nil)
	f.call(t, "POST", "/api/v1/local-services/transactions", map[string]string{"operation": "save"}, 409, nil)
	if f.api.backend.calls != before {
		t.Fatal("v1 writer was consulted")
	}
	var capabilities Capabilities
	f.call(t, "GET", "/api/v1/capabilities", nil, 200, &capabilities)
	if !capabilities.ConfigurationOperationsV2 || capabilities.Firewall || len(capabilities.FirewallConfigSchemaVersions) != 1 || capabilities.FirewallConfigSchemaVersions[0] != 4 {
		t.Fatal("incorrect transport capability")
	}
}
func TestRuntimeOperationsFactoryRBACAndCSRF(t *testing.T) {
	f := runtimeOperationsFixtureV2(t)
	f.headers["Authorization"] = "Bearer " + f.tokens["viewer"]
	f.call(t, "GET", "/api/v2/config/current", nil, 200, nil)
	f.call(t, "POST", namespacesV2Path, map[string]string{"domain": "firewall"}, 403, nil)
	f.call(t, "POST", "/api/v1/firewall/transactions", map[string]string{"operation": "save"}, 403, nil)
	status, _, _ := f.api.request(t, "POST", namespacesV2Path, `{"domain":"firewall"}`, map[string]string{"Cookie": cookieName + "=" + f.tokens["alice"], "Content-Type": "application/json", "Origin": f.api.server.URL})
	if status != 403 {
		t.Fatal("missing CSRF accepted", status)
	}
	status, _, _ = f.api.request(t, "GET", "/api/v2/config/current", "", map[string]string{"Authorization": "Bearer " + f.tokens["alice"], "Origin": "https://foreign.invalid"})
	if status != 403 {
		t.Fatal("foreign origin accepted", status)
	}
}
func TestRuntimeOperationsFactoryRejectsMixedAuthority(t *testing.T) {
	f := fixtureOperationsV2(t)
	if _, err := NewOperationsV2(Options{Origin: f.api.server.URL, Auth: f.api.auth, Backend: f.api.backend, Observe: func(context.Context) (Effective, error) { return Effective{}, nil }}, f.service); err == nil {
		t.Fatal("mixed v1/v2 writer accepted")
	}
	other := fixtureServer(t, "admin")
	if _, err := NewOperationsV2(Options{Origin: f.api.server.URL, Auth: other.auth}, f.service); err == nil {
		t.Fatal("unrelated auth authority accepted")
	}
}

func TestRuntimeOperationsCatalogueCloseKeepsLastRunning(t *testing.T) {
	f := runtimeOperationsFixtureV2(t)
	before := make([]string, len(f.engines))
	for i, e := range f.engines {
		before[i] = e.Current()
	}
	if err := f.service.Close(); err != nil {
		t.Fatal(err)
	}
	status, _, _ := f.api.request(t, "GET", "/api/v2/config/current", "", f.headers)
	if status != 503 {
		t.Fatal("closed catalogue did not report unavailable", status)
	}
	for i, e := range f.engines {
		if e.Current() != before[i] {
			t.Fatal("API/store failure removed Running configuration")
		}
	}
}
