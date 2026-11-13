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
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/routednft"
)

// Wire fixtures exercise the real CLI/TLS client, not nftables or a real store.
func TestConfigurationCLIUsesDurableIDsWithoutRetryingUncertainExecution(t *testing.T) {
	firewall, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	local, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := configpoc.NewRoutedActivationBundleV1(firewall, local)
	if err != nil {
		t.Fatal(err)
	}
	current := adminapi.CurrentV2{
		Domain: "routed", Global: adminapi.GlobalV2{Lineage: "selected-lineage", Generation: adminapi.DecimalV2(^uint64(0)), Running: bundle.Composite.Hash, Startup: bundle.Composite.Hash},
		DomainGenerations: &adminapi.DomainGenerationsV2{Firewall: 2, Network: 2, LocalServices: 3},
		Snapshot:          adminapi.SnapshotV2{Generation: 2, Running: firewall, Startup: firewall, LastGood: firewall, Revoked: []string{}},
		Routed:            &adminapi.RoutedCurrentV2{SchemaVersion: 7, Running: bundle.Composite, Startup: bundle.Composite, LastGood: bundle.Composite, LocalServices: adminapi.SnapshotV2{Generation: 3, Running: local, Startup: local, LastGood: local, Revoked: []string{}}},
	}
	for _, scenario := range []string{"status", "stage", "stage4", "replace-candidate", "replace-routed", "discard-candidate", "validate", "commit", "operation", "uncertain", "audit"} {
		t.Run(scenario, func(t *testing.T) {
			secret, token := strings.Repeat("b", 64), strings.Repeat("a", 64)
			now := time.Now().UTC()
			kind := scenario
			if scenario == "uncertain" || scenario == "operation" {
				kind = "validate"
			}
			if scenario == "stage4" {
				kind = "stage"
			}
			if scenario == "replace-candidate" || scenario == "replace-routed" {
				kind = configpoc.OpReplaceCandidate
			}
			if scenario == "discard-candidate" {
				kind = configpoc.OpDiscardCandidate
			}
			response := adminapi.OperationResponseV2{SchemaVersion: 2, Current: current, Operation: adminapi.OperationV2{ID: "v2.op.1.accepted", Namespace: "v2.ns.1.accepted", Domain: "routed", Kind: kind, State: "accepted", Expected: current.Global.Generation, Fingerprint: strings.Repeat("c", 64), Accepted: now, ExecuteBefore: now.Add(time.Minute)}}
			var paths []string
			var mu sync.Mutex
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				paths = append(paths, r.URL.Path)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.TLS == nil || r.Header.Get("X-ANDEIVA-Client") != "cli" {
					t.Error("transport identity missing")
				}
				if r.URL.Path != "/api/v1/auth/login" && r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("authentication missing")
				}
				switch r.URL.Path {
				case "/api/v1/auth/login":
					_, _ = fmt.Fprintf(w, `{"username":"alice","role":"admin","token":%q}`, token)
				case "/api/v1/auth/logout":
					_, _ = w.Write([]byte(`{"logged_out":true}`))
				case "/api/v2/config/audit":
					if r.URL.Query().Get("limit") != "50" || r.URL.Query().Get("before") != "0" {
						t.Error("audit bounds missing")
					}
					_ = json.NewEncoder(w).Encode(configpoc.AuditPageV2{SchemaVersion: 1, Events: []configpoc.AuditEventV2{}})
				case "/api/v2/config/current":
					_ = json.NewEncoder(w).Encode(struct {
						Schema  int                `json:"schema_version"`
						Current adminapi.CurrentV2 `json:"current"`
					}{2, current})
				case "/api/v2/config/operation-namespaces":
					var body struct {
						Domain string `json:"domain"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Domain != "routed" {
						t.Error("incorrect operation domain")
					}
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(adminapi.NamespaceResponseV2{SchemaVersion: 2, Namespace: response.Operation.Namespace, State: "open", AdmitUntil: now.Add(time.Hour)})
				case "/api/v2/config/operations/admit":
					var body adminapi.AdmitRequestV2
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Expected != current.Global.Generation || body.Request.Operation != kind || body.Namespace != response.Operation.Namespace {
						t.Error("lost generation or operation binding")
					}
					if kind == "commit" && (body.Request.ConfirmSeconds == nil || *body.Request.ConfirmSeconds != 60) {
						t.Error("commit confirmation missing")
					}
					if kind == configpoc.OpReplaceCandidate || kind == configpoc.OpDiscardCandidate {
						if body.Request.ExpectedCandidateStage != "v2.op.1.stage" {
							t.Error("explicit candidate identity lost")
						}
					}
					if scenario == "stage4" || scenario == "replace-candidate" {
						if body.Request.Config == nil || body.Request.Config.SchemaVersion != 4 || body.Request.Config.Routed != nil {
							t.Error("policy4 acquired a fabricated network plan")
						}
					}
					if scenario == "stage" || scenario == "replace-routed" {
						if body.Request.Config == nil || body.Request.Config.Routed == nil {
							t.Error("routed payload missing")
						} else {
							canonical, err := configpoc.CanonicalRouted(*body.Request.Config)
							if err != nil || canonical.Config.Routed.Network.Hash != routednft.LabPolicy().Network.Hash {
								t.Error("nested network identity was not derived from typed data")
							}
						}
					}
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(response)
				case "/api/v2/config/operations/v2.op.1.accepted/execute":
					if scenario == "uncertain" {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = fmt.Fprintf(w, `{"code":"ANDEIVA_CONFIG_RECOVERY_REQUIRED","request_id":%q}`, strings.Repeat("d", 32))
					} else {
						completed, until := now.Add(time.Second), now.Add(24*time.Hour)
						response.Operation.State, response.Operation.Completed, response.Operation.RetainUntil = "final", &completed, &until
						response.Operation.Outcome = &adminapi.OutcomeV2{Code: "applied", GlobalGeneration: current.Global.Generation}
						_ = json.NewEncoder(w).Encode(response)
					}
				case "/api/v2/config/operations/v2.op.1.accepted":
					_ = json.NewEncoder(w).Encode(response)
				case "/api/v2/config/operation-namespaces/v2.ns.1.accepted/close":
					_ = json.NewEncoder(w).Encode(adminapi.NamespaceClosedV2{SchemaVersion: 2, Namespace: response.Operation.Namespace, State: "closed"})
				default:
					t.Error("unexpected or downgraded endpoint", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			dir := t.TempDir()
			ca, credentials := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "credentials.json")
			if os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600) != nil || os.WriteFile(credentials, []byte(fmt.Sprintf(`{"username":"alice","credential":%q}`, secret)), 0600) != nil {
				t.Fatal("fixture files")
			}
			command := scenario
			if scenario == "uncertain" {
				command = "validate"
			}
			if scenario == "stage4" {
				command = "stage"
			}
			if scenario == "replace-routed" {
				command = "replace-candidate"
			}
			args := []string{"configuration", command, "--url", server.URL, "--ca-file", ca, "--credentials-file", credentials}
			if command == "operation" {
				args = append(args, "--operation-id", response.Operation.ID)
			}
			var out, errOut bytes.Buffer
			var input *strings.Reader
			if command == "replace-candidate" || command == "discard-candidate" {
				args = append(args, "--expected-candidate-stage", "v2.op.1.stage")
			}
			if command == "stage" || command == "replace-candidate" {
				policy := routednft.LabPolicy()
				policy.Network.Hash = strings.Repeat("0", 64)
				config := &configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy}
				if scenario == "stage4" || scenario == "replace-candidate" {
					config = &configpoc.Config{SchemaVersion: 4, DefaultAction: "deny"}
				}
				data, err := json.Marshal(adminapi.OperationRequestV2{Operation: kind, Config: config})
				if err != nil {
					t.Fatal(err)
				}
				input = strings.NewReader(string(data))
				args = append(args, "--request-file", "-")
			}
			code := RunInput(args, input, &out, &errOut)
			if scenario == "uncertain" {
				if code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "ANDEIVA_OPERATION_ACCEPTED: v2.op.1.accepted") {
					t.Fatal("uncertain execution lost its durable ID")
				}
			} else if scenario == "audit" {
				if code != 0 || !strings.Contains(out.String(), `"events":[]`) {
					t.Fatal("audit query failed", out.String(), errOut.String())
				}
			} else if code != 0 || !strings.Contains(out.String(), `"18446744073709551615"`) {
				t.Fatal("v2 CLI lost selected generation", out.String(), errOut.String())
			}
			mu.Lock()
			defer mu.Unlock()
			if paths[len(paths)-1] != "/api/v1/auth/logout" {
				t.Fatal("session not closed")
			}
			if scenario == "audit" && (len(paths) != 3 || paths[1] != "/api/v2/config/audit") {
				t.Fatal("audit query issued configuration writes", paths)
			}
			count := 0
			for _, path := range paths {
				if strings.HasSuffix(path, "/execute") {
					count++
				}
			}
			if count > 1 {
				t.Fatal("uncertain write retried")
			}
			if strings.Contains(out.String()+errOut.String(), token) || strings.Contains(out.String()+errOut.String(), secret) {
				t.Fatal("credentials exposed")
			}
		})
	}
}
