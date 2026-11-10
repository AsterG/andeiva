//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
)

type ruleStateBackend struct{ core *configpoc.Service }

func (b ruleStateBackend) Execute(ctx context.Context, p configpoc.Principal, s configpoc.Surface, r configpoc.Request) (configpoc.Snapshot, error) {
	return b.core.Execute(ctx, p, s, r)
}
func (b ruleStateBackend) History(p configpoc.Principal, before uint64, limit int) ([]configpoc.RevisionEntry, error) {
	return b.core.Revisions(p, before, limit)
}
func (b ruleStateBackend) Audit(p configpoc.Principal) ([]configpoc.Audit, error) {
	return b.core.History(p)
}

func TestRuleStateCLIStagesExactJSONThroughAuthenticatedAPI(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(fmt.Sprint(supported), func(t *testing.T) {
			dir := t.TempDir()
			engine := configpoc.NewSimEngine("state-test")
			core, err := configpoc.Open(filepath.Join(dir, "state"), []configpoc.Engine{engine}, configpoc.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			secret := strings.Repeat("b", 64)
			digest := sha256.Sum256([]byte(secret))
			var logouts atomic.Int32
			auth, err := adminauth.New([]adminauth.Account{{Username: "alice", Role: "admin", CredentialSHA256: hex.EncodeToString(digest[:])}}, func(e adminauth.Event) error {
				if e.Action == "logout" {
					logouts.Add(1)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(nil)
			handler, err := adminapi.New(adminapi.Options{FirewallRuleState: supported, Origin: "https://" + server.Listener.Addr().String(), Auth: auth, Backend: ruleStateBackend{core}, Observe: func(context.Context) (adminapi.Effective, error) { return adminapi.Effective{}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = handler
			server.StartTLS()
			defer server.Close()
			ca, credentials := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "credentials.json")
			if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(credentials, []byte(fmt.Sprintf(`{"username":"alice","credential":%q}`, secret)), 0600); err != nil {
				t.Fatal(err)
			}
			request := `{"operation":"stage","key":"cli-disabled","expected_generation":1,"config":{"schema_version":4,"default_action":"deny","rules":[{"id":"off","action":"allow","match":{"source":"198.18.0.2/32","destination":"198.18.0.6/32","protocol":"tcp","source_ports":{"from":1,"to":65535},"destination_ports":{"from":18080,"to":18080}},"enabled":false}]}}`
			baseline, e := core.Execute(context.Background(), configpoc.Principal{ID: "alice", Role: configpoc.RoleAdmin}, configpoc.CLI, configpoc.Request{Operation: configpoc.OpStatus})
			if e != nil {
				t.Fatal(e)
			}
			request = strings.Replace(request, `"expected_generation":1`, fmt.Sprintf(`"expected_generation":%d`, baseline.Generation), 1)
			args := []string{"firewall", "stage", "--url", server.URL, "--ca-file", ca, "--credentials-file", credentials, "--request-file", "-"}
			var out, errOut bytes.Buffer
			code := RunInput(args, strings.NewReader(request), &out, &errOut)
			if logouts.Load() != 1 {
				t.Fatal("capability negotiation leaked session")
			}
			if !supported {
				if code != 2 || out.Len() != 0 {
					t.Fatal("unsupported schema was admitted")
				}
				return
			}
			var response adminapi.State
			if code != 0 || json.Unmarshal(out.Bytes(), &response) != nil || response.Snapshot.Candidate == nil {
				t.Fatal("CLI stage failed", code, errOut.String())
			}
			rule := response.Snapshot.Candidate.Revision.Config.Rules[0]
			if rule.Enabled == nil || *rule.Enabled || response.Snapshot.Running.Config.SchemaVersion != 1 {
				t.Fatal("stage lost explicit disabled state or changed Running")
			}
			for _, bad := range []string{strings.Replace(request, `"enabled":false`, `"enabled":false,"Enabled":true`, 1), strings.Replace(request, `"enabled":false`, `"enabled":null`, 1), strings.Replace(request, `"protocol":"tcp"`, `"protocol":"invalid"`, 1)} {
				out.Reset()
				errOut.Reset()
				if RunInput(args, strings.NewReader(bad), &out, &errOut) != 2 || out.Len() != 0 {
					t.Fatal("ambiguous or invalid inactive rule accepted")
				}
			}
			if logouts.Load() != 1 {
				t.Fatal("invalid input reached authentication")
			}
		})
	}
}
