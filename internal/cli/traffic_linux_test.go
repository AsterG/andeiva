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
	"testing"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/adminauth"
	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalltraffic"
)

type trafficBackend struct {
	snapshot configpoc.Snapshot
	calls    int
}

func (b *trafficBackend) Execute(_ context.Context, p configpoc.Principal, s configpoc.Surface, r configpoc.Request) (configpoc.Snapshot, error) {
	b.calls++
	if p.ID != "alice" || p.Role != configpoc.RoleAdmin || s != configpoc.CLI || r.Operation != configpoc.OpStatus {
		return configpoc.Snapshot{}, configpoc.ErrDenied
	}
	return b.snapshot, nil
}
func (*trafficBackend) History(configpoc.Principal, uint64, int) ([]configpoc.RevisionEntry, error) {
	return nil, configpoc.ErrDenied
}
func (*trafficBackend) Audit(configpoc.Principal) ([]configpoc.Audit, error) {
	return nil, configpoc.ErrDenied
}
func TestTrafficCLIUsesAuthenticatedAPI(t *testing.T) {
	for _, role := range []string{"admin", "viewer"} {
		t.Run(role, func(t *testing.T) {
			secret := strings.Repeat("b", 64)
			digest := sha256.Sum256([]byte(secret))
			events := []adminauth.Event{}
			auth, err := adminauth.New([]adminauth.Account{{Username: "alice", Role: role, CredentialSHA256: hex.EncodeToString(digest[:])}}, func(e adminauth.Event) error { events = append(events, e); return nil })
			if err != nil {
				t.Fatal(err)
			}
			config := configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "web", Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}}
			revision, err := configpoc.Canonical(config)
			if err != nil {
				t.Fatal(err)
			}
			backend := &trafficBackend{snapshot: configpoc.Snapshot{Generation: 3, Running: revision}}
			observations := 0
			packets := ^uint64(0) - 1
			bytesCount := uint64(600)
			server := httptest.NewUnstartedServer(nil)
			handler, err := adminapi.New(adminapi.Options{Origin: "https://" + server.Listener.Addr().String(), Auth: auth, Backend: backend, Observe: func(context.Context) (adminapi.Effective, error) {
				observations++
				return adminapi.Effective{Revision: revision.Hash, CounterEpoch: strings.Repeat("a", 32) + ".1", Rules: []adminapi.RuleCounter{{ID: "web", Packets: packets, Bytes: bytesCount}}}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = handler
			server.StartTLS()
			defer server.Close()
			dir := t.TempDir()
			ca, credentials := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "credentials.json")
			if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(credentials, []byte(fmt.Sprintf(`{"username":"alice","credential":%q}`, secret)), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"firewall", "traf", "--url", server.URL, "--ca-file", ca, "--credentials-file", credentials, "--limit", "1"}
			var out, errOut bytes.Buffer
			code := RunInput(args, nil, &out, &errOut)
			if role == "viewer" {
				if code != 2 || observations != 0 || backend.calls != 0 || !strings.Contains(errOut.String(), "ANDEIVA_CONFIG_DENIED") {
					t.Fatal("viewer sampled traffic", code, errOut.String())
				}
				if events[len(events)-1].Action != "logout" {
					t.Fatal("viewer session leaked")
				}
				return
			}
			var page firewalltraffic.Page
			if code != 0 || json.Unmarshal(out.Bytes(), &page) != nil || len(page.Records) != 1 || page.Records[0].Kind != "baseline" || page.Records[0].PacketsTotal != "18446744073709551614" {
				t.Fatal(code, out.String(), errOut.String())
			}
			out.Reset()
			errOut.Reset()
			packets++
			bytesCount += 60
			if code = RunInput(args, nil, &out, &errOut); code != 0 || json.Unmarshal(out.Bytes(), &page) != nil || page.Records[0].PacketsDelta != "1" || page.Records[0].PacketsTotal != "18446744073709551615" || page.NextBefore != 2 {
				t.Fatal("CLI delta differs from API", code, out.String(), errOut.String())
			}
			out.Reset()
			errOut.Reset()
			args = append(args, "--before", "2", "--stream", page.Stream)
			if code = RunInput(args, nil, &out, &errOut); code != 0 || json.Unmarshal(out.Bytes(), &page) != nil || page.Records[0].Kind != "baseline" || observations != 2 {
				t.Fatal("CLI history resampled", code, out.String(), errOut.String())
			}
			if len(events) != 6 || events[5].Action != "logout" {
				t.Fatal("traffic session leaked")
			}
		})
	}
}
