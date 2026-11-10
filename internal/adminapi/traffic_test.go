package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalltraffic"
)

func trafficFixture(t *testing.T, role string) (*fixtureAPI, *Effective, *int) {
	t.Helper()
	f := fixtureServer(t, role)
	revision, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "deny-rule", Action: "deny", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "udp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}})
	if err != nil {
		t.Fatal(err)
	}
	f.backend.snapshot = configpoc.Snapshot{Running: revision, Generation: 7}
	effective := &Effective{Revision: revision.Hash, CounterEpoch: strings.Repeat("a", 32) + ".1", Rules: []RuleCounter{{ID: "deny-rule", Packets: 10, Bytes: 600}}}
	calls := new(int)
	f.server.Config.Handler.(*handler).options.Observe = func(context.Context) (Effective, error) { *calls++; return *effective, nil }
	return f, effective, calls
}
func trafficResponse(t *testing.T, f *fixtureAPI, path, token string) (int, firewalltraffic.Page, string) {
	t.Helper()
	status, body, _ := f.request(t, "GET", path, "", map[string]string{"Authorization": "Bearer " + token})
	var page firewalltraffic.Page
	if status == 200 && json.Unmarshal([]byte(body), &page) != nil {
		t.Fatal("invalid page JSON")
	}
	return status, page, body
}
func TestTrafficAuthorizationAndPaginationBeforeHelper(t *testing.T) {
	for _, role := range []string{"admin", "viewer"} {
		t.Run(role, func(t *testing.T) {
			f, _, calls := trafficFixture(t, role)
			status, _, _ := trafficResponse(t, f, "/api/v1/firewall/traffic", strings.Repeat("b", 64))
			if status != 401 || *calls != 0 || f.backend.calls != 0 {
				t.Fatal("unauthenticated helper access")
			}
			_, token, _ := f.login(t, "cli")
			if role == "viewer" {
				status, _, _ = trafficResponse(t, f, "/api/v1/firewall/traffic", token)
				if status != 403 || *calls != 0 || f.backend.calls != 0 {
					t.Fatal("viewer helper access")
				}
				return
			}
			for _, query := range []string{"limit=101", "before=1", "stream=" + strings.Repeat("a", 32), "before=1&stream=x", "limit=1&limit=2", "x=1", "before=-1"} {
				status, _, _ = trafficResponse(t, f, "/api/v1/firewall/traffic?"+query, token)
				if status != 400 || *calls != 0 || f.backend.calls != 0 {
					t.Fatal("invalid query invoked helper", query, status)
				}
			}
		})
	}
}
func TestTrafficReadbackDeltaAndHistoryPages(t *testing.T) {
	f, e, calls := trafficFixture(t, "admin")
	_, token, _ := f.login(t, "cli")
	status, page, _ := trafficResponse(t, f, "/api/v1/firewall/traffic", token)
	if status != 200 || len(page.Records) != 1 || page.Records[0].Action != "deny" || page.Records[0].Kind != "baseline" {
		t.Fatal(page, status)
	}
	e.Rules[0].Packets += 2
	e.Rules[0].Bytes += 120
	status, page, _ = trafficResponse(t, f, "/api/v1/firewall/traffic?limit=1", token)
	if status != 200 || page.Records[0].PacketsDelta != "2" || page.NextBefore != 2 || *calls != 2 {
		t.Fatal(page, status)
	}
	priorCalls := f.backend.calls
	status, older, _ := trafficResponse(t, f, "/api/v1/firewall/traffic?before=2&stream="+page.Stream, token)
	if status != 200 || len(older.Records) != 1 || older.Records[0].Sequence != 1 || *calls != 2 || f.backend.calls != priorCalls {
		t.Fatal("older page resampled")
	}
	status, _, body := trafficResponse(t, f, "/api/v1/firewall/traffic?before=2&stream="+strings.Repeat("f", 32), token)
	if status != 409 || !strings.Contains(body, "ANDEIVA_TRAFFIC_STREAM_CHANGED") || *calls != 2 {
		t.Fatal("cross-process cursor accepted")
	}
}
func TestTrafficUnverifiedSamplesCannotPublish(t *testing.T) {
	for _, kind := range []string{"revision", "missing-rule", "duplicate-rule", "epoch", "decrease", "error", "recovery", "concurrent"} {
		t.Run(kind, func(t *testing.T) {
			f, e, _ := trafficFixture(t, "admin")
			_, token, _ := f.login(t, "cli")
			status, page, _ := trafficResponse(t, f, "/api/v1/firewall/traffic", token)
			if status != 200 {
				t.Fatal(status)
			}
			switch kind {
			case "revision":
				e.Revision = strings.Repeat("f", 64)
			case "missing-rule":
				e.Rules = nil
			case "duplicate-rule":
				e.Rules = append(e.Rules, e.Rules[0])
			case "epoch":
				e.CounterEpoch = ""
			case "decrease":
				e.Rules[0].Packets--
			case "error":
				f.server.Config.Handler.(*handler).options.Observe = func(context.Context) (Effective, error) { return Effective{}, errors.New("private engine failure") }
			case "recovery":
				f.backend.snapshot.RecoveryRequired = true
			case "concurrent":
				f.server.Config.Handler.(*handler).options.Observe = func(context.Context) (Effective, error) { f.backend.snapshot.Generation++; return *e, nil }
			}
			status, _, body := trafficResponse(t, f, "/api/v1/firewall/traffic", token)
			if status != 503 || strings.Contains(body, "private") {
				t.Fatal("unverified sample published", status, body)
			}
			status, retained, _ := trafficResponse(t, f, "/api/v1/firewall/traffic?before=2&stream="+page.Stream, token)
			if status != 200 || len(retained.Records) != 1 || retained.Records[0].Sequence != 1 {
				t.Fatal("failed sample changed ring")
			}
		})
	}
}
