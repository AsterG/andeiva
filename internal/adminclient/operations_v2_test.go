package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/configpoc"
)

// These are client wire-contract fixtures, not a real-store/engine integration.
// The prepared adminapi qualification tests cover real stores with SimEngine.
func wireFixtureV2(t *testing.T) (adminapi.OperationResponseV2, adminapi.NamespaceResponseV2) {
	t.Helper()
	revision, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	until := now.Add(time.Hour)
	ns := adminapi.NamespaceResponseV2{SchemaVersion: 2, Namespace: "v2.ns.1.fixture", State: "open", AdmitUntil: until}
	response := adminapi.OperationResponseV2{SchemaVersion: 2, Operation: adminapi.OperationV2{ID: "v2.op.1.fixture", Namespace: ns.Namespace, Domain: "firewall", Kind: "validate", State: "accepted", Expected: 1, Fingerprint: strings.Repeat("b", 64), Accepted: now, ExecuteBefore: until}, Current: adminapi.CurrentV2{Global: adminapi.GlobalV2{Lineage: "fixture-lineage", Generation: 1, Running: strings.Repeat("a", 64), Startup: strings.Repeat("a", 64)}, Domain: "firewall", Snapshot: adminapi.SnapshotV2{Generation: 17, Running: revision, Startup: revision, LastGood: revision, Revoked: []string{}}}}
	return response, ns
}
func TestOperationsV2ClientRecognizesVerifiedNoEffectFinality(t *testing.T) {
	for code, reason := range map[string]string{"profile_changed_without_effects": "ANDEIVA_RESERVE_PROFILE_CHANGED", "confirmation_resolved_without_effects": "ANDEIVA_CONFIRMATION_RESOLVED"} {
		t.Run(code, func(t *testing.T) {
			response, _ := wireFixtureV2(t)
			op := response.Operation
			now, until := time.Now().UTC(), time.Now().UTC().Add(30*24*time.Hour)
			op.State, op.Completed, op.RetainUntil = "final", &now, &until
			op.Outcome = &adminapi.OutcomeV2{Code: code, ErrorCode: reason}
			if !validOperationV2(op) {
				t.Fatal("verified no-effect finality refused")
			}
			op.Outcome.ErrorCode = "ANDEIVA_UNRELATED"
			if validOperationV2(op) {
				t.Fatal("mismatched finality reason accepted")
			}
			op.Outcome.ErrorCode, op.State = reason, "pending"
			if validOperationV2(op) {
				t.Fatal("unfinished operation advertised no effects")
			}
		})
	}
}

func TestOperationsV2ClientRecognizesOnlyGroupedCandidateOperations(t *testing.T) {
	response, _ := wireFixtureV2(t)
	for _, kind := range []string{configpoc.OpReplaceCandidate, configpoc.OpDiscardCandidate} {
		op := response.Operation
		op.Kind, op.Domain = kind, "routed"
		if !validOperationV2(op) {
			t.Fatal("grouped operation rejected", kind)
		}
		op.Domain = "firewall"
		if validOperationV2(op) {
			t.Fatal("group operation accepted as legacy writer", kind)
		}
	}
}
func TestOperationsV2ClientWireLifecycle(t *testing.T) {
	op, ns := wireFixtureV2(t)
	calls := 0
	c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.TLS == nil || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) || r.Header.Get("X-ANDEIVA-Client") != "cli" {
			t.Error("transport authority missing")
		}
		switch r.URL.Path {
		case namespacesPathV2:
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(ns)
		case operationsPathV2 + "/admit":
			var request adminapi.AdmitRequestV2
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Request.Operation != "validate" || request.Expected != 1 {
				t.Error("admit wire changed")
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(op)
		case operationsPathV2 + "/" + op.Operation.ID + "/execute":
			if r.Method != "POST" {
				t.Error("execute method")
			}
			_ = json.NewEncoder(w).Encode(op)
		case operationsPathV2 + "/" + op.Operation.ID:
			_ = json.NewEncoder(w).Encode(op)
		case operationsPathV2:
			if r.URL.Query().Get("namespace_id") != ns.Namespace || r.URL.Query().Get("cursor") != "0" {
				t.Error("list filters lost")
			}
			_ = json.NewEncoder(w).Encode(adminapi.OperationPageV2{SchemaVersion: 2, Operations: []adminapi.OperationV2{}, NextCursor: 0, Current: op.Current})
		case namespacesPathV2 + "/" + ns.Namespace + "/close":
			_ = json.NewEncoder(w).Encode(adminapi.NamespaceClosedV2{SchemaVersion: 2, Namespace: ns.Namespace, State: "closed"})
		default:
			t.Error("unexpected route", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	c.token = strings.Repeat("a", 64)
	ctx := context.Background()
	if _, err := c.NamespaceV2(ctx, "firewall"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AdmitV2(ctx, adminapi.AdmitRequestV2{Namespace: ns.Namespace, Expected: 1, Request: adminapi.OperationRequestV2{Operation: "validate"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecuteV2(ctx, op.Operation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.OperationV2(ctx, op.Operation.ID); err != nil {
		t.Fatal(err)
	}
	page, err := c.OperationsV2(ctx, ns.Namespace, "", 0, 10)
	if err != nil || page.Current.Global.Generation != 1 || page.Current.Snapshot.Generation != 17 {
		t.Fatal("empty-list global/projection lost", err)
	}
	if _, err := c.CloseNamespaceV2(ctx, ns.Namespace); err != nil {
		t.Fatal(err)
	}
	if calls != 6 {
		t.Fatal("unexpected retries/fallback", calls)
	}
}
func TestOperationsV2ClientRejectsMalformedResponsesAndIDs(t *testing.T) {
	op, _ := wireFixtureV2(t)
	valid, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"numeric_global":     strings.Replace(string(valid), `"generation":"1"`, `"generation":1`, 1),
		"numeric_projection": strings.Replace(string(valid), `"generation":"17"`, `"generation":17`, 1),
		"leading_zero":       strings.Replace(string(valid), `"generation":"1"`, `"generation":"01"`, 1),
		"unknown":            strings.TrimSuffix(string(valid), "}") + `,"unknown":true}`,
		"duplicate":          strings.Replace(string(valid), `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1),
		"foreign_id":         strings.Replace(string(valid), op.Operation.ID, "v2.op.2.foreign", 1),
		"overflow":           strings.Replace(string(valid), `"generation":"1"`, `"generation":"18446744073709551616"`, 1),
		"trailing":           string(valid) + `{}`,
		"oversized":          strings.Repeat(" ", 1024*1024+1),
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			c.token = strings.Repeat("a", 64)
			if _, err := c.OperationV2(context.Background(), op.Operation.ID); !errors.Is(err, ErrResponse) {
				t.Fatal("malformed response accepted", err)
			}
		})
	}
	c, _ := trustedClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid ID sent to network") }))
	c.token = strings.Repeat("a", 64)
	for _, id := range []string{"../etc/passwd", "x/y", "x?subject=alice", strings.Repeat("a", 129), ""} {
		if _, err := c.OperationV2(context.Background(), id); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid ID accepted", err)
		}
	}
}
func TestOperationsV2ClientNoSilentDowngrade(t *testing.T) {
	calls := 0
	c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(APIError{Code: "ANDEIVA_OPERATION_NOT_FOUND", RequestID: strings.Repeat("b", 32)})
	}))
	c.token = strings.Repeat("a", 64)
	_, err := c.OperationV2(context.Background(), "v2.op.1.unknown")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "ANDEIVA_OPERATION_NOT_FOUND" || calls != 1 {
		t.Fatal("v2 silently downgraded/retried", err, calls)
	}
}

func TestOperationsV2ClientCorrelatesAdmissionAndCandidatePending(t *testing.T) {
	for name, mutate := range map[string]func(*adminapi.OperationResponseV2){
		"wrong_kind":  func(op *adminapi.OperationResponseV2) { op.Operation.Kind = "save" },
		"wrong_state": func(op *adminapi.OperationResponseV2) { op.Operation.State = "pending" },
		"candidate_hash": func(op *adminapi.OperationResponseV2) {
			op.Current.Snapshot.Candidate = &configpoc.Candidate{Owner: "subject", Base: op.Current.Snapshot.Running.Hash, Revision: op.Current.Snapshot.Running}
			op.Current.Snapshot.Candidate.Revision.Hash = strings.Repeat("f", 64)
		},
		"malformed_candidate_base": func(op *adminapi.OperationResponseV2) {
			op.Current.Snapshot.Candidate = &configpoc.Candidate{Owner: "subject", Base: "not-a-revision", Revision: op.Current.Snapshot.Running}
		},
		"pending_previous": func(op *adminapi.OperationResponseV2) {
			op.Current.Snapshot.Pending = &configpoc.Pending{Owner: "subject", Lease: "v2.lease.1.fixture", Previous: op.Current.Snapshot.Running, Deadline: time.Now().UTC().Add(time.Minute)}
			op.Current.Snapshot.Pending.Previous.Hash = strings.Repeat("f", 64)
		},
		"pending_lease": func(op *adminapi.OperationResponseV2) {
			op.Current.Snapshot.Pending = &configpoc.Pending{Owner: "subject", Previous: op.Current.Snapshot.Running, Deadline: time.Now().UTC().Add(time.Minute)}
		},
		"pending_deadline": func(op *adminapi.OperationResponseV2) {
			op.Current.Snapshot.Pending = &configpoc.Pending{Owner: "subject", Lease: "v2.lease.1.fixture", Previous: op.Current.Snapshot.Running}
		},
	} {
		t.Run(name, func(t *testing.T) {
			op, ns := wireFixtureV2(t)
			mutate(&op)
			c, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(201)
				_ = json.NewEncoder(w).Encode(op)
			}))
			c.token = strings.Repeat("a", 64)
			if _, err := c.AdmitV2(context.Background(), adminapi.AdmitRequestV2{Namespace: ns.Namespace, Expected: 1, Request: adminapi.OperationRequestV2{Operation: "validate"}}); !errors.Is(err, ErrResponse) {
				t.Fatal("uncorrelated/malformed admission accepted", err)
			}
		})
	}
}
