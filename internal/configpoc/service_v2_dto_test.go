package configpoc

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestOperationDTOv2PreservesPublicContractAndIsolation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seconds := uint64(60)
	op := v2Operation{ID: "operation", Namespace: "namespace", Subject: "subject", Lineage: "lineage", Domain: "firewall", Sequence: 1, Expected: 2, Request: v2Request{Kind: OpCommit, ConfirmSeconds: &seconds}, Fingerprint: "fingerprint", State: "final", Accepted: now, ExecuteBefore: now.Add(time.Minute), Completed: &now, RetainUntil: &now, Outcome: &v2Outcome{Code: "verified", Generation: 3, AuditHash: "audit", DomainGeneration: 4, RunningRevision: "running", StartupRevision: "startup", ConfirmationDeadline: &now, ConfirmationLease: "lease", AuditFirst: 1, AuditLast: 2}, Pinned: true}
	public := operationDTOv2(op)
	before, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("public contract changed: %s != %s", before, after)
	}
	*public.Request.ConfirmSeconds = 30
	*public.Completed = now.Add(time.Hour)
	*public.Outcome.ConfirmationDeadline = now.Add(time.Hour)
	if *op.Request.ConfirmSeconds != 60 || !op.Completed.Equal(now) || !op.Outcome.ConfirmationDeadline.Equal(now) {
		t.Fatal("public projection aliases durable operation")
	}
}

func TestNamespaceDTOv2IsolatedOpenMembership(t *testing.T) {
	ns := v2Namespace{ID: "namespace", Subject: "subject", Domain: "firewall", Open: []string{"operation"}}
	public := namespaceDTOv2(ns)
	public.Open[0] = "foreign"
	if ns.Open[0] != "operation" {
		t.Fatal("public namespace aliases canonical membership")
	}
}
