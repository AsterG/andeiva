package configpoc

import (
	"testing"
	"time"
)

func TestPendingOriginRejectsDifferentCommitOrDeadline(t *testing.T) {
	deadline := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	pending := v2Confirmation{Domain: "routed", OriginCommit: "commit", Owner: "owner", Lease: "lease", Target: "target", Deadline: deadline}
	origin := v2Operation{
		ID: pending.OriginCommit, Subject: pending.Owner, Domain: pending.Domain,
		State: "final", Pinned: true, Request: v2Request{Kind: OpCommit},
		Outcome: &v2Outcome{Code: "applied_pending_confirmation", ConfirmationLease: pending.Lease, RunningRevision: pending.Target, ConfirmationDeadline: &deadline},
	}
	if !pendingOriginMatchesV2(&pending, origin) {
		t.Fatal("original Commit and deadline rejected")
	}
	for name, change := range map[string]func(*v2Operation){
		"other commit":     func(op *v2Operation) { op.ID = "other" },
		"other owner":      func(op *v2Operation) { op.Subject = "other" },
		"other domain":     func(op *v2Operation) { op.Domain = "firewall" },
		"other operation":  func(op *v2Operation) { op.Request.Kind = OpConfirm },
		"already consumed": func(op *v2Operation) { op.Pinned = false },
		"other lease":      func(op *v2Operation) { op.Outcome.ConfirmationLease = "other" },
		"other revision":   func(op *v2Operation) { op.Outcome.RunningRevision = "other" },
		"expired early":    func(op *v2Operation) { value := deadline.Add(-time.Second); op.Outcome.ConfirmationDeadline = &value },
		"rearmed":          func(op *v2Operation) { value := deadline.Add(time.Second); op.Outcome.ConfirmationDeadline = &value },
	} {
		t.Run(name, func(t *testing.T) {
			bad := clone(origin)
			change(&bad)
			if pendingOriginMatchesV2(&pending, bad) {
				t.Fatal("closing proof accepted a different origin or window")
			}
		})
	}
}
