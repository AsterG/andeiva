//go:build linux

package configpoc

import (
	"errors"
	"testing"
)

func TestRoutedConntrackCleanupIsBoundToOneProtectedAuditRecord(t *testing.T) {
	c, _, _, _ := bootFixtureV2(t)
	source := c.store.state.Configuration
	if source == nil {
		t.Fatal("missing audit source")
	}
	for _, tc := range []struct {
		name, operation, origin, kind, result, subject string
		cleanup                                        []RoutedConntrackCleanupV1
		want                                           bool
	}{
		{name: "commit cleanup", operation: "commit-a", origin: "commit-a", kind: OpCommit,
			result: "applied_pending_confirmation", subject: "operator",
			cleanup: []RoutedConntrackCleanupV1{{Operation: "commit-a", Retired: 128, Partial: true}}, want: true},
		{name: "timeout cleanup", operation: "timeout-a", origin: "commit-a", kind: "timeout",
			result: "reverted", subject: "system",
			cleanup: []RoutedConntrackCleanupV1{{Operation: "timeout-a", Retired: 0, Partial: true}}, want: true},
		{name: "foreign result", operation: "commit-a", origin: "commit-a", kind: OpCommit,
			result: "applied_pending_confirmation", subject: "operator", cleanup: []RoutedConntrackCleanupV1{{Operation: "commit-b"}}},
		{name: "over limit", operation: "commit-a", origin: "commit-a", kind: OpCommit,
			result: "applied_pending_confirmation", subject: "operator", cleanup: []RoutedConntrackCleanupV1{{Operation: "commit-a", Retired: 129}}},
		{name: "duplicate results", operation: "commit-a", origin: "commit-a", kind: OpCommit,
			result: "applied_pending_confirmation", subject: "operator", cleanup: []RoutedConntrackCleanupV1{{Operation: "commit-a"}, {Operation: "commit-a"}}},
		{name: "confirm has no cleanup", operation: "confirm-a", origin: "commit-a", kind: OpConfirm,
			result: "applied", subject: "operator", cleanup: []RoutedConntrackCleanupV1{{Operation: "confirm-a"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := clone(*source)
			hash, err := c.appendAuditLocked(&target, tc.operation, tc.origin, "lease-a", tc.subject, tc.kind,
				tc.result, c.store.state.Generation, c.recoveryNow(), tc.cleanup...)
			if !tc.want {
				if !errors.Is(err, ErrRecovery) || hash != "" || target.AuditTip != source.AuditTip || target.AuditSequence != source.AuditSequence {
					t.Fatal("invalid cleanup advanced audit state", err)
				}
				return
			}
			var record v2CoordinatorAudit
			if err != nil || c.store.readObject(hash, &record) != nil || !validActionAuditShapeV2(record) ||
				record.Cleanup == nil || record.Cleanup.Retired != tc.cleanup[0].Retired || record.Cleanup.Partial != tc.cleanup[0].Partial ||
				target.AuditSequence != source.AuditSequence+1 || record.Previous != source.AuditTip || target.AuditTip != hash {
				t.Fatal("cleanup did not produce exactly one bounded audit record", err)
			}
		})
	}
}
