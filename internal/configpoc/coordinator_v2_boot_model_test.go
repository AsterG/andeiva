package configpoc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestV2BootIdentityAndRecoveryDiscriminator(t *testing.T) {
	for _, id := range []v2BootID{"", "00000000-0000-0000-0000-000000000000", "ED012378-aabc-4123-9123-0123456789ab", "../../boot", "ed012378-aabc-4123-9123-0123456789ab\n", "ed012378aabc412391230123456789ab"} {
		if validBootIDV2(id) {
			t.Fatal("invalid boot identity accepted", id)
		}
	}
	id := v2BootID("ed012378-aabc-4123-9123-0123456789ab")
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	record := v2RecoveryRecord{Format: v2Format, ID: "durable-boot", BootID: &id, Kind: v2BootKind, State: "pending", Previous: strings.Repeat("a", 64), Target: strings.Repeat("b", 64), Lineage: "lineage", Started: now, Pinned: true}
	if !validRecoveryRecordV2(record, "lineage") {
		t.Fatal("valid boot record rejected")
	}
	for _, mutate := range []func(*v2RecoveryRecord){func(r *v2RecoveryRecord) { r.Subject = "alice" }, func(r *v2RecoveryRecord) { r.Origin = "fabricated" }, func(r *v2RecoveryRecord) { r.Lease = "fabricated" }, func(r *v2RecoveryRecord) { r.BootID = nil }, func(r *v2RecoveryRecord) { r.Kind = "restart" }} {
		bad := record
		mutate(&bad)
		if validRecoveryRecordV2(bad, "lineage") {
			t.Fatal("ambiguous recovery kind accepted")
		}
	}
	legacy := record
	legacy.BootID = nil
	legacy.Kind = "restart"
	legacy.Subject = "subject"
	legacy.Origin = "origin"
	legacy.Lease = "lease"
	if !validRecoveryRecordV2(legacy, "lineage") {
		t.Fatal("legacy recovery rejected")
	}
	encoded, _ := json.Marshal(legacy)
	if strings.Contains(string(encoded), "boot_id") {
		t.Fatal("nil boot field changes old encoding")
	}
	legacy.Lease = ""
	if validRecoveryRecordV2(legacy, "lineage") {
		t.Fatal("legacy lease requirement weakened")
	}
}

func TestV2BootIntentGolden(t *testing.T) {
	intent := v2CoordinatorIntent{Operation: "operation", Subject: "subject", Domain: "firewall", Kind: OpSave, Previous: strings.Repeat("a", 64), Target: strings.Repeat("b", 64), TargetGeneration: 3}
	encoded, err := json.Marshal(intent)
	want := `{"operation_id":"operation","subject":"subject","domain":"firewall","kind":"save","previous_snapshot":"` + strings.Repeat("a", 64) + `","target_snapshot":"` + strings.Repeat("b", 64) + `","target_generation":"3","recovery":false}`
	if err != nil || string(encoded) != want {
		t.Fatal("old intent golden changed", string(encoded), err)
	}
	for _, features := range [][]string{{"unknown"}, {v2BootFeature, v2BootFeature}, {v2BootFeature, "unknown"}} {
		if validFeaturesV2(v2State{RequiredFeatures: features}) {
			t.Fatal("unknown or repeated feature accepted")
		}
	}
}
