//go:build linux && andeiva_native_dhcp_diagnostics

package networkexecutor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNativeLeaseObservationRaceV4ReportsOnlyScalarAssociations(t *testing.T) {
	_, l, _, _ := observationFixtureV4(t, true)
	before := leaseObservationSnapshotV4{epoch: 6, fact: l.fact}
	after := before
	after.epoch++
	after.fact.Sequence++
	r := nativeLeaseObservationRaceRecordForV4(before, after)
	if r.Kind != "unstable_source" || r.BeforeEpoch != 6 || r.AfterEpoch != 7 || r.AfterSequence != r.BeforeSequence+1 || !r.SameOwner || !r.SameTuple || r.BeforeMargin || r.AfterMargin {
		t.Fatal(r)
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 512 || strings.Contains(string(raw), l.fact.Address) || strings.Contains(string(raw), l.fact.DesiredHash) || strings.Contains(string(raw), l.owner.RunID) {
		t.Fatal("race diagnostic exposed authority data")
	}
	after.fact.Owner.PID++
	after.fact.Address = "198.19.0.9/24"
	r = nativeLeaseObservationRaceRecordForV4(before, after)
	if r.SameOwner || r.SameTuple {
		t.Fatal("changed association hidden")
	}
	after = leaseObservationSnapshotV4{epoch: 7, hasMargin: true, margin: LeaseMarginObservationV4{owner: l.owner}}
	r = nativeLeaseObservationRaceRecordForV4(before, after)
	if !r.SameOwner || r.SameTuple || r.BeforeMargin || !r.AfterMargin || r.AfterSequence != 0 {
		t.Fatal("margin hint became grant tuple")
	}
}
