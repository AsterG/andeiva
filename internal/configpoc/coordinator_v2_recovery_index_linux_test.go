//go:build linux

package configpoc

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestCoordinatorV2RecoveryLookupRetainsExactOldResultsWithoutRenewal(t *testing.T) {
	c, _, _, p, now := coordinatorV2Fixture(t, false)
	var first v2RecoveryRecord
	for i, id := range []string{"first-recovery", "second-recovery"} {
		coordinatorV2Stage(t, c, p, id)
		seconds := uint64(30)
		coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
		*now = now.Add(31 * time.Second)
		if err := c.tick(context.Background(), *now); err != nil {
			t.Fatal(err)
		}
		record, err := c.recoveryStatus()
		if err != nil || record.State != "final" || record.Pinned || record.RetainUntil == nil {
			t.Fatal("recovery final metadata", err)
		}
		if i == 0 {
			first = record
		}
	}
	old, err := c.lookupRecovery(p.Subject, first.ID)
	if err != nil || !reflect.DeepEqual(first, old) {
		t.Fatal("old recovery lost after next recovery", err)
	}
	if recoveryDetailEligibleV2(old, old.Completed.Add(29*24*time.Hour)) || !recoveryDetailEligibleV2(old, old.Completed.Add(31*24*time.Hour)) {
		t.Fatal("retention window changed")
	}
	*now = now.Add(31 * 24 * time.Hour)
	old, err = c.lookupRecovery(p.Subject, first.ID)
	if err != nil || !reflect.DeepEqual(first, old) {
		t.Fatal("lookup renewed/mutated retention", err)
	}
	other, err := c.store.changeSubject("", "other", checkpointDigest([]byte("other credential revision")), false, *now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.lookupRecovery(other.ID, first.ID); !errors.Is(err, errV2NotFound) {
		t.Fatal("foreign recovery was exposed", err)
	}
	if _, err = c.lookupRecovery(p.Subject, first.ID+"x"); !errors.Is(err, errV2NotFound) {
		t.Fatal("unknown recovery created/guessed", err)
	}
}
