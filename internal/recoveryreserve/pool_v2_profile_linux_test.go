//go:build linux

package recoveryreserve

import (
	"bytes"
	"testing"
)

func TestPoolV2ProfileDoesNotClaimCapacity(t *testing.T) {
	p, area := preparedV2(t, 18)
	before, err := area.ReadFile("pool.json")
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		profile, err := p.Profile()
		if err != nil || profile.ID == "" || profile.Role != PlanV2 || profile.Slots != 18 || profile.Capacity != 4096 {
			t.Fatalf("wrong profile: %+v %v", profile, err)
		}
	}
	for i := 0; i < 8; i++ {
		if _, err := p.ClaimClass(string(rune('a'+i)), OrdinaryV2); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.ClaimClass("ninth", OrdinaryV2); err != ErrFull {
		t.Fatalf("wrong capacity: %v", err)
	}
	after, err := area.ReadFile("pool.json")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("profile changed manifest")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Profile(); err != ErrUnavailable {
		t.Fatal("closed pool exposed profile")
	}
	var missing *PoolV2
	if _, err := missing.Profile(); err != ErrUnavailable {
		t.Fatal("nil pool exposed profile")
	}
}
