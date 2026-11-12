//go:build linux

package recoveryreserve

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestPoolV2ClassOrphansNeverBorrowSystemOrClosing(t *testing.T) {
	p, area := preparedV2(t, 18)
	for i := 0; i < 8; i++ {
		c, err := p.ClaimClass(fmt.Sprintf("ordinary-orphan-%d", i), OrdinaryV2)
		if err != nil || c.Slot != i {
			t.Fatal("ordinary partition", c.Slot, err)
		}
	}
	before := snapshotV2(t, area)
	if _, err := p.ClaimClass("overflow-user", OrdinaryV2); !errors.Is(err, ErrFull) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
		t.Fatal("ordinary borrowed capacity", err)
	}
	for i := 0; i < 8; i++ {
		c, err := p.ClaimClass(fmt.Sprintf("closing-orphan-%d", i), ClosingV2)
		if err != nil || c.Slot != 8+i {
			t.Fatal("closing partition", c.Slot, err)
		}
	}
	before = snapshotV2(t, area)
	if _, err := p.ClaimClass("overflow-closing", ClosingV2); !errors.Is(err, ErrFull) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
		t.Fatal("closing borrowed capacity", err)
	}
	for i := 0; i < 2; i++ {
		c, err := p.ClaimClass(fmt.Sprintf("autonomous-%d", i), SystemV2)
		if err != nil || c.Slot != 16+i {
			t.Fatal("system reserve lost", c.Slot, err)
		}
	}
	before = snapshotV2(t, area)
	if _, err := p.ClaimClass("system-full", SystemV2); !errors.Is(err, ErrFull) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
		t.Fatal("system overflow", err)
	}
	if _, err := p.ClaimClass("ordinary-orphan-0", SystemV2); !errors.Is(err, ErrConflict) {
		t.Fatal("owner crossed classes", err)
	}
}

func TestPoolV2PartialOrphanHoldsOnlyItsClassSlot(t *testing.T) {
	p, area := preparedV2(t, 18)
	p.hook = func(point string) error {
		if point == "claim_first_synced" {
			return errors.New("interrupted pre-admission claim")
		}
		return nil
	}
	if _, err := p.ClaimClass("ordinary-partial", OrdinaryV2); err == nil {
		t.Fatal("fault missing")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	p, err = OpenV2(area)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for i := 1; i < 8; i++ {
		c, e := p.ClaimClass(fmt.Sprintf("ordinary-held-%d", i), OrdinaryV2)
		if e != nil || c.Slot != i {
			t.Fatal("held slot was reused or blocked another slot", c.Slot, e)
		}
	}
	if _, err = p.ClaimClass("ordinary-full", OrdinaryV2); !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	if _, err = p.ClaimClass("ordinary-partial", OrdinaryV2); err == nil {
		t.Fatal("partial claim silently repaired")
	}
	if c, e := p.ClaimClass("closing", ClosingV2); e != nil || c.Slot != 8 {
		t.Fatal("closing blocked by user orphan", e)
	}
	if c, e := p.ClaimClass("system-one", SystemV2); e != nil || c.Slot != 16 {
		t.Fatal("system blocked by user orphan", e)
	}
	if c, e := p.ClaimClass("system-two", SystemV2); e != nil || c.Slot != 17 {
		t.Fatal("second system credit lost", e)
	}
}

func TestPoolV2ClassRejectsOtherProfilesAndInvalidClass(t *testing.T) {
	for _, size := range []int{1, 17, 19, 32} {
		p, area := preparedV2(t, size)
		before := snapshotV2(t, area)
		if _, err := p.ClaimClass("owner", SystemV2); !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
			t.Fatal("unqualified partition profile", size, err)
		}
	}
	p, area := preparedV2(t, 18)
	before := snapshotV2(t, area)
	if _, err := p.ClaimClass("owner", ClassV2("0..31")); !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
		t.Fatal("arbitrary range accepted", err)
	}
}

func TestPoolV2ClassConcurrentAdmissionBounded(t *testing.T) {
	p, _ := preparedV2(t, 18)
	var wg sync.WaitGroup
	results := make(chan SlotClaimV2, 32)
	failures := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(owner int) {
			defer wg.Done()
			c, err := p.ClaimClass(fmt.Sprintf("concurrent-%d", owner), OrdinaryV2)
			if err != nil {
				failures <- err
				return
			}
			results <- c
		}(i)
	}
	wg.Wait()
	close(results)
	close(failures)
	seen := map[int]bool{}
	for c := range results {
		if c.Slot < 0 || c.Slot >= 8 || seen[c.Slot] {
			t.Fatal("duplicate or foreign class slot", c.Slot)
		}
		seen[c.Slot] = true
	}
	if len(seen) != 8 {
		t.Fatal("ordinary capacity", len(seen))
	}
	for err := range failures {
		if !errors.Is(err, ErrFull) {
			t.Fatal(err)
		}
	}
	if c, err := p.ClaimClass("autonomous", SystemV2); err != nil || c.Slot != 16 {
		t.Fatal("concurrency consumed system", err)
	}
}
