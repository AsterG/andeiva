//go:build linux

package configpoc

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCoordinatorV2VerifiedIndexColdSplitAndPrefixCollisions(t *testing.T) {
	c, _, _, _, _ := coordinatorV2Fixture(t, false)
	initial := c.store.state.Configuration.VerifiedIndex
	root := initial
	witness := c.store.state.Configuration.AuditTip
	for i := 0; i < 200; i++ {
		entry := v2VerifiedEntry{Revision: checkpointDigest([]byte(fmt.Sprintf("index-key-%d", i))), Audit: witness, Operation: "index-codec-fixture"}
		var err error
		root, err = c.verifiedInsert(root, 0, entry)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 200; i++ {
		key := checkpointDigest([]byte(fmt.Sprintf("index-key-%d", i)))
		entry, known, err := c.verifiedLookup(root, key)
		if err != nil || !known || entry.Revision != key {
			t.Fatal("cold exact split lookup", i, err)
		}
		if _, known, err = c.verifiedLookup(initial, key); err != nil || known {
			t.Fatal("COW insertion mutated old root", err)
		}
	}
	// This is an index/codec fixture, not a fabricated engine verification:
	// synthetic keys are never selected as configuration or used by Apply.
	root = ""
	for i := 0; i < 64; i++ {
		key := strings.Repeat("a", 16) + fmt.Sprintf("%048x", i)
		var err error
		root, err = c.verifiedInsert(root, 0, v2VerifiedEntry{Revision: key, Audit: witness, Operation: "collision-codec-fixture"})
		if err != nil {
			t.Fatal(err)
		}
	}
	retained := root
	key := strings.Repeat("a", 16) + fmt.Sprintf("%048x", 64)
	if _, err := c.verifiedInsert(root, 0, v2VerifiedEntry{Revision: key, Audit: witness, Operation: "collision-codec-fixture"}); !errors.Is(err, errV2Limited) {
		t.Fatal("bounded collision bucket silently exceeded", err)
	}
	if _, known, err := c.verifiedLookup(retained, key); err != nil || known {
		t.Fatal("failed insertion authorized missing full hash", err)
	}
}
