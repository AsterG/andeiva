//go:build linux

package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func reachabilityBudgetV2() v2ReachabilityBudget {
	return v2ReachabilityBudget{Entries: 20000, Objects: 16000, Edges: 200000, IOCalls: 2000000, Bytes: 256 << 20, ActiveBytes: 16 << 20, Depth: 128}
}

func TestV2ReachabilityRealStoreReadOnly(t *testing.T) {
	for _, kind := range []string{"prepared", "stage", "commit", "confirmed"} {
		t.Run(kind, func(t *testing.T) {
			c, area, engines, p, _ := coordinatorV2Fixture(t, false)
			if kind != "prepared" {
				coordinatorV2Stage(t, c, p, "inspection")
				if kind != "stage" {
					seconds := uint64(0)
					if kind == "confirmed" {
						seconds = 30
					}
					coordinatorV2Run(t, c, p, v2Request{Kind: OpCommit, ConfirmSeconds: &seconds})
				}
			}
			c.close()
			if err := c.store.close(); err != nil {
				t.Fatal(err)
			}
			before := journalFiles(t, area.Name())
			for _, engine := range engines {
				engine.reset()
			}
			report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
			if err != nil || !report.Complete || report.Objects == 0 || report.BytesRead == 0 || report.Sequence != c.store.selection.Sequence {
				t.Fatal("incomplete known closure", report, err)
			}
			if !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("inspection changed store")
			}
			if _, err := area.Stat("."); err != nil {
				t.Fatal("caller root closed")
			}
			for _, engine := range engines {
				if engine.applies.Load() != 0 {
					t.Fatal("inspection applied engine")
				}
			}
		})
	}
}

func TestV2ReachabilityBudgetFailureNeverComplete(t *testing.T) {
	c, area, _, _, _ := coordinatorV2Fixture(t, false)
	c.close()
	_ = c.store.close()
	for _, field := range []string{"entries", "objects", "edges", "io", "bytes", "active", "depth"} {
		t.Run(field, func(t *testing.T) {
			budget := reachabilityBudgetV2()
			switch field {
			case "entries":
				budget.Entries = 1
			case "objects":
				budget.Objects = 1
			case "edges":
				budget.Edges = 1
			case "io":
				budget.IOCalls = 1
			case "bytes":
				budget.Bytes = 1
			case "active":
				budget.ActiveBytes = 1
			case "depth":
				budget.Depth = 1
			}
			before := journalFiles(t, area.Name())
			report, err := inspectReachabilityV2(context.Background(), area, budget)
			if err == nil || report.Complete {
				t.Fatal("budget produced complete report", report)
			}
			if !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("budget failure mutated store")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := inspectReachabilityV2(ctx, area, reachabilityBudgetV2())
	if !errors.Is(err, context.Canceled) || report.Complete {
		t.Fatal("cancel accepted", err)
	}
}

func TestV2ReachabilityLockMissingAndBusy(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	before := journalFiles(t, area.Name())
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if !errors.Is(err, ErrLocked) || report.Complete || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
		t.Fatal("busy inspector", err)
	}
	_ = s.close()
	if err := area.Remove("checkpoint.lock"); err != nil {
		t.Fatal(err)
	}
	before = journalFiles(t, area.Name())
	report, err = inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err == nil || report.Complete || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
		t.Fatal("missing lock recreated", err)
	}
}

func TestV2ReachabilityOpaqueAuditDoesNotInferHash(t *testing.T) {
	s, area, now, subject := v2Fixture(t, 64)
	ns, err := s.namespace(subject, "firewall", now, 60000000000)
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.admit(subject, ns.ID, 1, v2Request{Kind: OpSave}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.begin(subject, op.ID, now); err != nil {
		t.Fatal(err)
	}
	audit, _ := json.Marshal(map[string]string{"fingerprint": strings.Repeat("a", 64), "not_a_path": "../../foreign"})
	if _, err = s.finish(subject, op.ID, v2Outcome{Code: "applied", Generation: 1}, audit, now, false); err != nil {
		t.Fatal(err)
	}
	semanticName, _ := v2ObjectName(op.Fingerprint)
	if _, err := area.Lstat(semanticName); !os.IsNotExist(err) {
		t.Fatal("fingerprint must not name an object", err)
	}
	_ = s.close()
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete || report.OpaqueAuditObjects == 0 {
		t.Fatal("opaque semantic fields treated as paths", report, err)
	}
}

func TestV2ReachabilityEdgeContextAndSelectorPair(t *testing.T) {
	for _, kind := range []string{"radix-prefix", "selector-previous"} {
		t.Run(kind, func(t *testing.T) {
			s, area, now, subject := v2Fixture(t, 64)
			ns, err := s.namespace(subject, "firewall", now, 60000000000)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.admit(subject, ns.ID, 1, v2Request{Kind: OpSave}, now); err != nil {
				t.Fatal(err)
			}
			if kind == "radix-prefix" {
				var root, middle, leaf v2Page
				if err := s.readObject(s.state.Index, &root); err != nil {
					t.Fatal(err)
				}
				if err := s.readObject(root.Refs[0], &middle); err != nil {
					t.Fatal(err)
				}
				if err := s.readObject(middle.Refs[0], &leaf); err != nil {
					t.Fatal(err)
				}
				// The same valid bytes are reached under another radix prefix. A
				// cache hit must not bypass the second edge's position constraint.
				leaf.Refs[1] = leaf.Refs[0]
				leafHash, err := s.object(leaf)
				if err != nil {
					t.Fatal(err)
				}
				middle.Refs[0] = leafHash
				middleHash, err := s.object(middle)
				if err != nil {
					t.Fatal(err)
				}
				root.Refs[0] = middleHash
				rootHash, err := s.object(root)
				if err != nil {
					t.Fatal(err)
				}
				st := clone(s.state)
				st.Index = rootHash
				if err := s.publish(st); err != nil {
					t.Fatal(err)
				}
			} else {
				selector := s.selector
				selector.Previous = ""
				data, _ := json.Marshal(selector)
				if err := area.WriteFile("selected.json", data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_ = s.close()
			before := journalFiles(t, area.Name())
			report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
			if err == nil || report.Complete || !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
				t.Fatal("wrong edge context accepted", report, err)
			}
		})
	}
}

func TestV2ReachabilityExistingLockIdentityPinned(t *testing.T) {
	s, area, _, _ := v2Fixture(t, 64)
	_ = s.close()
	r := &v2ReachabilityReader{ctx: context.Background(), area: area, budget: reachabilityBudgetV2()}
	lock, root, err := r.lockExisting()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	r.root = root
	if err := area.Rename("checkpoint.lock", "test-owned-old-lock"); err != nil {
		t.Fatal(err)
	}
	if err := area.WriteFile("checkpoint.lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.verifyScope(lock); err == nil {
		t.Fatal("same-byte replacement lock accepted")
	}
}

func TestV2ReachabilityRejectsForeignAndMalformed(t *testing.T) {
	for _, kind := range []string{"foreign", "symlink", "mode", "missing", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			c, area, _, _, _ := coordinatorV2Fixture(t, false)
			c.close()
			_ = c.store.close()
			name, _ := v2ObjectName(c.store.selection.State)
			switch kind {
			case "foreign":
				if err := area.WriteFile("foreign", []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := area.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := area.Symlink("/etc/passwd", name); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := area.Chmod(name, 0644); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := area.Remove(name); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := area.WriteFile(name, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
			if err == nil || report.Complete {
				t.Fatal("unknown graph accepted", report, err)
			}
		})
	}
}

func TestV2ReachabilityMigrationReadSeamBounded(t *testing.T) {
	c, _, _, _, _ := coordinatorV2Fixture(t, false)
	if validateMigrationReadV2(c.store.state, nil) == nil {
		t.Fatal("nil reader accepted")
	}
	for _, stop := range []error{errV2InspectionBudget, context.Canceled} {
		calls := 0
		err := validateMigrationReadV2(c.store.state, func(hash string, target any) error {
			calls++
			if calls == 2 {
				return stop
			}
			return c.store.readObject(hash, target)
		})
		if err == nil || calls != 2 {
			t.Fatal("migration bypassed supplied reader", calls, err)
		}
	}
}

func TestV2ReachabilityMigrationRecordsUseBoundedReader(t *testing.T) {
	c, area, _, _, _ := coordinatorV2Fixture(t, false)
	state := clone(c.store.state)
	c.close()
	_ = c.store.close()
	before := journalFiles(t, area.Name())
	budget := reachabilityBudgetV2()
	// The manifest consumes the only object allowance. The wrapped legacy
	// record must traverse the same reader and stop before another read.
	budget.Objects = 1
	r := &v2ReachabilityReader{ctx: context.Background(), area: area, budget: budget, objects: map[string]bool{}, edges: map[string]uint8{}}
	lock, root, err := r.lockExisting()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	r.root = root
	if err := r.state("migration-fixture", state, 0); !errors.Is(err, errV2InspectionBudget) || r.report.Objects != 1 {
		t.Fatal("legacy record escaped bounded reader", r.report, err)
	}
	if !reflect.DeepEqual(before, journalFiles(t, area.Name())) {
		t.Fatal("inspection changed migration files")
	}
}

func TestV2ReachabilityVerifiedSeamPreservesBlocked(t *testing.T) {
	c, _, _, _, _ := coordinatorV2Fixture(t, false)
	node := v2VerifiedNode{Format: v2Format, Depth: 0, Kind: "leaf", Entries: []v2VerifiedEntry{{Revision: strings.Repeat("a", 64), Audit: strings.Repeat("b", 64), Operation: "operation"}}}
	if !validVerifiedNodeV2(node, 0, "") || validVerifiedNodeV2(node, 1, "f") {
		t.Fatal("prefix validator")
	}
	node.Children[0] = strings.Repeat("c", 64)
	hash, err := c.store.object(node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.verifiedNode(hash, 0, ""); err == nil || !c.store.blocked {
		t.Fatal("old wrapper lost blocked semantics")
	}
}

func TestV2ReachabilityInvalidArguments(t *testing.T) {
	if report, err := inspectReachabilityV2(nil, nil, v2ReachabilityBudget{}); err == nil || report.Complete {
		t.Fatal("zero arguments accepted")
	}
	var _ *os.Root
}

func TestV2ReachabilityBootRecoveryKeyIsNotObject(t *testing.T) {
	c, area, _, _ := bootFixtureV2(t)
	booted, err := reopenBootV2(t, c, area, ptrBootV2(testBootIDV2), nil)
	if err != nil {
		t.Fatal(err)
	}
	var record v2RecoveryRecord
	if err := booted.store.readObject(booted.store.state.Configuration.LastCompletedBoot, &record); err != nil {
		t.Fatal(err)
	}
	semanticName, _ := v2ObjectName(checkpointDigest([]byte(record.ID)))
	if _, err := area.Lstat(semanticName); !os.IsNotExist(err) {
		t.Fatal("fixture must not have an object for recovery semantic key", err)
	}
	booted.close()
	_ = booted.store.close()
	report, err := inspectReachabilityV2(context.Background(), area, reachabilityBudgetV2())
	if err != nil || !report.Complete {
		t.Fatal("recovery key inferred as object", report, err)
	}
}
