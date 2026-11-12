//go:build linux

package configpoc

import (
	"context"
	"testing"
)

func TestReserveArchiveV2ReachabilityValidatesArchiveOnlyAudit(t *testing.T) {
	for _, mode := range []string{"complete", "missing", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			c, area, _, p, _ := coordinatorV2Fixture(t, false)
			attachReserveManagerV2(t, c)
			first := coordinatorV2Stage(t, c, p, "first")
			second := coordinatorV2Stage(t, c, p, "second")
			archive, found, err := c.store.reserveArchiveBundleLookupV2(c.store.state.ReserveArchiveRoot, v2ReserveArchiveEntry{Claim: first.Operation.Reserve.Claims.Admission}, "claim")
			if err != nil || !found {
				t.Fatalf("fixture archive: %t %v", found, err)
			}
			var facts v2ReserveFinality
			if err := c.store.readObject(archive.FinalWork, &facts); err != nil {
				t.Fatal(err)
			}
			if mode == "missing" {
				name, err := v2ObjectName(archive.Audit)
				if err != nil {
					t.Fatal(err)
				}
				if err := area.Remove(name); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign" {
				var origin v2Operation
				if err := c.store.readObject(facts.Origin.Object, &origin); err != nil {
					t.Fatal(err)
				}
				origin.Outcome.AuditHash = second.Operation.Outcome.AuditHash
				archive.Audit = origin.Outcome.AuditHash
				facts.Origin.Object, err = c.store.object(origin)
				if err != nil {
					t.Fatal(err)
				}
				archive.FinalWork, err = c.store.object(facts)
				if err != nil {
					t.Fatal(err)
				}
			}
			// Hash-consistent finality alone does not validate the audit object.
			if err := validateArchiveFinalityV2(archive, c.store.state, c.store.readObject); err != nil {
				t.Fatalf("precondition: %v", err)
			}
			hash, err := c.store.object(archive)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := reserveArchiveBundleRefV2(archive.Lineage, first.Operation.Reserve.Scope.Bundle, hash)
			if err != nil {
				t.Fatal(err)
			}
			rootInfo, err := area.Stat(".")
			if err != nil {
				t.Fatal(err)
			}
			reader := &v2ReachabilityReader{ctx: context.Background(), area: area, root: rootInfo, budget: reachabilityBudgetV2(), objects: map[string]bool{}, edges: map[string]uint8{}}
			// Trace only the archived closure: no current catalogue or AuditTip can
			// accidentally cover the missing or foreign edge in this regression.
			err = reader.reserveArchiveObject(ref, "archive-only", c.store.state, 0)
			if mode == "complete" && err != nil {
				t.Fatalf("valid archived closure: %v", err)
			}
			if mode != "complete" && err == nil {
				t.Fatal("invalid archived audit accepted")
			}
		})
	}
}
