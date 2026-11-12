//go:build linux

package recoveryreserve

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func preparedV2(t *testing.T, n int) (*PoolV2, *os.Root) {
	t.Helper()
	area, _ := areaFor(t)
	p, err := PrepareV2(area, n, 4096, PlanV2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, area
}

func scopeForV2(owner string) ScopeV2 {
	return ScopeV2{Kind: "operation", Lineage: "v2.lineage.1.example", Bundle: owner, Operation: "v2.op.1.example", Namespace: "v2.ns.1.example", Subject: "subject-incarnation", Domain: "firewall", Fingerprint: digest([]byte("request")), Global: 1, Generation: 1}
}
func proofForV2(scope ScopeV2) RetirementProofV2 {
	finality := "operation_final"
	work := scope.Operation
	if scope.Kind != "operation" {
		finality = "recovery_final"
		work = scope.Recovery
	}
	resolved := ""
	if scope.Lease != "" {
		finality = "lease_resolved"
		resolved = digest([]byte("lease resolution"))
	}
	return RetirementProofV2{Scope: scope, Archive: digest([]byte("canonical protected archive")), FinalAudit: digest([]byte("canonical terminal audit")), FinalWork: work, Finality: finality, LeaseResolution: resolved, Current: SelectionProofV2{Selection: digest([]byte("current")), State: digest([]byte("current-state")), Sequence: 12, Lineage: scope.Lineage, ArchiveRoot: digest([]byte("archive-root"))}, Previous: SelectionProofV2{Selection: digest([]byte("previous")), State: digest([]byte("previous-state")), Sequence: 11, Lineage: scope.Lineage, ArchiveRoot: digest([]byte("archive-root"))}}
}

func snapshotV2(t *testing.T, area *os.Root) map[string]string {
	t.Helper()
	dir, err := area.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, entry := range entries {
		data, err := area.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = digest(data)
	}
	return out
}

func TestPoolV2CompleteLifecycleAndReuse(t *testing.T) {
	p, area := preparedV2(t, 2)
	initialNames := len(snapshotV2(t, area))
	var firstExpected ExpectedV2
	var firstProof RetirementProofV2
	var priorEpoch uint64
	for i := 0; i < 160; i++ {
		owner := fmt.Sprintf("bundle-%d", i)
		claim, err := p.Claim(owner)
		if err != nil {
			t.Fatal(i, err)
		}
		if claim.Validate() != nil || claim.Epoch <= priorEpoch {
			t.Fatal("epoch did not advance", claim.Epoch)
		}
		priorEpoch = claim.Epoch
		scope := scopeForV2(owner)
		payload := []byte(fmt.Sprintf(`{"recovery":%d}`, i))
		binding, err := p.WriteOnce(claim, payload, scope)
		if err != nil || binding.Validate() != nil {
			t.Fatal(i, err)
		}
		again, err := p.WriteOnce(claim, payload, scope)
		if err != nil || again != binding {
			t.Fatal("idempotent write changed", err)
		}
		if _, err = p.WriteOnce(claim, []byte("changed"), scope); !errors.Is(err, ErrConflict) {
			t.Fatal("rewrote immutable bytes", err)
		}
		candidate, err := p.InspectClaimed(claim)
		if err != nil || candidate.Binding != binding || !bytes.Equal(candidate.Bytes, payload) {
			t.Fatal("candidate", err)
		}
		candidate.Bytes[0] = 'X'
		actual, err := p.ReadBound(binding)
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatal("read alias", err)
		}
		expected := ExpectedV2{Claim: claim, Written: &binding}
		proof := proofForV2(scope)
		if i == 0 {
			firstExpected = expected
			firstProof = proof
		}
		if i > 0 {
			before := snapshotV2(t, area)
			if err = p.RetireCAS(firstExpected, firstProof); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
				t.Fatal("old permit changed next owner", err)
			}
		}
		if err = p.RetireCAS(expected, proof); err != nil {
			t.Fatal(i, err)
		}
		if err = p.RetireCAS(expected, proof); err != nil {
			t.Fatal("idempotent retirement", err)
		}
		if _, err = p.ReadBound(binding); err == nil {
			t.Fatal("retired record became selected success")
		}
		if len(snapshotV2(t, area)) != initialNames {
			t.Fatal("reserve files grew")
		}
		if i%19 == 0 {
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			p, err = OpenV2(area)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
		}
	}
	if _, err := area.Stat("."); err != nil {
		t.Fatal("closed borrowed root", err)
	}
}

func TestPoolV2ZeroProfilesAndR1Compatibility(t *testing.T) {
	for _, p := range []*PoolV2{nil, {}} {
		if _, err := p.Claim("owner"); err == nil {
			t.Fatal("zero claim")
		}
		if _, err := p.WriteOnce(SlotClaimV2{}, nil, ScopeV2{}); err == nil {
			t.Fatal("zero write")
		}
		if _, err := p.ReadBound(BindingV2{}); err == nil {
			t.Fatal("zero read")
		}
		if _, err := p.InspectClaimed(SlotClaimV2{}); err == nil {
			t.Fatal("zero inspect")
		}
		if err := p.RetireCAS(ExpectedV2{}, RetirementProofV2{}); err == nil {
			t.Fatal("zero retire")
		}
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, profile := range []struct {
		n, capacity int
		role        RoleV2
	}{{0, 4096, PlanV2}, {33, 4096, PlanV2}, {1, 4095, PlanV2}, {1, 2 << 20, PlanV2}, {1, 4096, "other"}} {
		area, _ := areaFor(t)
		if _, err := PrepareV2(area, profile.n, profile.capacity, profile.role); err == nil {
			t.Fatal("bad profile")
		}
		if len(snapshotV2(t, area)) != 0 {
			t.Fatal("bad profile mutated area")
		}
	}
	p, area := preparedV2(t, 1)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	before := snapshotV2(t, area)
	if old, err := Open(area); err == nil {
		_ = old.Close()
		t.Fatal("R1 accepted V2")
	}
	if !reflect.DeepEqual(before, snapshotV2(t, area)) {
		t.Fatal("R1 changed V2")
	}
	legacy, legacyArea, _ := prepared(t, 1)
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	before = snapshotV2(t, legacyArea)
	if next, err := OpenV2(legacyArea); err == nil {
		_ = next.Close()
		t.Fatal("V2 adopted R1")
	}
	if !reflect.DeepEqual(before, snapshotV2(t, legacyArea)) {
		t.Fatal("V2 changed R1")
	}
}

func TestPoolV2ExactProofRejectsTamperAndPendingLease(t *testing.T) {
	for _, field := range []string{"scope-subject", "scope-domain", "scope-operation", "scope-namespace", "scope-fingerprint", "scope-origin", "scope-lease", "scope-deadline", "scope-global", "scope-domain-generation", "pool", "slot", "epoch", "claim-sequence", "owner", "role", "binding-digest", "binding-scope", "archive", "final-audit", "final-work", "pending", "resolution", "current", "previous", "lineage"} {
		t.Run(field, func(t *testing.T) {
			p, area := preparedV2(t, 1)
			claim, err := p.Claim("owner")
			if err != nil {
				t.Fatal(err)
			}
			scope := scopeForV2("owner")
			scope.Origin = scope.Operation
			scope.Lease = "lease"
			scope.Deadline = time.Now().UTC().Add(time.Minute)
			b, err := p.WriteOnce(claim, []byte(`{"rollback":true}`), scope)
			if err != nil {
				t.Fatal(err)
			}
			expected := ExpectedV2{claim, &b}
			proof := proofForV2(scope)
			switch field {
			case "scope-subject":
				proof.Scope.Subject = "other"
			case "scope-domain":
				proof.Scope.Domain = "local_services"
			case "scope-operation":
				proof.Scope.Operation = "other"
				proof.FinalWork = "other"
			case "scope-namespace":
				proof.Scope.Namespace = "other"
			case "scope-fingerprint":
				proof.Scope.Fingerprint = digest([]byte("other"))
			case "scope-origin":
				proof.Scope.Origin = "other"
			case "scope-lease":
				proof.Scope.Lease = "other"
			case "scope-deadline":
				proof.Scope.Deadline = proof.Scope.Deadline.Add(time.Nanosecond)
			case "scope-global":
				proof.Scope.Global++
			case "scope-domain-generation":
				proof.Scope.Generation++
			case "pool":
				expected.Claim.Pool = strings.Repeat("a", 32)
				b.Claim = expected.Claim
			case "slot":
				expected.Claim.Slot = 1
				b.Claim = expected.Claim
			case "epoch":
				expected.Claim.Epoch++
				b.Claim = expected.Claim
			case "claim-sequence":
				expected.Claim.ClaimSequence++
				b.Claim = expected.Claim
				b.Sequence++
			case "owner":
				expected.Claim.Owner = "other"
				b.Claim = expected.Claim
			case "role":
				expected.Claim.Role = AdmissionV2
				b.Claim = expected.Claim
			case "binding-digest":
				b.Digest = digest([]byte("other"))
			case "binding-scope":
				b.ScopeHash = digest([]byte("other"))
			case "archive":
				proof.Archive = "invalid"
			case "final-audit":
				proof.FinalAudit = "invalid"
			case "final-work":
				proof.FinalWork = "other"
			case "pending":
				proof.Finality = "applied_pending_confirmation"
			case "resolution":
				proof.LeaseResolution = ""
			case "current":
				proof.Current.Sequence++
			case "previous":
				proof.Previous.ArchiveRoot = "invalid"
			case "lineage":
				proof.Previous.Lineage = "other"
			}
			before := snapshotV2(t, area)
			if err = p.RetireCAS(expected, proof); err == nil || !reflect.DeepEqual(before, snapshotV2(t, area)) {
				t.Fatal("invalid retirement changed bytes", err)
			}
		})
	}
}

func TestPoolV2ConcurrentWriteAndRetirementCAS(t *testing.T) {
	p, area := preparedV2(t, 1)
	claim, err := p.Claim("owner")
	if err != nil {
		t.Fatal(err)
	}
	scope := scopeForV2("owner")
	payload := []byte(`{"verified":"scope"}`)
	var wg sync.WaitGroup
	bindings := make(chan BindingV2, 20)
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, e := p.WriteOnce(claim, payload, scope)
			if e != nil {
				errs <- e
			} else {
				bindings <- b
			}
		}()
	}
	wg.Wait()
	close(bindings)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	var binding BindingV2
	for b := range bindings {
		if binding.Sequence != 0 && b != binding {
			t.Fatal("concurrent binding mismatch")
		}
		binding = b
	}
	proof := proofForV2(scope)
	expected := ExpectedV2{claim, &binding}
	errs = make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- p.RetireCAS(expected, proof) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	next, err := p.Claim("next-owner")
	if err != nil {
		t.Fatal(err)
	}
	nextScope := scopeForV2("next-owner")
	nextBinding, err := p.WriteOnce(next, payload, nextScope)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotV2(t, area)
	if err = p.RetireCAS(expected, proof); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(before, snapshotV2(t, area)) {
		t.Fatal("replayed retirement changed next lease", err)
	}
	if got, err := p.ReadBound(nextBinding); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("new payload lost", err)
	}
}

func TestPoolV2OwnedNamesPermissionsAndBindings(t *testing.T) {
	for _, mode := range []string{"slot-symlink", "slot-hardlink", "slot-mode", "manifest-mode", "foreign", "binding-newer", "scope-redaction"} {
		t.Run(mode, func(t *testing.T) {
			p, area := preparedV2(t, 1)
			claim, err := p.Claim("owner")
			if err != nil {
				t.Fatal(err)
			}
			scope := scopeForV2("owner")
			binding, err := p.WriteOnce(claim, []byte("payload"), scope)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "slot-symlink":
				if err = area.Remove(slotName(0)); err != nil {
					t.Fatal(err)
				}
				if err = area.Symlink("pool.json", slotName(0)); err != nil {
					t.Fatal(err)
				}
			case "slot-hardlink":
				if err = area.Link(slotName(0), "alias"); err != nil {
					t.Fatal(err)
				}
			case "slot-mode":
				if err = area.Chmod(slotName(0), 0640); err != nil {
					t.Fatal(err)
				}
			case "manifest-mode":
				if err = area.Chmod("pool.json", 0640); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err = area.WriteFile("foreign", []byte("held"), 0600); err != nil {
					t.Fatal(err)
				}
				if err = p.Close(); err != nil {
					t.Fatal(err)
				}
				if other, e := OpenV2(area); e == nil {
					_ = other.Close()
					t.Fatal("foreign namespace adopted")
				}
				return
			case "binding-newer":
				binding.Sequence++
				if _, err = p.ReadBound(binding); err == nil {
					t.Fatal("wrong sequence accepted")
				}
				return
			case "scope-redaction":
				if strings.Contains(fmt.Sprintf("%+v %+v", claim, binding), "owner") {
					t.Fatal("claim leaked in formatting")
				}
				data, _ := json.Marshal(binding)
				if !bytes.Contains(data, []byte(`"pool"`)) {
					t.Fatal("persistence codec lost fields")
				}
				return
			}
			if _, err = p.ReadBound(binding); err == nil {
				t.Fatal("invalid identity read accepted")
			}
			if _, err = p.Claim("next"); err == nil {
				t.Fatal("invalid identity write accepted")
			}
		})
	}
}

func TestPoolV2ScopesAndReadCopies(t *testing.T) {
	s := scopeForV2("owner")
	a, err := s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	s.Lease = "lease"
	s.Origin = s.Operation
	s.Deadline = time.Now().UTC()
	a, err = s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	s.Deadline = s.Deadline.In(time.FixedZone("offset", 3600))
	b, err := s.Hash()
	if err != nil || a != b {
		t.Fatal("location changed semantic scope", err)
	}
	if (SlotClaimV2{}).Validate() == nil || (BindingV2{}).Validate() == nil {
		t.Fatal("zero validation")
	}
}
