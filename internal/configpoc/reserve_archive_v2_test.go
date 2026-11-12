package configpoc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func reserveArchiveFixtureV2(t *testing.T, owner string) v2ReserveArchive {
	t.Helper()
	scope := recoveryreserve.ScopeV2{Kind: "operation", Lineage: "lineage", Bundle: owner, Operation: "v2.op.1.fixture", Namespace: "v2.ns.1.fixture", Subject: "subject", Domain: "firewall", Fingerprint: strings.Repeat("a", 64), Global: 1, Generation: 1}
	scopeHash, err := scope.Hash()
	if err != nil {
		t.Fatal(err)
	}
	archive := v2ReserveArchive{Format: v2Format, Version: 1, Lineage: scope.Lineage, Origin: scope.Operation, Audit: strings.Repeat("b", 64), FinalWork: strings.Repeat("c", 64), Dependencies: []string{}}
	for i, role := range []recoveryreserve.RoleV2{recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2} {
		claim := recoveryreserve.SlotClaimV2{Pool: fmt.Sprintf("%032x", i+1), Slot: 0, Epoch: 1, Owner: owner, Role: role, ClaimSequence: 2, Capacity: 16384}
		raw := json.RawMessage(`{"format":"capsule","value":"retained"}`)
		binding := recoveryreserve.BindingV2{Claim: claim, Sequence: 3, Digest: checkpointDigest(raw), Length: len(raw), ScopeHash: scopeHash}
		copyScope := scope
		archive.Entries = append(archive.Entries, v2ReserveArchiveEntry{Claim: claim, Binding: &binding, Scope: &copyScope, Raw: raw})
	}
	sortReserveArchiveV2(&archive)
	return archive
}

func TestReserveArchiveV2PreservesExactRawAndRejectsCorruption(t *testing.T) {
	archive := reserveArchiveFixtureV2(t, "bundle")
	data, hash, err := encodeReserveArchiveV2(archive)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeReserveArchiveV2(data)
	if err != nil || checkpointDigest(data) != hash {
		t.Fatalf("decode: %v", err)
	}
	for i, entry := range decoded.Entries {
		if !bytes.Equal(entry.Raw, archive.Entries[i].Raw) || checkpointDigest(entry.Raw) != entry.Binding.Digest {
			t.Fatal("archive changed capsule bytes")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*v2ReserveArchive)
	}{
		{"digest", func(a *v2ReserveArchive) { a.Entries[0].Binding.Digest = strings.Repeat("e", 64) }},
		{"scope", func(a *v2ReserveArchive) { a.Entries[0].Scope.Subject = "foreign" }},
		{"claim", func(a *v2ReserveArchive) { a.Entries[0].Claim.Epoch++ }},
		{"empty-admission", func(a *v2ReserveArchive) {
			for i := range a.Entries {
				if a.Entries[i].Claim.Role == recoveryreserve.AdmissionV2 {
					a.Entries[i].Binding = nil
					a.Entries[i].Scope = nil
					a.Entries[i].Raw = nil
				}
			}
		}},
		{"owner-role", func(a *v2ReserveArchive) { a.Entries[1] = a.Entries[0] }},
		{"child-without-closure", func(a *v2ReserveArchive) { a.Child = "v2.op.2.fixture" }},
		{"foreign-work", func(a *v2ReserveArchive) { a.Entries[0].Scope.Operation = "v2.op.3.foreign" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := clone(archive)
			tc.change(&changed)
			if _, _, err := encodeReserveArchiveV2(changed); err == nil {
				t.Fatal("invalid archive accepted")
			}
		})
	}
	for _, invalid := range [][]byte{append([]byte(" "), data...), append(append([]byte{}, data...), []byte(" {}")...), bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(data, []byte(`"version":1`), []byte(`"Version":1`), 1)} {
		if _, err := decodeReserveArchiveV2(invalid); err == nil {
			t.Fatal("noncanonical or duplicate encoding accepted")
		}
	}
}

func TestReserveArchiveV2SerializedLimitBeforePublication(t *testing.T) {
	archive := reserveArchiveFixtureV2(t, "bundle")
	for i := range archive.Entries {
		entry := &archive.Entries[i]
		entry.Claim.Capacity = 32768
		entry.Binding.Claim = entry.Claim
		entry.Raw = json.RawMessage(`{"payload":"` + strings.Repeat("x", 19200) + `"}`)
		entry.Binding.Length = len(entry.Raw)
		entry.Binding.Digest = checkpointDigest(entry.Raw)
	}
	sortReserveArchiveV2(&archive)
	if _, _, err := encodeReserveArchiveV2(archive); err == nil {
		t.Fatal("raw payload beyond 56KiB accepted")
	}
	entry := &archive.Entries[0]
	entry.Raw = json.RawMessage(`{"payload":"ok"}`)
	entry.Binding.Length = len(entry.Raw)
	entry.Binding.Digest = checkpointDigest(entry.Raw)
	data, _, err := encodeReserveArchiveV2(archive)
	if err != nil || len(data) > reserveArchiveLimitV2 {
		t.Fatalf("bounded inline payload: %d, %v", len(data), err)
	}
	if bytes.Contains(data, []byte(`"raw":"`)) {
		t.Fatal("raw capsule became base64/string")
	}
}

func TestReserveArchiveV2IndexContextAndCollision(t *testing.T) {
	s, _, _, _ := v2Fixture(t, v2MaximumOperations)
	defer s.close()
	root := ""
	var expected v2ReserveArchiveEntry
	for i := 0; i < 65; i++ {
		archive := reserveArchiveFixtureV2(t, fmt.Sprintf("bundle-%d", i))
		hash, err := s.object(archive)
		if err != nil {
			t.Fatal(err)
		}
		entry := archive.Entries[0]
		key, err := reserveIdentityKeyV2(entry, "binding")
		if err != nil {
			t.Fatal(err)
		}
		root, err = s.reserveArchiveInsertV2(root, 0, "", v2ReserveArchiveRef{Key: key, Archive: hash, Owner: entry.Claim.Owner, Role: entry.Claim.Role, Kind: "binding"})
		if err != nil {
			t.Fatal(err)
		}
		expected = entry
	}
	archive, found, err := s.reserveArchiveLookupV2(root, expected, "binding")
	if err != nil || !found || archive.Entries[0].Claim.Owner != expected.Claim.Owner {
		t.Fatalf("lookup: found=%t, %v", found, err)
	}
	key, _ := reserveIdentityKeyV2(expected, "binding")
	if _, err := s.reserveArchiveInsertV2(root, 0, "", v2ReserveArchiveRef{Key: key, Archive: strings.Repeat("e", 64), Owner: expected.Claim.Owner, Role: expected.Claim.Role, Kind: "binding"}); err == nil {
		t.Fatal("same semantic identity overwritten")
	}
	foreign := clone(expected)
	foreign.Claim.Epoch++
	foreign.Binding.Claim = foreign.Claim
	if _, found, err := s.reserveArchiveLookupV2(root, foreign, "binding"); err != nil || found {
		t.Fatalf("foreign epoch resolved: %t %v", found, err)
	}
}

func TestReserveArchiveV2CountsSerializedEnvelope(t *testing.T) {
	origin, child := strings.Repeat("o", 128), strings.Repeat("c", 128)
	archive := reserveArchiveFixtureV2(t, strings.Repeat("a", 128))
	other := reserveArchiveFixtureV2(t, strings.Repeat("b", 128))
	archive.Origin, archive.Child, archive.Lineage = origin, child, strings.Repeat("l", 128)
	archive.LeaseResolution = strings.Repeat("d", 64)
	archive.Entries = append(archive.Entries, other.Entries...)
	total := 0
	for i := range archive.Entries {
		entry := &archive.Entries[i]
		scope := entry.Scope
		scope.Lineage, scope.Namespace, scope.Subject = archive.Lineage, strings.Repeat("n", 128), strings.Repeat("s", 128)
		scope.Operation = origin
		if entry.Claim.Owner == strings.Repeat("b", 128) {
			scope.Operation = child
		}
		scope.Origin, scope.Lease, scope.Deadline = origin, strings.Repeat("e", 64), time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		capacity := map[recoveryreserve.RoleV2]int{recoveryreserve.AdmissionV2: 4096, recoveryreserve.PlanV2: 16384, recoveryreserve.EmergencyV2: 8192}[entry.Claim.Role]
		entry.Claim.Capacity, entry.Binding.Claim = capacity, entry.Claim
		entry.Binding.Claim.Capacity = capacity
		entry.Raw = json.RawMessage(`{"payload":"` + strings.Repeat("x", capacity-len(`{"payload":""}`)) + `"}`)
		entry.Binding.Length, entry.Binding.Digest = len(entry.Raw), checkpointDigest(entry.Raw)
		var err error
		entry.Binding.ScopeHash, err = scope.Hash()
		if err != nil {
			t.Fatal(err)
		}
		total += len(entry.Raw)
	}
	sortReserveArchiveV2(&archive)
	if total != reserveArchivePayloadLimitV2 {
		t.Fatalf("wrong raw boundary fixture: %d", total)
	}
	serialized, err := json.Marshal(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) <= reserveArchiveLimitV2 {
		t.Fatalf("fixture must cross serialized limit: %d", len(serialized))
	}
	if _, _, err := encodeReserveArchiveV2(archive); err != errV2Limited {
		t.Fatalf("serialized limit was not enforced: %v", err)
	}
}
