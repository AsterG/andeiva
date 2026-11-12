//go:build linux

package configpoc

import (
	"strings"
	"testing"
)

func TestReserveArchiveV2BundleAuthenticatesEveryIdentity(t *testing.T) {
	s, _, _, _ := v2Fixture(t, v2MaximumOperations)
	defer s.close()
	archive := reserveArchiveFixtureV2(t, "bundle")
	s.state.Lineage = archive.Lineage
	hash, err := s.object(archive)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := reserveArchiveBundleRefV2(archive.Lineage, "bundle", hash)
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.reserveArchiveInsertV2("", 0, "", ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range archive.Entries {
		for _, kind := range []string{"claim", "binding"} {
			if _, found, err := s.reserveArchiveBundleLookupV2(root, entry, kind); err != nil || !found {
				t.Fatalf("%s: %t %v", kind, found, err)
			}
		}
		for _, change := range []string{"epoch", "digest", "scope", "length", "sequence"} {
			bad := clone(entry)
			switch change {
			case "epoch":
				bad.Claim.Epoch++
				bad.Binding.Claim = bad.Claim
			case "digest":
				bad.Binding.Digest = strings.Repeat("d", 64)
			case "scope":
				bad.Binding.ScopeHash = strings.Repeat("d", 64)
			case "length":
				bad.Binding.Length++
			case "sequence":
				bad.Binding.Sequence++
			}
			if _, found, err := s.reserveArchiveBundleLookupV2(root, bad, "binding"); err == nil || found {
				t.Fatalf("substituted %s accepted", change)
			}
		}
	}
	for _, change := range []string{"lineage", "owner", "role", "key"} {
		bad := ref
		switch change {
		case "lineage":
			bad.Lineage = "foreign"
		case "owner":
			bad.Owner = "foreign"
		case "role":
			bad.Role = "plan"
		case "key":
			bad.Key = strings.Repeat("d", 64)
		}
		if validReserveArchiveNodeV2(v2ReserveArchiveNode{Format: v2Format, Kind: "leaf", Entries: []v2ReserveArchiveRef{bad}}, 0, "") || reserveArchiveHasBundleV2(archive, bad) {
			t.Fatalf("substituted ref %s accepted", change)
		}
	}
}

func TestReserveArchiveV2BundleUnusedEscrowHasNoBinding(t *testing.T) {
	s, _, _, _ := v2Fixture(t, v2MaximumOperations)
	defer s.close()
	archive := reserveArchiveFixtureV2(t, "origin")
	for _, entry := range archive.Entries {
		claim := entry.Claim
		claim.Owner = "unused"
		claim.Slot = 8
		archive.UnusedEscrow = append(archive.UnusedEscrow, claim)
	}
	sortReserveArchiveV2(&archive)
	s.state.Lineage = archive.Lineage
	hash, err := s.object(archive)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := reserveArchiveBundleRefV2(archive.Lineage, "unused", hash)
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.reserveArchiveInsertV2("", 0, "", ref)
	if err != nil {
		t.Fatal(err)
	}
	entry := v2ReserveArchiveEntry{Claim: archive.UnusedEscrow[0]}
	if _, found, err := s.reserveArchiveBundleLookupV2(root, entry, "claim"); err != nil || !found {
		t.Fatalf("claim: %t %v", found, err)
	}
	binding := *archive.Entries[0].Binding
	binding.Claim = entry.Claim
	entry.Binding = &binding
	if _, found, err := s.reserveArchiveBundleLookupV2(root, entry, "binding"); err == nil || found {
		t.Fatal("unused escrow invented a written binding")
	}
}
