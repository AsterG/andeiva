package configpoc

// A bundle has one index edge; the archived claims and bindings remain exact
// authenticated identities rather than independent COW paths.
func reserveBundleKeyV2(lineage, owner string) (string, error) {
	if lineage == "" || len(lineage) > 128 || owner == "" || len(owner) > 128 {
		return "", errV2Invalid
	}
	_, hash, err := v2Canonical(struct{ Kind, Lineage, Owner string }{"bundle", lineage, owner})
	return hash, err
}

func reserveArchiveBundleRefV2(lineage, owner, archive string) (v2ReserveArchiveRef, error) {
	key, err := reserveBundleKeyV2(lineage, owner)
	if err != nil || !validHash(archive) {
		return v2ReserveArchiveRef{}, errV2Invalid
	}
	return v2ReserveArchiveRef{Key: key, Archive: archive, Owner: owner, Kind: "bundle", Lineage: lineage}, nil
}

func reserveArchiveHasBundleV2(archive v2ReserveArchive, ref v2ReserveArchiveRef) bool {
	key, err := reserveBundleKeyV2(archive.Lineage, ref.Owner)
	if err != nil || ref.Kind != "bundle" || ref.Role != "" || ref.Lineage != archive.Lineage || ref.Key != key {
		return false
	}
	for _, entry := range archive.Entries {
		if entry.Claim.Owner == ref.Owner {
			return true
		}
	}
	for _, claim := range archive.UnusedEscrow {
		if claim.Owner == ref.Owner {
			return true
		}
	}
	return false
}

func (s *v2Store) reserveArchiveBundleLookupV2(root string, expected v2ReserveArchiveEntry, kind string) (v2ReserveArchive, bool, error) {
	if _, err := reserveIdentityKeyV2(expected, kind); err != nil {
		return v2ReserveArchive{}, false, err
	}
	key, err := reserveBundleKeyV2(s.state.Lineage, expected.Claim.Owner)
	if err != nil {
		return v2ReserveArchive{}, false, err
	}
	for depth := 0; root != "" && depth <= v2VerifiedDepthLimit; depth++ {
		node, err := s.reserveArchiveNodeV2(root, depth, key[:depth])
		if err != nil {
			return v2ReserveArchive{}, false, err
		}
		if node.Kind == "branch" {
			root = node.Children[archiveDigitV2(key, depth)]
			continue
		}
		for _, ref := range node.Entries {
			if ref.Key != key {
				continue
			}
			archive, err := s.readReserveArchiveV2(ref.Archive)
			if err != nil || !reserveArchiveHasBundleV2(archive, ref) || ref.Owner != expected.Claim.Owner {
				return v2ReserveArchive{}, false, errV2Unavailable
			}
			for _, entry := range archive.Entries {
				if entry.Claim != expected.Claim {
					continue
				}
				if kind == "claim" {
					return archive, true, nil
				}
				if entry.Binding != nil && expected.Binding != nil && *entry.Binding == *expected.Binding {
					return archive, true, nil
				}
			}
			if kind == "claim" {
				for _, claim := range archive.UnusedEscrow {
					if claim == expected.Claim {
						return archive, true, nil
					}
				}
			}
			// Finding the owner alone never authenticates a substituted epoch/binding.
			return v2ReserveArchive{}, false, errV2Unavailable
		}
		return v2ReserveArchive{}, false, nil
	}
	return v2ReserveArchive{}, false, nil
}
