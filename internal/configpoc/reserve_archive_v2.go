package configpoc

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

const reserveArchiveLimitV2 = 64 * 1024
const reserveArchivePayloadLimitV2 = 56 * 1024

// Archive records preserve the original bytes. A hash alone cannot replace a
// physical record before its bank is reused. These types are never wire DTOs.
type v2ReserveArchiveEntry struct {
	Claim   recoveryreserve.SlotClaimV2 `json:"claim"`
	Binding *recoveryreserve.BindingV2  `json:"binding,omitempty"`
	Scope   *recoveryreserve.ScopeV2    `json:"scope,omitempty"`
	Raw     json.RawMessage             `json:"raw,omitempty"`
}

type v2ReserveArchive struct {
	Format          string                  `json:"format"`
	Version         uint8                   `json:"version"`
	Lineage         string                  `json:"lineage"`
	Origin          string                  `json:"origin"`
	Child           string                  `json:"child,omitempty"`
	Audit           string                  `json:"audit"`
	FinalWork       string                  `json:"final_work"`
	LeaseResolution string                  `json:"lease_resolution,omitempty"`
	Dependencies    []string                `json:"dependencies"`
	Entries         []v2ReserveArchiveEntry `json:"entries"`
}

func reserveClaimKeyV2(claim recoveryreserve.SlotClaimV2) (string, error) {
	if claim.Validate() != nil {
		return "", errV2Invalid
	}
	_, hash, err := v2Canonical(claim)
	return hash, err
}

func validateReserveArchiveV2(archive v2ReserveArchive) error {
	if archive.Format != v2Format || archive.Version != 1 || archive.Lineage == "" || len(archive.Lineage) > 128 || archive.Origin == "" || len(archive.Origin) > 128 || len(archive.Child) > 128 || archive.Child == archive.Origin || !validHash(archive.Audit) || !validHash(archive.FinalWork) || (archive.LeaseResolution != "" && !validHash(archive.LeaseResolution)) || len(archive.Dependencies) > 32 || (len(archive.Entries) != 3 && len(archive.Entries) != 6) {
		return errV2Invalid
	}
	if (archive.Child != "") != (len(archive.Entries) == 6) || (archive.Child != "" && archive.LeaseResolution == "") {
		return errV2Invalid
	}
	previous := ""
	for _, hash := range archive.Dependencies {
		if !validHash(hash) || hash <= previous {
			return errV2Invalid
		}
		previous = hash
	}
	seen := map[string]bool{}
	roles := map[string]map[recoveryreserve.RoleV2]bool{}
	ownerWork := map[string]string{}
	work := map[string]bool{}
	payload := 0
	previous = ""
	var subject, domain, lease string
	var deadline time.Time
	for _, entry := range archive.Entries {
		key, err := reserveClaimKeyV2(entry.Claim)
		if err != nil || seen[key] || key <= previous {
			return errV2Invalid
		}
		previous = key
		seen[key] = true
		owner := entry.Claim.Owner
		if roles[owner] == nil {
			roles[owner] = map[recoveryreserve.RoleV2]bool{}
		}
		if roles[owner][entry.Claim.Role] {
			return errV2Invalid
		}
		roles[owner][entry.Claim.Role] = true
		if entry.Binding == nil {
			if len(entry.Raw) != 0 || entry.Scope != nil || entry.Claim.Role == recoveryreserve.AdmissionV2 {
				return errV2Invalid
			}
			continue
		}
		binding := entry.Binding
		if binding.Validate() != nil || binding.Claim != entry.Claim || binding.Length != len(entry.Raw) || len(entry.Raw) == 0 || checkpointDigest(entry.Raw) != binding.Digest || !jsoncheck.UniqueControlFields(entry.Raw) || entry.Raw[0] != '{' || entry.Scope == nil {
			return errV2Invalid
		}
		scope := *entry.Scope
		scopeHash, err := scope.Hash()
		if err != nil || binding.ScopeHash != scopeHash || scope.Lineage != archive.Lineage || scope.Bundle != owner {
			return errV2Invalid
		}
		id := scope.Operation
		if scope.Kind != "operation" {
			id = scope.Recovery
		}
		if id != archive.Origin && id != archive.Child {
			return errV2Invalid
		}
		if ownerWork[owner] != "" && ownerWork[owner] != id {
			return errV2Invalid
		}
		ownerWork[owner] = id
		if domain != "" && (domain != scope.Domain || subject != scope.Subject) {
			return errV2Invalid
		}
		domain, subject = scope.Domain, scope.Subject
		if id == archive.Child && scope.Origin != archive.Origin {
			return errV2Invalid
		}
		if scope.Lease != "" {
			if lease != "" && (lease != scope.Lease || !deadline.Equal(scope.Deadline)) {
				return errV2Invalid
			}
			lease, deadline = scope.Lease, scope.Deadline.UTC()
		}
		work[id] = true
		// RawMessage marshaling must not normalize or HTML-escape retained bytes.
		roundTrip, err := json.Marshal(entry.Raw)
		if err != nil || !bytes.Equal(roundTrip, entry.Raw) {
			return errV2Invalid
		}
		payload += len(entry.Raw)
		if payload > reserveArchivePayloadLimitV2 {
			return errV2Limited
		}
	}
	want := 1
	if archive.Child != "" {
		want = 2
	}
	if len(roles) != want || len(work) != want {
		return errV2Invalid
	}
	for _, ownerRoles := range roles {
		if len(ownerRoles) != 3 {
			return errV2Invalid
		}
	}
	if archive.Child != "" && lease == "" {
		return errV2Invalid
	}
	return nil
}

func encodeReserveArchiveV2(archive v2ReserveArchive) ([]byte, string, error) {
	if err := validateReserveArchiveV2(archive); err != nil {
		return nil, "", err
	}
	data, hash, err := v2Canonical(archive)
	if err != nil {
		return nil, "", err
	}
	if len(data) > reserveArchiveLimitV2 {
		return nil, "", errV2Limited
	}
	return data, hash, nil
}

func decodeReserveArchiveV2(data []byte) (v2ReserveArchive, error) {
	var archive v2ReserveArchive
	if len(data) == 0 || len(data) > reserveArchiveLimitV2 || !jsoncheck.UniqueControlFields(data) || checkpointDecode(data, &archive) != nil {
		return archive, errV2Invalid
	}
	encoded, _, err := encodeReserveArchiveV2(archive)
	if err != nil {
		return archive, err
	}
	if !bytes.Equal(encoded, data) {
		return archive, errV2Invalid
	}
	return archive, nil
}

// Stable ordering is performed only by the trusted archive producer, before
// publication. Decoders reject a differently encoded object rather than repair it.
func sortReserveArchiveV2(archive *v2ReserveArchive) {
	sort.Strings(archive.Dependencies)
	sort.Slice(archive.Entries, func(i, j int) bool {
		left, _ := reserveClaimKeyV2(archive.Entries[i].Claim)
		right, _ := reserveClaimKeyV2(archive.Entries[j].Claim)
		return left < right
	})
}
