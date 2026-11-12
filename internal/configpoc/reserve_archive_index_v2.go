package configpoc

import (
	"sort"
	"strings"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

type v2ReserveArchiveRef struct {
	Key     string                 `json:"key"`
	Archive string                 `json:"archive"`
	Owner   string                 `json:"owner"`
	Role    recoveryreserve.RoleV2 `json:"role,omitempty"`
	Kind    string                 `json:"kind"`
	Lineage string                 `json:"lineage,omitempty"`
}

type v2ReserveArchiveNode struct {
	Format   string                `json:"format"`
	Depth    int                   `json:"depth"`
	Kind     string                `json:"kind"`
	Children [16]string            `json:"children"`
	Entries  []v2ReserveArchiveRef `json:"entries"`
}

func reserveIdentityKeyV2(entry v2ReserveArchiveEntry, kind string) (string, error) {
	if _, err := reserveClaimKeyV2(entry.Claim); err != nil {
		return "", err
	}
	switch kind {
	case "claim":
		_, hash, err := v2Canonical(struct {
			Kind  string                      `json:"kind"`
			Claim recoveryreserve.SlotClaimV2 `json:"claim"`
		}{kind, entry.Claim})
		return hash, err
	case "binding":
		if entry.Binding == nil || entry.Binding.Validate() != nil {
			return "", errV2Invalid
		}
		_, hash, err := v2Canonical(struct {
			Kind    string                    `json:"kind"`
			Binding recoveryreserve.BindingV2 `json:"binding"`
		}{kind, *entry.Binding})
		return hash, err
	default:
		return "", errV2Invalid
	}
}

func validReserveArchiveNodeV2(node v2ReserveArchiveNode, depth int, prefix string) bool {
	if node.Format != v2Format || node.Depth != depth || depth < 0 || depth > v2VerifiedDepthLimit || len(prefix) != depth {
		return false
	}
	switch node.Kind {
	case "leaf":
		if len(node.Entries) == 0 || len(node.Entries) > v2VerifiedLeafLimit {
			return false
		}
		for _, child := range node.Children {
			if child != "" {
				return false
			}
		}
		previous := ""
		for _, entry := range node.Entries {
			if !validHash(entry.Key) || !strings.HasPrefix(entry.Key, prefix) || entry.Key <= previous || !validHash(entry.Archive) || entry.Owner == "" || len(entry.Owner) > 128 || (entry.Kind != "claim" && entry.Kind != "binding" && entry.Kind != "bundle") {
				return false
			}
			if entry.Kind == "bundle" {
				expected, err := reserveBundleKeyV2(entry.Lineage, entry.Owner)
				if err != nil || entry.Role != "" || entry.Key != expected {
					return false
				}
				previous = entry.Key
				continue
			}
			if entry.Lineage != "" {
				return false
			}
			switch entry.Role {
			case recoveryreserve.AdmissionV2, recoveryreserve.PlanV2, recoveryreserve.EmergencyV2:
			default:
				return false
			}
			previous = entry.Key
		}
	case "branch":
		if depth >= v2VerifiedDepthLimit || len(node.Entries) != 0 {
			return false
		}
		count := 0
		for _, child := range node.Children {
			if child != "" {
				if !validHash(child) {
					return false
				}
				count++
			}
		}
		if count == 0 {
			return false
		}
	default:
		return false
	}
	return true
}

func (s *v2Store) reserveArchiveNodeV2(hash string, depth int, prefix string) (v2ReserveArchiveNode, error) {
	var node v2ReserveArchiveNode
	if s.readObject(hash, &node) != nil || !validReserveArchiveNodeV2(node, depth, prefix) {
		s.blocked = true
		return node, errV2Unavailable
	}
	return node, nil
}

func archiveDigitV2(key string, depth int) int {
	value := key[depth]
	if value <= '9' {
		return int(value - '0')
	}
	return int(value - 'a' + 10)
}

func (s *v2Store) reserveArchiveInsertV2(root string, depth int, prefix string, entry v2ReserveArchiveRef) (string, error) {
	probe := v2ReserveArchiveNode{Format: v2Format, Depth: depth, Kind: "leaf", Entries: []v2ReserveArchiveRef{entry}}
	if !validReserveArchiveNodeV2(probe, depth, prefix) {
		return "", errV2Invalid
	}
	node := v2ReserveArchiveNode{Format: v2Format, Depth: depth, Kind: "leaf"}
	if root != "" {
		var err error
		node, err = s.reserveArchiveNodeV2(root, depth, prefix)
		if err != nil {
			return "", err
		}
	}
	if node.Kind == "branch" {
		digit := archiveDigitV2(entry.Key, depth)
		next, err := s.reserveArchiveInsertV2(node.Children[digit], depth+1, entry.Key[:depth+1], entry)
		if err != nil {
			return "", err
		}
		node.Children[digit] = next
		return s.object(node)
	}
	position := sort.Search(len(node.Entries), func(i int) bool { return node.Entries[i].Key >= entry.Key })
	if position < len(node.Entries) && node.Entries[position].Key == entry.Key {
		if node.Entries[position] != entry {
			return "", errV2Unavailable
		}
		return root, nil
	}
	node.Entries = append(node.Entries, v2ReserveArchiveRef{})
	copy(node.Entries[position+1:], node.Entries[position:])
	node.Entries[position] = entry
	if len(node.Entries) <= v2VerifiedLeafLimit {
		return s.object(node)
	}
	if depth == v2VerifiedDepthLimit {
		return "", errV2Limited
	}
	return s.reserveArchiveBuildV2(depth, prefix, node.Entries)
}

// Build each partition once. Reinserting each entry through every shared
// prefix would multiply COW writes beyond the reserved closing budget.
func (s *v2Store) reserveArchiveBuildV2(depth int, prefix string, entries []v2ReserveArchiveRef) (string, error) {
	if len(entries) == 0 || depth < 0 || depth > v2VerifiedDepthLimit || len(prefix) != depth {
		return "", errV2Invalid
	}
	node := v2ReserveArchiveNode{Format: v2Format, Depth: depth, Kind: "leaf", Entries: entries}
	if len(entries) <= v2VerifiedLeafLimit {
		if !validReserveArchiveNodeV2(node, depth, prefix) {
			return "", errV2Invalid
		}
		return s.object(node)
	}
	if depth == v2VerifiedDepthLimit {
		return "", errV2Limited
	}
	node.Kind, node.Entries = "branch", nil
	for start := 0; start < len(entries); {
		digit := archiveDigitV2(entries[start].Key, depth)
		end := start + 1
		for end < len(entries) && archiveDigitV2(entries[end].Key, depth) == digit {
			end++
		}
		child, err := s.reserveArchiveBuildV2(depth+1, entries[start].Key[:depth+1], entries[start:end])
		if err != nil {
			return "", err
		}
		node.Children[digit] = child
		start = end
	}
	return s.object(node)
}

// Every lookup validates its contextual identity against the archived bytes;
// neither a semantic key nor a cached object hash establishes membership alone.
func (s *v2Store) reserveArchiveLookupV2(root string, expected v2ReserveArchiveEntry, kind string) (v2ReserveArchive, bool, error) {
	key, err := reserveIdentityKeyV2(expected, kind)
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
		position := sort.Search(len(node.Entries), func(i int) bool { return node.Entries[i].Key >= key })
		if position == len(node.Entries) || node.Entries[position].Key != key {
			return v2ReserveArchive{}, false, nil
		}
		ref := node.Entries[position]
		if ref.Owner != expected.Claim.Owner || ref.Role != expected.Claim.Role || ref.Kind != kind {
			return v2ReserveArchive{}, false, errV2Unavailable
		}
		archive, err := s.readReserveArchiveV2(ref.Archive)
		if err != nil {
			return v2ReserveArchive{}, false, err
		}
		for _, entry := range archive.Entries {
			if entry.Claim != expected.Claim {
				continue
			}
			actual, err := reserveIdentityKeyV2(entry, kind)
			if err == nil && actual == key {
				return archive, true, nil
			}
		}
		if kind == "claim" {
			for _, claim := range archive.UnusedEscrow {
				if claim != expected.Claim {
					continue
				}
				actual, err := reserveIdentityKeyV2(v2ReserveArchiveEntry{Claim: claim}, "claim")
				if err == nil && actual == key {
					return archive, true, nil
				}
			}
		}
		return v2ReserveArchive{}, false, errV2Unavailable
	}
	return v2ReserveArchive{}, false, nil
}

func (s *v2Store) readReserveArchiveV2(hash string) (v2ReserveArchive, error) {
	name, err := v2ObjectName(hash)
	if err != nil {
		s.blocked = true
		return v2ReserveArchive{}, errV2Unavailable
	}
	data, err := s.readRecordV2(name, reserveArchiveLimitV2)
	if err != nil || checkpointDigest(data) != hash {
		s.blocked = true
		return v2ReserveArchive{}, errV2Unavailable
	}
	archive, err := decodeReserveArchiveV2(data)
	if err != nil {
		s.blocked = true
		return v2ReserveArchive{}, errV2Unavailable
	}
	return archive, nil
}
