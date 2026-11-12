package configpoc

import (
	"sort"
	"strings"
)

const v2VerifiedLeafLimit = 64
const v2VerifiedDepthLimit = 16

type v2VerifiedEntry struct {
	Revision  string `json:"revision"`
	Audit     string `json:"audit"`
	Operation string `json:"operation_id"`
}
type v2VerifiedNode struct {
	Format   string            `json:"format"`
	Depth    int               `json:"depth"`
	Kind     string            `json:"kind"`
	Children [16]string        `json:"children"`
	Entries  []v2VerifiedEntry `json:"entries"`
}

func (c *v2Coordinator) verifyWitness(entry v2VerifiedEntry) error {
	var audit v2CoordinatorAudit
	if c.store.readObject(entry.Audit, &audit) != nil || audit.Format != v2Format || audit.Operation != entry.Operation || audit.Running != entry.Revision || (audit.Result != "verified" && audit.Result != "applied") || audit.Sequence > c.store.state.Configuration.AuditSequence || audit.Generation > c.store.state.Generation {
		c.store.blocked = true
		return errV2Unavailable
	}
	return nil
}

// Bounded COW metadata separates verified history from persisted Candidates.
// Full hashes are compared; an overfull terminal leaf refuses insertion.
func (c *v2Coordinator) verifiedNode(hash string, depth int, prefix string) (node v2VerifiedNode, result error) {
	defer func() {
		if result != nil {
			c.store.blocked = true
		}
	}()
	if depth < 0 || depth > v2VerifiedDepthLimit || len(prefix) != depth || c.store.readObject(hash, &node) != nil || node.Format != v2Format || node.Depth != depth {
		return node, errV2Unavailable
	}
	switch node.Kind {
	case "leaf":
		if len(node.Entries) == 0 || len(node.Entries) > v2VerifiedLeafLimit {
			return node, errV2Unavailable
		}
		for _, child := range node.Children {
			if child != "" {
				return node, errV2Unavailable
			}
		}
		previous := ""
		for _, entry := range node.Entries {
			if !validHash(entry.Revision) || !validHash(entry.Audit) || entry.Operation == "" || len(entry.Operation) > 128 || !strings.HasPrefix(entry.Revision, prefix) || entry.Revision <= previous {
				return node, errV2Unavailable
			}
			previous = entry.Revision
		}
	case "branch":
		if depth >= v2VerifiedDepthLimit || len(node.Entries) != 0 {
			return node, errV2Unavailable
		}
		count := 0
		for _, child := range node.Children {
			if child != "" {
				if !validHash(child) {
					return node, errV2Unavailable
				}
				count++
			}
		}
		if count == 0 {
			return node, errV2Unavailable
		}
	default:
		return node, errV2Unavailable
	}
	return node, nil
}

func (c *v2Coordinator) verifiedLookup(root, hash string) (v2VerifiedEntry, bool, error) {
	if !validHash(hash) {
		return v2VerifiedEntry{}, false, ErrInvalid
	}
	for depth := 0; root != "" && depth <= v2VerifiedDepthLimit; depth++ {
		node, err := c.verifiedNode(root, depth, hash[:depth])
		if err != nil {
			return v2VerifiedEntry{}, false, err
		}
		if node.Kind == "leaf" {
			for _, entry := range node.Entries {
				if entry.Revision == hash {
					return entry, true, nil
				}
			}
			return v2VerifiedEntry{}, false, nil
		}
		root = node.Children[strings.IndexByte("0123456789abcdef", hash[depth])]
	}
	return v2VerifiedEntry{}, false, nil
}

func (c *v2Coordinator) verifiedInsert(root string, depth int, entry v2VerifiedEntry) (string, error) {
	return c.cowIndexInsert(root, depth, entry, false)
}

func (c *v2Coordinator) cowIndexInsert(root string, depth int, entry v2VerifiedEntry, replace bool) (string, error) {
	if !validHash(entry.Revision) || !validHash(entry.Audit) || entry.Operation == "" || len(entry.Operation) > 128 || depth < 0 || depth > v2VerifiedDepthLimit {
		return "", ErrInvalid
	}
	if root == "" {
		return c.verifiedBuild([]v2VerifiedEntry{entry}, depth)
	}
	node, err := c.verifiedNode(root, depth, entry.Revision[:depth])
	if err != nil {
		return "", err
	}
	if node.Kind == "leaf" {
		for index, known := range node.Entries {
			if known.Revision == entry.Revision {
				if replace {
					if known.Operation != entry.Operation {
						return "", ErrInvalid
					}
					node.Entries[index] = entry
					return c.store.object(node)
				}
				return root, nil
			}
		}
		node.Entries = append(node.Entries, entry)
		return c.verifiedBuild(node.Entries, depth)
	}
	index := strings.IndexByte("0123456789abcdef", entry.Revision[depth])
	node.Children[index], err = c.cowIndexInsert(node.Children[index], depth+1, entry, replace)
	if err != nil {
		return "", err
	}
	return c.store.object(node)
}

func (c *v2Coordinator) verifiedBuild(entries []v2VerifiedEntry, depth int) (string, error) {
	node := v2VerifiedNode{Format: v2Format, Depth: depth, Kind: "leaf", Entries: append([]v2VerifiedEntry{}, entries...)}
	if len(entries) <= v2VerifiedLeafLimit {
		sort.Slice(node.Entries, func(i, j int) bool { return node.Entries[i].Revision < node.Entries[j].Revision })
		return c.store.object(node)
	}
	if depth >= v2VerifiedDepthLimit {
		return "", errV2Limited
	}
	node.Kind = "branch"
	node.Entries = []v2VerifiedEntry{}
	var buckets [16][]v2VerifiedEntry
	for _, entry := range entries {
		index := strings.IndexByte("0123456789abcdef", entry.Revision[depth])
		buckets[index] = append(buckets[index], entry)
	}
	for index, bucket := range buckets {
		if len(bucket) > 0 {
			hash, err := c.verifiedBuild(bucket, depth+1)
			if err != nil {
				return "", err
			}
			node.Children[index] = hash
		}
	}
	return c.store.object(node)
}
