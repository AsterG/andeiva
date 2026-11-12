package configpoc

import (
	"sort"
	"strings"
)

const reserveMetadataObjectLimitV2 = 256 * 1024

func (m *v2ReserveManager) bootProfile(s *v2Store, record v2RecoveryRecord, target v2Configuration, owner string) error {
	if raw, _, err := v2Canonical(s.state); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	if raw, _, err := v2Canonical(target); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	key, err := reserveBundleKeyV2(s.state.Lineage, owner)
	if err != nil {
		return err
	}
	archive, err := reserveIndexCostV2(s, s.state.ReserveArchiveRoot, key, "archive", false)
	if err != nil {
		return err
	}
	recoveryKey := checkpointDigest([]byte(record.ID))
	initial, err := reserveIndexCostV2(s, s.state.Configuration.RecoveryIndex, recoveryKey, "verified", true)
	if err != nil {
		return err
	}
	// Replacement follows the same prefix as the inserted recovery record.
	// initial bounds that prefix plus a possible split, so reusing it is a
	// conservative bound for the terminal replacement as well.
	verified, err := reserveIndexCostV2(s, s.state.Configuration.VerifiedIndex, target.Running.Hash, "verified", false)
	if err != nil {
		return err
	}
	if 18+8+archive+2*initial+verified > v2OperationReserveInodes {
		return errV2Limited
	}
	return nil
}

// Counts retain the existing 64 inode / 16 MiB ordinary contract, including
// one interrupted final publication, its seven retry objects, a retained
// unselected selector, and a simultaneously live pending
// selector inode. Physical pool banks are independently preallocated.
func (m *v2ReserveManager) operationProfile(s *v2Store, op v2Operation, owner string) error {
	if s.state.Configuration == nil {
		return ErrRecovery
	}
	if raw, _, err := v2Canonical(s.state); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	if raw, _, err := v2Canonical(*s.state.Configuration); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	if op.ClosingCredit != "" || closingPotentialV2(op.Request) {
		return nil
	}
	key, err := reserveBundleKeyV2(s.state.Lineage, owner)
	if err != nil {
		return err
	}
	archive, err := reserveIndexCostV2(s, s.state.ReserveArchiveRoot, key, "archive", false)
	if err != nil {
		return err
	}
	running, err := reserveTargetRunningV2(s, op)
	if err != nil {
		return err
	}
	verified, err := reserveIndexCostV2(s, s.state.Configuration.VerifiedIndex, running, "verified", false)
	if err != nil {
		return err
	}
	base := uint64(30)
	if op.Request.Kind == OpStage {
		base = 32
	}
	if op.Request.Kind == OpRollback {
		base = 31
	}
	if base+8+archive+verified > v2OperationReserveInodes {
		return errV2Limited
	}
	return nil
}

func reserveTargetRunningV2(s *v2Store, op v2Operation) (string, error) {
	target := clone(*s.state.Configuration)
	domain := domainSnapshotV2(&target, op.Domain)
	switch op.Request.Kind {
	case OpCommit:
		if domain.Candidate == nil || domain.Candidate.Owner != op.Subject {
			return "", ErrConflict
		}
		domain.Running = domain.Candidate.Revision
	case OpRollback:
		revision, err := (&v2Coordinator{store: s}).loadDomainRevision(op.Request.Target, op.Domain)
		if err != nil {
			return "", err
		}
		domain.Running = revision
	case OpRecover:
		domain.Running = domain.LastGood
	case OpStage, OpValidate, OpSave:
	default:
		return "", ErrInvalid
	}
	if err := target.refresh(); err != nil {
		return "", err
	}
	return target.Running.Hash, nil
}

// Exact COW shape estimation creates no object, claim or capability. Repeat
// under the writer mutex before Plan/Intent because earlier work may finish.
func reserveIndexCostV2(s *v2Store, root, key, kind string, replace bool) (uint64, error) {
	if !validHash(key) {
		return 0, ErrInvalid
	}
	parents := uint64(0)
	for depth := 0; depth <= v2VerifiedDepthLimit; depth++ {
		if root == "" {
			return parents + 1, nil
		}
		var keys []string
		var children [16]string
		branch := false
		if kind == "archive" {
			node, err := s.reserveArchiveNodeV2(root, depth, key[:depth])
			if err != nil {
				return 0, err
			}
			branch = node.Kind == "branch"
			children = node.Children
			for _, entry := range node.Entries {
				keys = append(keys, entry.Key)
			}
		} else if kind == "verified" {
			node, err := (&v2Coordinator{store: s}).verifiedNode(root, depth, key[:depth])
			if err != nil {
				return 0, err
			}
			branch = node.Kind == "branch"
			children = node.Children
			for _, entry := range node.Entries {
				keys = append(keys, entry.Revision)
			}
		} else {
			return 0, ErrInvalid
		}
		if branch {
			parents++
			root = children[archiveDigitV2(key, depth)]
			continue
		}
		for _, known := range keys {
			if known == key {
				if replace {
					return parents + 1, nil
				}
				return 0, nil
			}
		}
		keys = append(keys, key)
		sort.Strings(keys)
		count, err := reserveIndexBuildCostV2(keys, depth)
		return parents + count, err
	}
	return 0, errV2Limited
}

func reserveIndexBuildCostV2(keys []string, depth int) (uint64, error) {
	if len(keys) <= v2VerifiedLeafLimit {
		return 1, nil
	}
	if depth >= v2VerifiedDepthLimit {
		return 0, errV2Limited
	}
	count := uint64(1)
	for start := 0; start < len(keys); {
		end := start + 1
		for end < len(keys) && strings.HasPrefix(keys[end], keys[start][:depth+1]) {
			end++
		}
		child, err := reserveIndexBuildCostV2(keys[start:end], depth+1)
		if err != nil {
			return 0, err
		}
		count += child
		start = end
	}
	return count, nil
}
