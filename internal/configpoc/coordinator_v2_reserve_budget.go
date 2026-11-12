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
	if !reserveMetadataStateFitsV2(reserveProjectedEnvelopeV2(s.state, target, "firewall")) {
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
	if op.ClosingCredit != "" {
		target, err := reserveTargetEnvelopeV2(s, op)
		if err != nil {
			return err
		}
		projected := reserveProjectedEnvelopeV2(s.state, target, op.Domain)
		if !reserveMetadataStateFitsV2(projected) {
			return errV2Limited
		}
		return nil
	}
	if raw, _, err := v2Canonical(s.state); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	if raw, _, err := v2Canonical(*s.state.Configuration); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	target, err := reserveTargetEnvelopeV2(s, op)
	if err != nil {
		return err
	}
	if data, _, e := v2Canonical(target); e != nil || len(data) > 128*1024 {
		return errV2Limited
	}
	projected := reserveProjectedEnvelopeV2(s.state, target, op.Domain)
	if !reserveMetadataStateFitsV2(projected) {
		return errV2Limited
	}
	if closingPotentialV2(op.Request) {
		confirmed := clone(target)
		domain := domainSnapshotV2(&confirmed, op.Domain)
		domain.LastGood = domain.Running
		confirmed.Pending = nil
		if confirmed.refresh() != nil || !reserveMetadataStateFitsV2(reserveProjectedEnvelopeV2(s.state, confirmed, op.Domain)) {
			return errV2Limited
		}
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
	running := target.Running.Hash
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

func reserveTargetEnvelopeV2(s *v2Store, op v2Operation) (v2Configuration, error) {
	target := clone(*s.state.Configuration)
	domain := domainSnapshotV2(&target, op.Domain)
	changed := true
	switch op.Request.Kind {
	case OpCommit:
		if domain.Candidate == nil || domain.Candidate.Owner != op.Subject {
			return target, ErrConflict
		}
		domain.Running = domain.Candidate.Revision
		domain.Candidate = nil
	case OpRollback:
		revision, err := (&v2Coordinator{store: s}).loadDomainRevision(op.Request.Target, op.Domain)
		if err != nil {
			return target, err
		}
		domain.Running = revision
		domain.Candidate = nil
	case OpRecover:
		domain.Running = domain.LastGood
		domain.Candidate = nil
	case OpConfirm:
		domain.LastGood = domain.Running
		target.Pending = nil
	case OpStage:
		revision, err := Canonical(*op.Request.Config)
		if err != nil {
			return target, err
		}
		domain.Candidate = &v2DomainCandidate{Owner: op.Subject, Base: domain.Running.Hash, Revision: revision}
	case OpValidate:
		changed = false
	case OpSave:
		changed = domain.Startup.Hash != domain.Running.Hash
		domain.Startup = domain.Running
	default:
		return target, ErrInvalid
	}
	if changed {
		if domain.Generation == ^uint64(0) {
			return target, errV2Limited
		}
		domain.Generation++
	}
	if err := target.refresh(); err != nil {
		return target, err
	}
	return target, nil
}

// Used for size bounds only, never persisted or presented as an applied
// configuration. Scalar maxima cover digit growth; placeholders account for
// newly populated fixed-width hash references.
func reserveProjectedEnvelopeV2(st v2State, target v2Configuration, _ string) v2State {
	projected := st
	projected.Configuration = &target
	reserveNormalizeEnvelopeScalarsV2(&projected)
	return projected
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
