package configpoc

import (
	"sort"
	"strings"
	"time"
)

const reserveMetadataObjectLimitV2 = 256 * 1024

func (m *v2ReserveManager) bootProfile(s *v2Store, record v2RecoveryRecord, target v2Configuration, owner string) error {
	if raw, _, err := v2Canonical(s.state); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	if raw, _, err := v2Canonical(target); err != nil || len(raw) > 128*1024 {
		return errV2Limited
	}
	projected := reserveProjectedEnvelopeV2(s.state, target, "firewall")
	if target.Running.Config.SchemaVersion == 7 {
		addFeatureV2(&projected, v2RoutedBootFeature)
		if target.Firewall.Running.Config.SchemaVersion==4{addFeatureV2(&projected,v2RoutedNoNetworkFeature)}
	}
	if !reserveMetadataStateFitsV2(projected) {
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
	routedObjects := uint64(0)
	if target.Running.Config.SchemaVersion == 7 && target.Firewall.Running.Config.SchemaVersion == 6 {
		routedObjects = 5
	}
	if 18+8+archive+2*initial+verified+routedObjects > v2OperationReserveInodes {
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
		reserveGuardFeatureBudgetV2(s, &projected)
		if !reserveMetadataStateFitsV2(projected) {
			return errV2Limited
		}
		if err := reserveProfileFutureFitsV2(s, target); err != nil {
			return err
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
	reserveGuardFeatureBudgetV2(s, &projected)
	if !reserveMetadataStateFitsV2(projected) {
		return errV2Limited
	}
	if err := reserveProfileFutureFitsV2(s, target); err != nil {
		return err
	}
	if closingPotentialV2(op.Request) {
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
	if op.Domain == "routed" {
		now := op.Accepted
		if now.IsZero() {
			now = s.state.Clock
		}
		target, _, err := routedTargetV2(s, op, *s.state.Configuration, now, "reserve-forecast")
		if target.Pending != nil && target.Pending.OriginCommit == op.ID {
			target.Pending.Deadline = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
		}
		return target, err
	}
	target := clone(*s.state.Configuration)
	target.Intent = nil
	domain := domainSnapshotV2(&target, op.Domain)
	changed := true
	switch op.Request.Kind {
	case OpCommit:
		if domain.Candidate == nil || domain.Candidate.Owner != op.Subject || domain.Candidate.Base != domain.Running.Hash {
			return target, ErrConflict
		}
		domain.Running = domain.Candidate.Revision
		domain.Candidate = nil
		if op.Request.ConfirmSeconds == nil {
			return target, ErrInvalid
		}
		if *op.Request.ConfirmSeconds == 0 {
			domain.LastGood = domain.Running
		}
	case OpRollback:
		revision, err := (&v2Coordinator{store: s}).loadDomainRevision(op.Request.Target, op.Domain)
		if err != nil {
			return target, err
		}
		domain.Running = revision
		domain.Candidate = nil
		if op.Domain == "firewall" {
			domain.LastGood = revision
		}
	case OpRecover:
		if op.Domain != "firewall" {
			return target, ErrDenied
		}
		domain.Running = domain.LastGood
		domain.Candidate = nil
		target.Pending = nil
		target.RecoveryRequired = false
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
	if op.Request.Kind == OpCommit && *op.Request.ConfirmSeconds > 0 || op.Request.Kind == OpRollback && op.Domain == "local_services" {
		_, previous, err := v2Canonical(*s.state.Configuration)
		if err != nil {
			return target, errV2Unavailable
		}
		target.Pending = &v2Confirmation{OriginCommit: op.ID, Lease: "reserve-forecast", Owner: op.Subject, Domain: op.Domain, Previous: previous, Target: target.Running.Hash, Deadline: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)}
	}
	return target, nil
}

func reserveProfileFutureFitsV2(s *v2Store, target v2Configuration) error {
	state := s.state
	reserveGuardFeatureBudgetV2(s, &state)
	state.Configuration = &target
	_, hash, err := v2Canonical(*s.state.Configuration)
	if err != nil {
		return errV2Unavailable
	}
	return reserveMetadataFutureFitsV2(state, func(key string, value any) error {
		// A new lease refers to the current canonical snapshot, which is not
		// necessarily a standalone object yet. No pre-ACK write is required.
		if key == hash {
			out, ok := value.(*v2Configuration)
			if !ok {
				return errV2Unavailable
			}
			*out = clone(*s.state.Configuration)
			return nil
		}
		return s.readObject(key, value)
	})
}

// Used for size bounds only, never persisted or presented as an applied
// configuration. Scalar maxima cover digit growth; placeholders account for
// newly populated fixed-width hash references.
func reserveProjectedEnvelopeV2(st v2State, target v2Configuration, _ string) v2State {
	projected := st
	projected.Configuration = &target
	if hasFeatureV2(st, v2RoutedFeature) {
		projected.RoutedActive = &v2RoutedActive{Work: strings.Repeat("f", 64), Side: "target"}
	}
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
