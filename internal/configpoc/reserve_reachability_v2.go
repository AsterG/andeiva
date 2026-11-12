package configpoc

import (
	"fmt"
	"strconv"
	"strings"
)

func (r *v2ReachabilityReader) closingIndex(hash string, level int, prefix, key string, state v2State, depth int, count *uint64) error {
	return r.walk(fmt.Sprintf("closing-index:%s:%s:%d:%s", key, hash, level, prefix), depth, func() error {
		var node v2ClosingIndexNode
		release, err := r.load(hash, &node)
		if err != nil {
			return err
		}
		defer release()
		if !validClosingNodeV2(node, level) || len(prefix) != level {
			return errV2Unavailable
		}
		if level < 16 {
			for i, child := range node.Children {
				if child != "" {
					if err := r.closingIndex(child, level+1, prefix+strconv.FormatInt(int64(i), 16), key, state, depth+1, count); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if !strings.HasPrefix(closingSequenceKeyV2(node.Sequence), prefix) || node.Sequence > state.HighWater {
			return errV2Unavailable
		}
		var op v2Operation
		releaseOp, err := r.load(node.Operation, &op)
		if err != nil {
			return err
		}
		defer releaseOp()
		if !(&v2Store{state: state}).validOperation(op) || op.Sequence != node.Sequence || op.ClosingCredit == "" || op.Lineage != state.Lineage || op.Retired {
			return errV2Unavailable
		}
		*count++
		if op.Outcome != nil {
			return r.operationAudit(op, state, depth+1)
		}
		return nil
	})
}

func (r *v2ReachabilityReader) closingObject(state v2State, sequence uint64) (string, bool, error) {
	key := closingSequenceKeyV2(sequence)
	hash := state.ClosingIndexRoot
	for level := 0; level <= 16 && hash != ""; level++ {
		var node v2ClosingIndexNode
		if err := r.object(hash, &node); err != nil {
			return "", false, err
		}
		if !validClosingNodeV2(node, level) {
			return "", false, errV2Unavailable
		}
		if level == 16 {
			if node.Sequence != sequence {
				return "", false, errV2Unavailable
			}
			return node.Operation, true, nil
		}
		digit := strings.IndexByte("0123456789abcdef", key[level])
		if digit < 0 {
			return "", false, errV2Unavailable
		}
		hash = node.Children[digit]
	}
	return "", false, nil
}

func (r *v2ReachabilityReader) reserveBundle(bundle *v2ReserveBundle, key string, state v2State, depth int) error {
	if !validReserveBundleV2(bundle) || bundle.Scope.Lineage != state.Lineage {
		return errV2Unavailable
	}
	_, bundleHash, err := v2Canonical(bundle)
	if err != nil {
		return err
	}
	return r.walk("reserve-bundle:"+key+":"+bundleHash, depth, func() error {
		if plan := bundle.PlanIntent; plan != nil {
			if plan.GuardDeadline != nil {
				var p, t v2Configuration
				if r.object(plan.Previous, &p) != nil || r.object(plan.Target, &t) != nil || validateGuardDeadlineContextV2(plan, p, t, hasFeatureV2(state, v2GuardDeadlineFeature), false) != nil {
					return errV2Unavailable
				}
			}
			if plan.Operation != reserveWorkV2(bundle) || plan.Domain != bundle.Scope.Domain || !validHash(plan.Previous) || !validHash(plan.Target) {
				return errV2Unavailable
			}
			if err := r.snapshot(plan.Previous, key, state, depth+1); err != nil {
				return err
			}
			if err := r.snapshot(plan.Target, key, state, depth+1); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *v2ReachabilityReader) activeReserves(key string, state v2State, depth int) error {
	owners := map[string]bool{}
	for _, active := range state.ActiveReserves {
		if active.Bundle == nil || active.Bundle.Scope.Kind != "operation" || reserveWorkV2(active.Bundle) != active.Work {
			return errV2Unavailable
		}
		if owners[active.Bundle.Scope.Bundle] {
			return errV2Unavailable
		}
		owners[active.Bundle.Scope.Bundle] = true
		op, err := r.lookup(state, active.Bundle.Scope.Subject, active.Work)
		if err != nil || op.Retired || op.Reserve == nil || !reserveJSONEqualV2(op.Reserve, active.Bundle) {
			return errV2Unavailable
		}
		if err := r.reserveBundle(active.Bundle, key, state, depth); err != nil {
			return err
		}
	}
	if active := state.SystemBundle; active != nil {
		if active.Bundle == nil || state.Configuration == nil || reserveWorkV2(active.Bundle) != active.Work {
			return errV2Unavailable
		}
		if owners[active.Bundle.Scope.Bundle] {
			return errV2Unavailable
		}
		matched := false
		for _, hash := range []string{state.Configuration.LastRecovery, state.Configuration.LastCompletedBoot} {
			if hash == "" {
				continue
			}
			var record v2RecoveryRecord
			if err := r.object(hash, &record); err != nil {
				return err
			}
			if record.ID == active.Work && validRecoveryRecordV2(record, state.Lineage) && reserveJSONEqualV2(record.Reserve, active.Bundle) {
				matched = true
				break
			}
		}
		if !matched {
			return errV2Unavailable
		}
		if err := r.reserveBundle(active.Bundle, key, state, depth); err != nil {
			return err
		}
	}
	return nil
}
