package configpoc

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/AsterG/andeiva/internal/recoveryreserve"
)

func (r *v2ReachabilityReader) reserveArchiveTree(hash string, level int, prefix, key string, state v2State, depth int) error {
	return r.walk(fmt.Sprintf("reserve-archive-index:%s:%s:%d:%s", key, hash, level, prefix), depth, func() error {
		var node v2ReserveArchiveNode
		release, err := r.loadBound(hash, &node, reserveArchiveLimitV2)
		if err != nil {
			return err
		}
		defer release()
		if !validReserveArchiveNodeV2(node, level, prefix) {
			return errV2Unavailable
		}
		if node.Kind == "branch" {
			for i, child := range node.Children {
				if child != "" {
					if err := r.reserveArchiveTree(child, level+1, prefix+strconv.FormatInt(int64(i), 16), key, state, depth+1); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for _, ref := range node.Entries {
			if err := r.reserveArchiveObject(ref, key, state, depth+1); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *v2ReachabilityReader) reserveArchiveObject(ref v2ReserveArchiveRef, key string, state v2State, depth int) error {
	return r.walk("reserve-archive-edge:"+key+":"+ref.Archive+":"+ref.Key+":"+ref.Kind, depth, func() error {
		var raw json.RawMessage
		release, err := r.loadBound(ref.Archive, &raw, reserveArchiveLimitV2)
		if err != nil {
			return err
		}
		defer release()
		archive, err := decodeReserveArchiveV2(raw)
		if err != nil || archive.Lineage != state.Lineage {
			return errV2Unavailable
		}
		found := reserveArchiveHasBundleV2(archive, ref)
		for _, entry := range archive.Entries {
			actual, err := reserveIdentityKeyV2(entry, ref.Kind)
			if err == nil && actual == ref.Key && entry.Claim.Owner == ref.Owner && entry.Claim.Role == ref.Role {
				found = true
			}
		}
		if ref.Kind == "claim" {
			for _, claim := range archive.UnusedEscrow {
				actual, err := reserveIdentityKeyV2(v2ReserveArchiveEntry{Claim: claim}, "claim")
				if err == nil && actual == ref.Key && claim.Owner == ref.Owner && claim.Role == ref.Role {
					found = true
				}
			}
		}
		if !found {
			return errV2Unavailable
		}
		return r.walk("reserve-archive-body:"+key+":"+ref.Archive, depth+1, func() error {
			if err := r.selectedArchiveFinalityV2(archive, state); err != nil {
				return err
			}
			if err := r.reserveArchiveFinality(archive, key, state, depth+2); err != nil {
				return err
			}
			for _, entry := range archive.Entries {
				// A never-applied operation retains an unbound plan claim, not a
				// serialized plan. Only bound capsules can own routed work edges.
				if entry.Binding != nil && entry.Claim.Role == recoveryreserve.PlanV2 {
					var plan v2ReservePlan
					if checkpointDecode(entry.Raw, &plan) != nil {
						return errV2Unavailable
					}
					if err := r.routedIntent(&plan.Intent, key, state, depth+2); err != nil {
						return err
					}
				}
			}
			for _, dependency := range archive.Dependencies {
				if err := r.snapshot(dependency, key, state, depth+2); err != nil {
					return err
				}
			}
			return nil
		})
	})
}
