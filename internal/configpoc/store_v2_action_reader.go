package configpoc

import (
	"bytes"
	"fmt"
	"os"
)

// Every authority dependency survives until final readback, even when the FD
// cache is full. The immutable bytes share the original active-byte charge.
// This is per-call storage, never an authority cache across selections.
const actionDependencyMetadataBytesV2 = 512

type actionReadDependencyV2 struct {
	info   os.FileInfo
	data   []byte
	pinned bool
}
type actionReadDependenciesV2 struct {
	entries       map[string]actionReadDependencyV2
	unpinnedBytes uint64
	metadataBytes uint64
}

func (a *actionReadDependenciesV2) get(r *v2ReachabilityReader, name string, limit int64) ([]byte, bool, error) {
	e, ok := a.entries[name]
	if !ok {
		return nil, false, nil
	}
	if err := r.step(); err != nil {
		return nil, true, err
	}
	if int64(len(e.data)) > limit {
		return nil, true, errV2Unavailable
	}
	return e.data, true, nil
}
func (a *actionReadDependenciesV2) keep(r *v2ReachabilityReader, name string, info os.FileInfo, data []byte, pinned bool) error {
	if name == "selected.json" {
		return errV2Unavailable
	}
	if _, exists := a.entries[name]; exists {
		return errV2Unavailable
	}
	if uint64(len(a.entries)) >= r.budget.Objects {
		return errV2InspectionBudget
	}
	// Keep the existing half-budget raw-cache cap; reserve room for decoding and
	// final byte comparison. Running out of descriptors never drops a dependency.
	used := a.unpinnedBytes + a.metadataBytes
	if r.cache != nil {
		used += r.cache.bytes
	}
	addition := uint64(actionDependencyMetadataBytesV2)
	if !pinned {
		addition += uint64(len(data))
	}
	if used > r.budget.ActiveBytes/2 || addition > r.budget.ActiveBytes/2-used || r.active > r.budget.ActiveBytes || actionDependencyMetadataBytesV2 > r.budget.ActiveBytes-r.active {
		return errV2InspectionBudget
	}
	r.active += actionDependencyMetadataBytesV2
	a.metadataBytes += actionDependencyMetadataBytesV2
	if r.active > r.report.PeakActiveBytes {
		r.report.PeakActiveBytes = r.active
	}
	a.entries[name] = actionReadDependencyV2{info: info, data: data, pinned: pinned}
	if !pinned {
		a.unpinnedBytes += uint64(len(data))
	}
	return nil
}
func (r *v2ReachabilityReader) closeSelectedV2() error {
	if r.action != nil {
		r.active -= r.action.unpinnedBytes + r.action.metadataBytes
		r.action.metadataBytes = 0
		r.action.unpinnedBytes = 0
		clear(r.action.entries)
	}
	return r.cache.close(r)
}
func (r *v2ReachabilityReader) revalidateSelectedV2() error {
	if err := r.cache.revalidate(r); err != nil {
		return err
	}
	if r.action == nil {
		return nil
	}
	for name, e := range r.action.entries {
		if e.pinned {
			pinned, ok := r.cache.entries[name]
			if !ok || !selectedCacheSameV2(e.info, pinned.info) || !bytes.Equal(e.data, pinned.data) {
				return errV2Unavailable
			}
			continue
		}
		if r.ctx.Err() != nil {
			return errV2Unavailable
		}
		if r.report.IOCalls > r.budget.IOCalls || r.budget.IOCalls-r.report.IOCalls < 128 {
			return errV2InspectionBudget
		}
		r.report.IOCalls += 128
		info, err := r.shared.CheckFile(r.area, name, max(int64(len(e.data)), 1))
		if err != nil || !selectedCacheSameV2(e.info, info) {
			return errV2Unavailable
		}
		n := uint64(len(e.data))
		if r.report.BytesRead > r.budget.Bytes || n > r.budget.Bytes-r.report.BytesRead || r.active > r.budget.ActiveBytes || n > r.budget.ActiveBytes-r.active {
			return errV2InspectionBudget
		}
		r.report.BytesRead += n
		r.active += n
		if r.active > r.report.PeakActiveBytes {
			r.report.PeakActiveBytes = r.active
		}
		data, readErr := r.shared.ReadFile(r.ctx, r.area, name, max(len(e.data), 1))
		r.active -= n
		if readErr != nil || !bytes.Equal(data, e.data) {
			return errV2Unavailable
		}
		after, err := r.shared.CheckFile(r.area, name, max(int64(len(e.data)), 1))
		if err != nil || !selectedCacheSameV2(e.info, after) {
			return errV2Unavailable
		}
	}
	return nil
}

// readSelection has already validated the complete bounded header/state segment.
// Only the current action closure is walked here. Full G1 remains the authority
// for retention/GC and the default selected-reader policy.
func (r *v2ReachabilityReader) actionAuthorityV2(s *v2Store) error {
	state := s.state
	key := s.selection.State
	if state.Configuration == nil {
		return errV2Unavailable
	}
	if err := (&v2Coordinator{store: s}).validateReferencesLocked(); err != nil {
		return err
	}
	if err := r.routedBootBoundary(state.RoutedBootBoundary, key, state, 2); err != nil {
		return err
	}
	if err := r.activeReserves(key, state, 2); err != nil {
		return err
	}
	if err := r.configuration(*state.Configuration, key, state, 2, true); err != nil {
		return err
	}
	// Closing entries are just as live as ordinary entries. A keyed lookup binds
	// every retained open operation to its protected typed outcome and reserve.
	for _, ns := range state.Namespaces {
		for _, id := range namespaceOpenIDsV2(ns) {
			op, err := r.lookup(state, ns.Subject, id)
			if err != nil {
				return err
			}
			if op.Outcome != nil {
				if err := r.operationAudit(op, state, 2); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Check a consumed protected audit leaf and its predecessor's reference shape.
// Deliberately do not enumerate that predecessor. Its integrity is a full-G1
// maintenance responsibility, not proof of this action's typed facts.
func (r *v2ReachabilityReader) actionAuditLeafV2(hash string, sequence, generation uint64, depth int) error {
	if !validHash(hash) || sequence == 0 || generation == 0 {
		return errV2Unavailable
	}
	return r.walk(fmt.Sprintf("action-audit:%s:%d:%d", hash, sequence, generation), depth, func() error {
		var audit v2CoordinatorAudit
		if err := r.object(hash, &audit); err != nil {
			return err
		}
		if audit.Format != v2Format || audit.Sequence != sequence || audit.Generation == 0 || audit.Generation > generation || !validHash(audit.Running) || !validHash(audit.Startup) || audit.Operation == "" || audit.At.IsZero() || (audit.Previous == "") != (sequence == 1) || (audit.Previous != "" && !validHash(audit.Previous)) {
			return errV2Unavailable
		}
		return nil
	})
}

func validActionAuditShapeV2(a v2CoordinatorAudit) bool {
	return a.Format == v2Format && a.Sequence > 0 && a.Generation > 0 && validHash(a.Running) && validHash(a.Startup) && a.Operation != "" && !a.At.IsZero() && (a.Previous == "") == (a.Sequence == 1) && (a.Previous == "" || validHash(a.Previous))
}
