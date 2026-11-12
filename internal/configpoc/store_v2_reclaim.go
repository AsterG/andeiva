package configpoc

import (
	"context"
	"errors"
	"os"
	"sort"
	"time"
)

const v2ReclaimPageLimit = 1024

// Authority is intentionally process-local. Reopen loses every entry: matching
// filenames, hashes, or a persisted opt-in marker never reconstruct provenance.
type v2ReclaimSession struct {
	root    os.FileInfo
	lineage string
	pages   map[string]os.FileInfo
	revoked bool
}

type v2ReclaimReport struct {
	AuthorityRevoked                         bool
	Complete                                 bool
	Tracked, Retained, Removed, RemovedBytes uint64
	LockDuration                             time.Duration
}

// Closed set of existing producer contracts, not a structural JSON classifier.
// State/selection/operation COW roots are covered by G1 once selected; failed
// publication fences the writer. Configuration, audit and witness producers
// have their distinct typed reference graphs, never an arbitrary index-page
// root. Opaque catalogue audit wrappers have no object edges in their payload.
// Any new/aliased/raw type must lose authority until its graph is reviewed.
func (s *v2Store) revokeReclaimGeneric(value any) {
	if s.reclaim == nil {
		return
	}
	switch value.(type) {
	case v2State, v2Selection, v2Operation, v2Configuration,
		v2CoordinatorAudit, v2RecoveryRecord, v2VerifiedNode,
		Config, v2CompositeConfig:
		return
	case struct {
		Format    string `json:"format"`
		Operation string `json:"operation"`
		Data      []byte `json:"data"`
	}, struct{ Format, Operation, Code string }:
		return
	default:
		// Before serialization: a failed marshal provides no stronger proof.
		s.revokeReclaimAuthority()
	}
}

func (s *v2Store) revokeReclaimAuthority() {
	if s.reclaim != nil {
		clear(s.reclaim.pages)
		s.reclaim.revoked = true
	}
}

func preservesReclamationV2(previous, next v2State) bool {
	return previous.ReclamationVersion <= 1 && next.ReclamationVersion <= 1 && next.ReclamationVersion >= previous.ReclamationVersion
}

// Explicit trusted preparation only; no runtime, API or automatic open binding.
// The marker changes reader compatibility, not configuration or replay identity.
func (s *v2Store) enableIndexReclamation() error {
	if s == nil {
		return errV2Invalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.blocked || s.lock == nil || s.state.Configuration != nil && (s.state.Configuration.Intent != nil || s.state.Configuration.Pending != nil || s.state.Configuration.RecoveryRequired) {
		return errV2Unavailable
	}
	if s.reclaim != nil {
		return nil
	}
	dir, err := s.physicalDirectory()
	if err != nil {
		return err
	}
	info, statErr := dir.Stat()
	closeErr := dir.Close()
	if statErr != nil || closeErr != nil {
		return errV2Unavailable
	}
	if s.state.ReclamationVersion == 0 {
		if err = s.physicalCapacity(2*v2ObjectLimit+4096, 3); err != nil {
			return err
		}
		st := clone(s.state)
		st.ReclamationVersion = 1
		if err = s.publish(st); err != nil {
			return err
		}
	}
	if s.state.ReclamationVersion != 1 {
		return errV2Unavailable
	}
	s.reclaim = &v2ReclaimSession{root: info, lineage: s.state.Lineage, pages: make(map[string]os.FileInfo)}
	return nil
}

func (s *v2Store) rememberReclaimPage(hash string, info os.FileInfo) {
	r := s.reclaim
	if r == nil || r.revoked || s.state.ReclamationVersion != 1 || s.state.Lineage != r.lineage || len(r.pages) >= v2ReclaimPageLimit || !regularOwned(info, v2ObjectLimit) || !v2PhysicalSameDevice(r.root, info) {
		return
	}
	r.pages[hash] = info
}

// Each unlink is independently safe after a complete current closure. There is
// no crash-resume batch: unremoved objects become held after process restart.
// LockDuration includes cooperative filesystem work, not a hard I/O deadline.
func (s *v2Store) reclaimIndexPages(ctx context.Context, budget v2ReachabilityBudget) (report v2ReclaimReport, result error) {
	if s == nil || ctx == nil || !validReachabilityBudgetV2(budget) {
		return report, errV2Invalid
	}
	s.mu.Lock()
	started := time.Now()
	defer func() { report.LockDuration = time.Since(started); s.mu.Unlock() }()
	if err := ctx.Err(); err != nil {
		return report, err
	}
	r := s.reclaim
	if s.blocked || r == nil || s.lock == nil || s.state.ReclamationVersion != 1 || s.state.Lineage != r.lineage {
		return report, errV2Unavailable
	}
	if s.state.Configuration != nil && (s.state.Configuration.Intent != nil || s.state.Configuration.Pending != nil || s.state.Configuration.RecoveryRequired) {
		return report, errV2Unavailable
	}
	defer func() {
		if result != nil && !errors.Is(result, errV2InspectionBudget) && !errors.Is(result, context.Canceled) && !errors.Is(result, context.DeadlineExceeded) {
			s.blocked = true
		}
	}()
	report.Tracked = uint64(len(r.pages))
	report.AuthorityRevoked = r.revoked
	reader := &v2ReachabilityReader{ctx: ctx, area: s.root, root: r.root, budget: budget, objects: make(map[string]bool), edges: make(map[string]uint8)}
	if err := reader.verifyScope(s.lock); err != nil {
		return report, err
	}
	closure, err := reader.traceLocked(s.lock)
	if err != nil || !closure.Complete || reader.report.IOCalls > budget.IOCalls {
		if err == nil {
			err = errV2InspectionBudget
		}
		return report, err
	}
	if closure.Current != s.selector.Current || closure.Previous != s.selector.Previous || closure.State != s.selection.State || closure.Sequence != s.selection.Sequence || closure.Lineage != r.lineage {
		return report, errV2Unavailable
	}
	keys := make([]string, 0, len(r.pages))
	for hash := range r.pages {
		keys = append(keys, hash)
	}
	sort.Strings(keys)
	for _, hash := range keys {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if reader.objects[hash] {
			report.Retained++
			continue
		}
		info := r.pages[hash]
		if err := s.reclaimPage(ctx, reader, hash, info, &report); err != nil {
			return report, err
		}
	}
	report.Complete = true
	return report, nil
}

func (s *v2Store) reclaimPage(ctx context.Context, reader *v2ReachabilityReader, hash string, expected os.FileInfo, report *v2ReclaimReport) error {
	name, err := v2ObjectName(hash)
	if err != nil {
		return err
	}
	// Read through the same no-follow, size/hash and inode-pinned G1 checks.
	var page v2Page
	if err = reader.object(hash, &page); err != nil {
		return err
	}
	if !v2ValidPage(page, page.Level) || page.Level < 0 || page.Level > 2 {
		return errV2Unavailable
	}
	actual, err := s.physicalRecord(name, expected)
	if err != nil {
		return err
	}
	size := actual.Size()
	allocated, err := v2Allocated(actual)
	if err != nil || size < 0 || uint64(size) > s.used.Bytes || s.used.Inodes == 0 || allocated > s.physical.files || s.physical.inodes <= 1 {
		return errV2Unavailable
	}
	if err = reader.verifyScope(s.lock); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = s.point("before_reclaim_unlink"); err != nil {
		return err
	}
	// Recheck after the test/fault boundary; the private directory and exclusive
	// writer lease exclude cooperating name replacements through this operation.
	if _, err = s.physicalRecord(name, expected); err != nil {
		return err
	}
	if err = s.root.Remove(name); err != nil {
		s.blocked = true
		return errV2Unavailable
	}
	delete(s.reclaim.pages, hash)
	if s.point("after_reclaim_unlink") != nil || checkpointSync(s.root, nil, "") != nil {
		s.blocked = true
		return errV2Uncertain
	}
	// These counters describe named files only; admission still probes Fstatfs.
	s.used.Bytes -= uint64(size)
	s.used.Inodes--
	s.physical.files -= allocated
	s.physical.inodes--
	if err = s.physicalRefreshDirectory(); err != nil {
		s.blocked = true
		return err
	}
	if err = s.point("after_reclaim_sync"); err != nil {
		s.blocked = true
		return errV2Uncertain
	}
	report.Removed++
	report.RemovedBytes += uint64(size)
	return nil
}
