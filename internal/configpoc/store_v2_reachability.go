package configpoc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"io"
	"os"
	"strings"
)

var errV2InspectionBudget = errors.New("ANDEIVA_REFERENCE_INSPECTION_BUDGET")

// These limits bound a trusted read-only inspection, not a reclamation policy.
// Object/edge/depth and active payload caps bound allocations; they are not an
// OS heap quota. Filesystem reads are cancellable between calls, not within a
// stalled kernel I/O operation.
type v2ReachabilityBudget struct {
	Entries, Objects, Edges, IOCalls uint64
	Bytes, ActiveBytes               uint64
	Depth                            int
}

type v2ReachabilityReport struct {
	Complete                          bool
	Current, Previous, State, Lineage string
	Sequence                          uint64
	Entries, Objects, Edges, IOCalls  uint64
	BytesRead, PeakActiveBytes        uint64
	MaximumDepth                      int
	OpaqueAuditObjects                uint64
}

type v2ReachabilityReader struct {
	// Per-inspection evidence only: set after a successful bounded read proves
	// an immutable record's hash or encoding is invalid. I/O is not corruption.
	integrityCorruption bool
	action              *actionReadDependenciesV2
	ctx                 context.Context
	area                *os.Root
	budget              v2ReachabilityBudget
	report              v2ReachabilityReport
	active              uint64
	objects             map[string]bool
	edges               map[string]uint8
	root                os.FileInfo
	shared              *recoveryreserve.ReaderAccessV2
	ownerRead           bool // Writer-owned maintenance only; helper readers remain group-scoped.
	cache               *selectedReadCacheV2
}

func (r *v2ReachabilityReader) step() error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if r.report.IOCalls >= r.budget.IOCalls {
		return errV2InspectionBudget
	}
	r.report.IOCalls++
	return nil
}

// Cleanup must still run after cancellation or a depleted work budget. Its
// calls are counted, and exceeding the budget prevents a complete report.
func (r *v2ReachabilityReader) closeFile(f *os.File) error {
	r.report.IOCalls++
	if f.Close() != nil {
		return errV2Unavailable
	}
	return nil
}

func (r *v2ReachabilityReader) walk(key string, depth int, visit func() error) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if depth < 0 || depth > r.budget.Depth {
		return errV2InspectionBudget
	}
	if depth > r.report.MaximumDepth {
		r.report.MaximumDepth = depth
	}
	if r.edges[key] == 2 {
		return nil
	}
	if r.edges[key] == 1 {
		return errV2Unavailable
	}
	if r.report.Edges >= r.budget.Edges || uint64(len(r.edges)) >= r.budget.Edges {
		return errV2InspectionBudget
	}
	r.edges[key] = 1
	r.report.Edges++
	if err := visit(); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	r.edges[key] = 2
	return nil
}

func (r *v2ReachabilityReader) object(hash string, target any) error {
	release, err := r.load(hash, target)
	if err != nil {
		return err
	}
	defer release()
	if r.action != nil {
		if audit, ok := target.(*v2CoordinatorAudit); ok && !validActionAuditShapeV2(*audit) {
			return errV2Unavailable
		}
	}
	return nil
}

func (r *v2ReachabilityReader) load(hash string, target any) (func(), error) {
	return r.loadBound(hash, target, v2ObjectLimit)
}

func (r *v2ReachabilityReader) loadBound(hash string, target any, limit int64) (func(), error) {
	if limit <= 0 || limit > v2ObjectLimit {
		return nil, errV2InspectionBudget
	}
	if r.report.Edges >= r.budget.Edges {
		return nil, errV2InspectionBudget
	}
	r.report.Edges++
	name, err := v2ObjectName(hash)
	if err != nil {
		return nil, err
	}
	if !r.objects[hash] {
		if uint64(len(r.objects)) >= r.budget.Objects {
			return nil, errV2InspectionBudget
		}
		r.objects[hash] = true
		r.report.Objects++
	}
	data, release, err := r.read(name, limit)
	if err != nil {
		return nil, err
	}
	if checkpointDigest(data) != hash || checkpointDecode(data, target) != nil {
		r.integrityCorruption = true
		release()
		return nil, errV2Unavailable
	}
	return release, nil
}

func (r *v2ReachabilityReader) read(name string, limit int64) (data []byte, release func(), result error) {
	release = func() {}
	if r.shared != nil {
		return r.readSharedRecordV2(name, limit)
	}
	if limit <= 0 || limit > v2ObjectLimit {
		return nil, release, ErrInvalid
	}
	if name != "selected.json" && !(len(name) == 76 && strings.HasPrefix(name, "object-") && strings.HasSuffix(name, ".json") && validHash(name[7:71])) {
		return nil, release, errV2Unavailable
	}
	if err := r.step(); err != nil {
		return nil, release, err
	}
	f, err := openRecordFile(r.area, name)
	if err != nil {
		return nil, release, errV2Unavailable
	}
	defer func() {
		if r.closeFile(f) != nil && result == nil {
			result = errV2Unavailable
		}
	}()
	if err := r.step(); err != nil {
		return nil, release, err
	}
	info, err := f.Stat()
	if err != nil || !regularOwned(info, limit) || !v2PhysicalSameDevice(r.root, info) {
		return nil, release, errV2Unavailable
	}
	fileSize := info.Size()
	if fileSize < 0 || fileSize > v2ObjectLimit {
		return nil, release, errV2Unavailable
	}
	size := uint64(fileSize)
	if size > r.budget.Bytes-r.report.BytesRead || size > r.budget.ActiveBytes-r.active {
		return nil, release, errV2InspectionBudget
	}
	r.active += size
	if r.active > r.report.PeakActiveBytes {
		r.report.PeakActiveBytes = r.active
	}
	reserved := true
	defer func() {
		if result != nil && reserved {
			r.active -= size
		}
	}()
	data = make([]byte, int(fileSize))
	for offset := 0; offset < len(data); {
		if err := r.step(); err != nil {
			return nil, release, err
		}
		end := offset + 64*1024
		if end > len(data) {
			end = len(data)
		}
		n, e := f.Read(data[offset:end])
		if n < 0 || n > end-offset {
			return nil, release, errV2Unavailable
		}
		r.report.BytesRead += uint64(n)
		offset += n
		if e != nil && !(e == io.EOF && offset == len(data)) {
			return nil, release, errV2Unavailable
		}
		if n == 0 && offset < len(data) {
			return nil, release, errV2Unavailable
		}
	}
	if err := r.step(); err != nil {
		return nil, release, err
	}
	after, err := f.Stat()
	if err != nil || !sameRecordFile(info, after) {
		return nil, release, errV2Unavailable
	}
	if err := r.step(); err != nil {
		return nil, release, err
	}
	named, err := r.area.Lstat(name)
	if err != nil || !sameRecordFile(info, named) {
		return nil, release, errV2Unavailable
	}
	reserved = false
	released := false
	release = func() {
		if !released {
			r.active -= size
			released = true
		}
	}
	return data, release, nil
}

func validReachabilityBudgetV2(b v2ReachabilityBudget) bool {
	return b.Entries > 0 && b.Entries <= 1<<20 && b.Objects > 0 && b.Objects <= 16384 && b.Edges > 0 && b.Edges <= 1<<18 && b.IOCalls > 0 && b.IOCalls <= 1<<24 && b.Bytes > 0 && b.Bytes <= 1<<30 && b.ActiveBytes > 0 && b.ActiveBytes <= 16<<20 && b.Depth > 0 && b.Depth <= 128
}

// inspectReachabilityV2 never creates a lock, opens a runtime, writes metadata,
// applies engines or classifies files as deletable. Complete only describes the
// bounded known reference closure; it is not a GC authorization or safety mark.
func inspectReachabilityV2(ctx context.Context, area *os.Root, budget v2ReachabilityBudget) (report v2ReachabilityReport, result error) {
	if ctx == nil || area == nil || !validReachabilityBudgetV2(budget) {
		return report, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	reader := &v2ReachabilityReader{ctx: ctx, area: area, budget: budget, objects: map[string]bool{}, edges: map[string]uint8{}}
	lock, root, err := reader.lockExisting()
	if err != nil {
		return reader.report, err
	}
	reader.root = root
	defer func() {
		if reader.closeFile(lock) != nil && result == nil {
			result = errV2Unavailable
		}
		if reader.report.IOCalls > budget.IOCalls && result == nil {
			result = errV2InspectionBudget
		}
		report = reader.report
		if result != nil {
			report.Complete = false
		}
	}()
	return reader.traceLocked(lock)
}

// The caller retains the exclusive writer lease and serializes all store access.
// This seam neither acquires a second flock nor grants deletion authority.
func (reader *v2ReachabilityReader) traceLocked(lock *os.File) (report v2ReachabilityReport, result error) {
	if err := reader.census(); err != nil {
		return report, err
	}
	var selector v2Selector
	data, release, err := reader.read("selected.json", 4096)
	if err != nil {
		return report, err
	}
	decodeErr := checkpointDecode(data, &selector)
	release()
	if decodeErr != nil || selector.Format != v2Format || !validHash(selector.Current) || (selector.Previous != "" && !validHash(selector.Previous)) {
		return report, errV2Unavailable
	}
	if err := reader.selection(selector.Current, &selector.Previous); err != nil {
		return report, err
	}
	if selector.Previous != "" {
		if err := reader.selection(selector.Previous, nil); err != nil {
			return report, err
		}
	}
	var final v2Selector
	data, release, err = reader.read("selected.json", 4096)
	if err != nil {
		return report, err
	}
	decodeErr = checkpointDecode(data, &final)
	release()
	if decodeErr != nil || final != selector {
		return report, errV2Unavailable
	}
	if err := reader.verifyScope(lock); err != nil {
		return report, err
	}
	reader.report.Current, reader.report.Previous = selector.Current, selector.Previous
	reader.report.Complete = true
	return reader.report, nil
}

func (r *v2ReachabilityReader) census() (result error) {
	if err := r.step(); err != nil {
		return err
	}
	dir, _, err := r.directory()
	if err != nil {
		return err
	}
	defer func() {
		if r.closeFile(dir) != nil && result == nil {
			result = errV2Unavailable
		}
	}()
	for {
		if err := r.step(); err != nil {
			return err
		}
		entries, readErr := dir.ReadDir(64)
		for _, entry := range entries {
			if r.report.Entries >= r.budget.Entries {
				return errV2InspectionBudget
			}
			r.report.Entries++
			name := entry.Name()
			if name != "checkpoint.lock" && name != "selected.json" && !(len(name) == 76 && strings.HasPrefix(name, "object-") && strings.HasSuffix(name, ".json") && validHash(name[7:71])) {
				return errV2Unavailable
			}
			if err := r.step(); err != nil {
				return err
			}
			info, err := r.area.Lstat(name)
			if err != nil || !r.profileRecordV2(name, info) || !v2PhysicalSameDevice(r.root, info) {
				return errV2Unavailable
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return errV2Unavailable
		}
	}
}

func (r *v2ReachabilityReader) directory() (*os.File, os.FileInfo, error) {
	if r.shared != nil {
		return r.sharedDirectoryV2()
	}
	if err := r.step(); err != nil {
		return nil, nil, err
	}
	before, err := r.area.Lstat(".")
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || !owned(before) {
		return nil, nil, errV2Unavailable
	}
	if err := r.step(); err != nil {
		return nil, nil, err
	}
	dir, err := r.area.Open(".")
	if err != nil {
		return nil, nil, errV2Unavailable
	}
	if err := r.step(); err != nil {
		_ = r.closeFile(dir)
		return nil, nil, err
	}
	opened, err := dir.Stat()
	if err != nil || !opened.IsDir() || opened.Mode().Perm() != 0700 || !owned(opened) || !os.SameFile(before, opened) {
		_ = r.closeFile(dir)
		return nil, nil, errV2Unavailable
	}
	if r.root != nil && !os.SameFile(r.root, opened) {
		_ = r.closeFile(dir)
		return nil, nil, errV2Unavailable
	}
	return dir, opened, nil
}

// json.RawMessage is permitted only for the explicitly opaque catalogue audit
// leaf. Hash-looking strings in it never become inferred filename references.
func (r *v2ReachabilityReader) operationAudit(op v2Operation, state v2State, depth int) error {
	var payload json.RawMessage
	release, err := r.load(op.Outcome.AuditHash, &payload)
	if err != nil {
		return err
	}
	defer release()
	var catalogue struct {
		Format    string `json:"format"`
		Operation string `json:"operation"`
		Data      []byte `json:"data"`
	}
	if checkpointDecode(payload, &catalogue) == nil {
		if r.action != nil {
			return errV2Unavailable
		}
		if catalogue.Format != v2Format || catalogue.Operation != op.ID || len(catalogue.Data) == 0 || len(catalogue.Data) > 8192 {
			return errV2Unavailable
		}
		r.report.OpaqueAuditObjects++
		return nil
	}
	var audit v2CoordinatorAudit
	if checkpointDecode(payload, &audit) != nil || audit.Format != v2Format || audit.Operation != op.ID || audit.Subject != op.Subject || audit.Kind != op.Request.Kind || audit.Result != op.Outcome.Code || audit.Generation != op.Outcome.Generation || audit.Running != op.Outcome.RunningRevision || audit.Startup != op.Outcome.StartupRevision || audit.Sequence != op.Outcome.AuditLast || op.Outcome.AuditFirst == 0 {
		return errV2Unavailable
	}
	return r.auditChain(op.Outcome.AuditHash, audit.Sequence, state.Generation, depth)
}
