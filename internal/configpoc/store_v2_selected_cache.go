package configpoc

import (
	"bytes"
	"encoding/json"
	"os"
)

// Raw object bytes are retained only within one selected read. Decoding and
// every edge/type/context check still run on each use. No selector is cached.
const selectedCacheFilesV2 = 256

type selectedCacheEntryV2 struct {
	file *os.File
	info os.FileInfo
	data []byte
}
type selectedReadCacheV2 struct {
	entries   map[string]selectedCacheEntryV2
	files     int
	workRead  bool
	bytes     uint64
	hits      uint64
	pure      map[string]bool
	plans     map[string]RoutedSelectedPlanV1
	planBytes uint64
}

func newSelectedReadCacheV2() *selectedReadCacheV2 {
	return &selectedReadCacheV2{files: selectedCacheFileLimitV2(), entries: make(map[string]selectedCacheEntryV2), pure: make(map[string]bool), plans: make(map[string]RoutedSelectedPlanV1)}
}
func (c *selectedReadCacheV2) get(r *v2ReachabilityReader, name string, limit int64) ([]byte, bool, error) {
	e, ok := c.entries[name]
	if !ok {
		return nil, false, nil
	}
	if err := r.step(); err != nil {
		return nil, true, err
	}
	if int64(len(e.data)) > limit {
		return nil, true, errV2Unavailable
	}
	c.hits++
	return e.data, true, nil
}
func (c *selectedReadCacheV2) keep(r *v2ReachabilityReader, name string, info os.FileInfo, data []byte) (bool, error) {
	if len(name) != 76 || name[:7] != "object-" || name[71:] != ".json" || !validHash(name[7:71]) || len(c.entries) >= c.files || (!c.workRead && len(c.entries) >= c.files/2) || uint64(len(data)) > r.budget.ActiveBytes/2-c.bytes {
		return false, nil
	}
	if err := r.step(); err != nil {
		return false, err
	}
	if err := r.step(); err != nil {
		return false, err
	}
	f, err := selectedCacheOpenV2(r.area, name)
	if err != nil {
		return false, errV2Unavailable
	}
	actual, err := f.Stat()
	if err != nil || !selectedCacheSameV2(info, actual) {
		_ = f.Close()
		return false, errV2Unavailable
	}
	c.entries[name] = selectedCacheEntryV2{file: f, info: actual, data: data}
	c.bytes += uint64(len(data))
	return true, nil
}
func (c *selectedReadCacheV2) revalidate(r *v2ReachabilityReader) error {
	if c == nil {
		return nil
	}
	for name, e := range c.entries {
		if r.ctx.Err() != nil {
			return errV2Unavailable
		}
		if r.report.IOCalls > r.budget.IOCalls || r.budget.IOCalls-r.report.IOCalls < 64 {
			return errV2InspectionBudget
		}
		r.report.IOCalls += 64
		info, err := r.shared.CheckFile(r.area, name, int64(len(e.data)))
		if err != nil || !selectedCacheSameV2(e.info, info) {
			return errV2Unavailable
		}
		n := uint64(len(e.data))
		if r.report.BytesRead > r.budget.Bytes || n > r.budget.Bytes-r.report.BytesRead || r.active > r.budget.ActiveBytes || n > r.budget.ActiveBytes-r.active {
			return errV2InspectionBudget
		}
		if err := r.step(); err != nil {
			return err
		}
		r.report.BytesRead += n
		r.active += n
		if r.active > r.report.PeakActiveBytes {
			r.report.PeakActiveBytes = r.active
		}
		scratch := make([]byte, len(e.data))
		read, readErr := e.file.ReadAt(scratch, 0)
		same := read == len(scratch) && readErr == nil && bytes.Equal(scratch, e.data)
		r.active -= n
		if !same {
			return errV2Unavailable
		}
		pinned, err := e.file.Stat()
		if err != nil || !selectedCacheSameV2(e.info, pinned) {
			return errV2Unavailable
		}
	}
	return nil
}
func (c *selectedReadCacheV2) close(r *v2ReachabilityReader) error {
	if c == nil {
		return nil
	}
	var result error
	for name, e := range c.entries {
		if r.closeFile(e.file) != nil {
			result = errV2Unavailable
		}
		delete(c.entries, name)
	}
	r.active -= c.bytes + c.planBytes
	c.bytes, c.planBytes = 0, 0
	clear(c.plans)
	clear(c.pure)
	if r.report.IOCalls > r.budget.IOCalls {
		result = errV2InspectionBudget
	}
	return result
}

// Hash every argument that can affect a repeated validation. Path labels are
// not authority; the full typed context prevents reuse across changed state.
func selectedValidationKeyV2(value any) (string, error) {
	_, hash, err := v2Canonical(value)
	return hash, err
}

// Only predicates without object reads or contextual authority use this cache.
// Keys contain all immutable inputs. Failed predicates are never memoized.
func (r *v2ReachabilityReader) selectedPureV2(key string, check func() bool) bool {
	if r.cache == nil {
		return check()
	}
	if r.cache.pure[key] {
		return true
	}
	if !check() {
		return false
	}
	if len(r.cache.pure) < selectedCacheFilesV2 {
		r.cache.pure[key] = true
	}
	return true
}
func (r *v2ReachabilityReader) selectedConfigurationValidV2(cfg *v2Configuration) bool {
	if r.cache == nil {
		return validV2Configuration(cfg)
	}
	key, err := selectedValidationKeyV2(cfg)
	if err != nil {
		return false
	}
	return r.selectedPureV2("configuration:"+key, func() bool { return validV2Configuration(cfg) })
}

// G1-only immutable memo. All source objects must remain pinned in the same
// call's raw cache. The returned value is only inspected by graph validators;
// selected authority is reconstructed separately after current-state checks.
func (r *v2ReachabilityReader) selectedRoutedWorkV2(hash, lineage string) (RoutedSelectedPlanV1, error) {
	if r.cache == nil {
		return loadRoutedWorkV2(hash, lineage, r.object)
	}
	key := hash + ":" + lineage
	if plan, ok := r.cache.plans[key]; ok {
		return plan, r.step()
	}
	retained := true
	plan, err := loadRoutedWorkWithValidationV2(hash, lineage, func(hash string, target any) error {
		previous := r.cache.workRead
		r.cache.workRead = true
		err := r.object(hash, target)
		r.cache.workRead = previous
		if _, ok := r.cache.entries["object-"+hash+".json"]; !ok {
			retained = false
		}
		return err
	}, r.selectedConfigurationValidV2)
	if err != nil || !retained || len(r.cache.plans) >= 8 {
		return plan, err
	}
	// Charge the complete represented payload, not just its small root struct.
	// ActiveBytes bounds payloads; as elsewhere it is not a Go heap/RSS quota.
	encoded, err := json.Marshal(struct {
		Work             v2RoutedWork
		Preparation      RoutedPreparationV1
		Previous, Target RoutedActivationBundleV1
		Baseline         *RoutedBaselineV1
		Resolution       string
		BootRecord       *v2RecoveryRecord
	}{plan.work, plan.preparation, plan.previous, plan.target, plan.baseline, plan.resolution, plan.bootRecord})
	if err != nil {
		return RoutedSelectedPlanV1{}, err
	}
	n := uint64(len(encoded))
	if r.cache.planBytes > r.budget.ActiveBytes/4 || n > r.budget.ActiveBytes/4-r.cache.planBytes || r.active > r.budget.ActiveBytes || n > r.budget.ActiveBytes-r.active {
		return plan, nil
	}
	r.active += n
	r.cache.planBytes += n
	if r.active > r.report.PeakActiveBytes {
		r.report.PeakActiveBytes = r.active
	}
	r.cache.plans[key] = plan
	return plan, nil
}

func selectedCacheFilesForLimitV2(limit uint64) int {
	available := limit / 2
	if available >= selectedCacheFilesV2 {
		return selectedCacheFilesV2
	}
	return int(available)
}

func selectedCacheFilesForUsageV2(limit, used uint64) int {
	cap := selectedCacheFilesForLimitV2(limit)
	if used >= limit || limit-used <= 32 {
		return 0
	}
	available := limit - used - 32
	if available >= selectedCacheFilesV2 {
		return cap
	}
	return min(cap, int(available))
}

func (r *v2ReachabilityReader) selectedArchiveFinalityV2(archive v2ReserveArchive, state v2State) error {
	if r.cache == nil {
		return validateArchiveFinalityV2(archive, state, r.object)
	}
	// Capture this invocation's complete state by value. No mutable current-state
	// field or partial state-key substitutes for the checks in the R2 body.
	return validateArchiveFinalityWithWorkV2(archive, state, r.object, func(hash, lineage string) (RoutedSelectedPlanV1, error) {
		if lineage != state.Lineage {
			return RoutedSelectedPlanV1{}, errV2Unavailable
		}
		return r.selectedRoutedWorkV2(hash, lineage)
	})
}
