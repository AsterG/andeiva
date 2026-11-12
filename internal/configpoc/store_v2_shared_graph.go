package configpoc

import "os"

func (r *v2ReachabilityReader) profileDirectoryV2(info os.FileInfo) bool {
	if r.shared == nil {
		return info != nil && info.IsDir() && info.Mode().Perm() == 0700 && owned(info)
	}
	return info != nil && r.shared.CheckDirectory(r.area) == nil
}

func (r *v2ReachabilityReader) profileRecordV2(name string, info os.FileInfo) bool {
	return (&v2Store{root: r.area, access: r.shared}).recordMetadataV2(name, info, v2ObjectLimit)
}

func (r *v2ReachabilityReader) sharedDirectoryV2() (*os.File, os.FileInfo, error) {
	if err := r.step(); err != nil {
		return nil, nil, err
	}
	dir, err := (&v2Store{root: r.area, access: r.shared}).recordDirectoryV2()
	if err != nil {
		return nil, nil, err
	}
	info, err := dir.Stat()
	if err != nil || !r.profileDirectoryV2(info) || r.root != nil && !os.SameFile(r.root, info) {
		_ = r.closeFile(dir)
		return nil, nil, errV2Unavailable
	}
	return dir, info, nil
}

// Read the same typed G1 graph through the shared filesystem validator. Budgets
// are charged before allocation; 64 reserves a conservative syscall envelope
// for metadata, ACL, readback and close within the two bounded helper calls.
func (r *v2ReachabilityReader) readSharedRecordV2(name string, limit int64) ([]byte, func(), error) {
	noop := func() {}
	if r.shared == nil || limit < 1 || limit > v2ObjectLimit || r.ctx.Err() != nil {
		return nil, noop, errV2Unavailable
	}
	if r.report.IOCalls > r.budget.IOCalls || r.budget.IOCalls-r.report.IOCalls < 64 {
		return nil, noop, errV2InspectionBudget
	}
	r.report.IOCalls += 64
	info, err := r.shared.CheckFile(r.area, name, limit)
	if err != nil {
		return nil, noop, errV2Unavailable
	}
	size := info.Size()
	if size < 0 || size > limit {
		return nil, noop, errV2Unavailable
	}
	n := uint64(size)
	if r.report.BytesRead > r.budget.Bytes || n > r.budget.Bytes-r.report.BytesRead || r.active > r.budget.ActiveBytes || n > r.budget.ActiveBytes-r.active {
		return nil, noop, errV2InspectionBudget
	}
	r.report.BytesRead += n
	r.active += n
	if r.active > r.report.PeakActiveBytes {
		r.report.PeakActiveBytes = r.active
	}
	// A concurrent enlargement must not allocate the uncharged caller limit.
	// The profile reader checks the size before allocating its bounded buffer.
	readLimit := max(size, 1)
	data, err := r.shared.ReadFile(r.ctx, r.area, name, int(readLimit))
	if err != nil || int64(len(data)) != size {
		r.active -= n
		return nil, noop, errV2Unavailable
	}
	released := false
	return data, func() {
		if !released {
			r.active -= n
			released = true
		}
	}, nil
}

func (r *v2ReachabilityReader) storeRecordV2(name string, limit int64) ([]byte, error) {
	if name != "selected.json" {
		if len(name) != 76 || name[:7] != "object-" || name[71:] != ".json" || !validHash(name[7:71]) {
			return nil, errV2Unavailable
		}
		hash := name[7:71]
		if r.report.Edges >= r.budget.Edges {
			return nil, errV2InspectionBudget
		}
		r.report.Edges++
		if !r.objects[hash] {
			if uint64(len(r.objects)) >= r.budget.Objects {
				return nil, errV2InspectionBudget
			}
			r.objects[hash] = true
			r.report.Objects++
		}
	}
	data, release, err := r.read(name, limit)
	if err != nil {
		return nil, err
	}
	release()
	return data, nil
}
