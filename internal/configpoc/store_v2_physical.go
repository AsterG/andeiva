package configpoc

import (
	"math"
	"os"
)

// Physical counters are observations, rebuilt under the store lock on open.
// They neither change durable logical reservations nor allocate/quota space.
type v2PhysicalUsage struct {
	files, directory, inodes uint64
	selector, selectorSize   uint64
	directoryInfo            os.FileInfo
}

func v2Add(a, b uint64) (uint64, bool) {
	if b > math.MaxUint64-a {
		return 0, false
	}
	return a + b, true
}

// Allow per-file allocation rounding plus one directory-growth block per new
// inode and four metadata blocks. This is a conservative supported-profile
// estimate, not a filesystem-wide allocation guarantee.
func v2PhysicalEnvelope(payload, inodes, block uint64) (uint64, bool) {
	if block == 0 {
		return 0, false
	}
	if payload == 0 && inodes == 0 {
		return 0, true
	}
	count, ok := v2Add(inodes, 4)
	if !ok || count > math.MaxUint64/block || inodes > math.MaxUint64/block {
		return 0, false
	}
	rounded, ok := v2Add(payload, inodes*(block-1))
	if !ok {
		return 0, false
	}
	return v2Add(rounded, count*block)
}

func (s *v2Store) physicalRecord(name string, expected os.FileInfo) (info os.FileInfo, result error) {
	f, err := openRecordFile(s.root, name)
	if err != nil {
		return nil, errV2Unavailable
	}
	defer func() {
		if f.Close() != nil {
			result = errV2Unavailable
		}
	}()
	info, err = f.Stat()
	if err != nil || !s.sameProfileRecordV2(name, expected, info) || !v2PhysicalSameDevice(s.physical.directoryInfo, info) {
		return nil, errV2Unavailable
	}
	named, err := s.root.Lstat(name)
	if err != nil || !s.sameProfileRecordV2(name, info, named) {
		return nil, errV2Unavailable
	}
	return info, nil
}

func (s *v2Store) physicalAddFile(info os.FileInfo) error {
	allocated, err := v2Allocated(info)
	if err != nil || !v2PhysicalSameDevice(s.physical.directoryInfo, info) {
		return errV2Unavailable
	}
	files, ok := v2Add(s.physical.files, allocated)
	inodes, inodeOK := v2Add(s.physical.inodes, 1)
	if !ok || !inodeOK {
		return errV2Unavailable
	}
	s.physical.files, s.physical.inodes = files, inodes
	return nil
}

func (s *v2Store) physicalDirectory() (directory *os.File, result error) {
	directory, err := s.recordDirectoryV2()
	if err != nil {
		return nil, errV2Unavailable
	}
	info, err := directory.Stat()
	if err != nil || s.physical.directoryInfo == nil || !os.SameFile(s.physical.directoryInfo, info) {
		_ = directory.Close()
		return nil, errV2Unavailable
	}
	allocated, err := v2Allocated(info)
	if err != nil {
		_ = directory.Close()
		return nil, errV2Unavailable
	}
	s.physical.directory = allocated
	return directory, nil
}

// Admission checks both owned allocation and currently available filesystem
// space. os.Root pins the scope; Fstatfs probes this validated directory FD.
// Shortage before effects is not durable ambiguity and must not clear/set blocked.
func (s *v2Store) physicalCapacity(payload, inodes uint64) (result error) {
	directory, err := s.physicalDirectory()
	if err != nil {
		return err
	}
	defer func() {
		if directory.Close() != nil {
			result = errV2Unavailable
		}
	}()
	probe := s.spaceProbe
	if probe == nil {
		probe = probeStorageSpace
	}
	space, err := probe(directory)
	if err != nil || space.ReadOnly || space.BlockSize == 0 || s.allowance.Bytes > s.state.ReservedBytes || s.allowance.Inodes > s.state.ReservedInodes {
		return errV2Unavailable
	}
	otherBytes := s.state.ReservedBytes - s.allowance.Bytes
	otherInodes := s.state.ReservedInodes - s.allowance.Inodes
	reserved, ok := v2PhysicalEnvelope(otherBytes, otherInodes, space.BlockSize)
	next, nextOK := v2PhysicalEnvelope(payload, inodes, space.BlockSize)
	future, futureOK := v2Add(reserved, next)
	allocated, allocatedOK := v2Add(s.physical.files, s.physical.directory)
	total, totalOK := v2Add(allocated, future)
	futureInodes, futureInodesOK := v2Add(otherInodes, inodes)
	totalInodes, totalInodesOK := v2Add(s.physical.inodes, futureInodes)
	if !ok || !nextOK || !futureOK || !allocatedOK || !totalOK || !futureInodesOK || !totalInodesOK {
		return errV2Unavailable
	}
	if total > s.budget.Bytes || totalInodes > s.budget.Inodes || future > space.AvailableBytes || futureInodes > space.AvailableInodes {
		return errV2Limited
	}
	return nil
}

// Publication keeps both selector inodes charged until the verified replacement
// is durable. Available-space probes, not this name-based deduction, account for
// an old selector still held open by another reader.
func (s *v2Store) physicalPendingSelector(info os.FileInfo) error {
	if info == nil {
		return errV2Unavailable
	}
	size := info.Size()
	if size < 0 {
		return errV2Unavailable
	}
	if err := s.physicalAddFile(info); err != nil {
		return err
	}
	s.used.Bytes += uint64(size)
	s.used.Inodes++
	return s.physicalRefreshDirectory()
}

func (s *v2Store) physicalSelected(info os.FileInfo) error {
	if info == nil {
		return errV2Unavailable
	}
	size := info.Size()
	if size < 0 {
		return errV2Unavailable
	}
	allocated, err := v2Allocated(info)
	if err != nil || s.physical.files < s.physical.selector || s.used.Bytes < s.physical.selectorSize {
		return errV2Unavailable
	}
	if s.physical.selectorSize != 0 {
		if s.physical.inodes == 0 || s.used.Inodes == 0 {
			return errV2Unavailable
		}
		s.physical.inodes--
		s.used.Inodes--
	}
	s.physical.files -= s.physical.selector
	s.used.Bytes -= s.physical.selectorSize
	s.physical.selector, s.physical.selectorSize = allocated, uint64(size)
	return s.physicalRefreshDirectory()
}

func (s *v2Store) physicalRefreshDirectory() error {
	dir, err := s.physicalDirectory()
	if err != nil {
		return err
	}
	if dir.Close() != nil {
		return errV2Unavailable
	}
	return nil
}
