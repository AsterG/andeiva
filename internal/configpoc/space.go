package configpoc

import "math"

type storageSpace struct {
	AvailableBytes  uint64
	AvailableInodes uint64
	BlockSize       uint64
	ReadOnly        bool
}

// spaceCapacity is an admission observation, not an allocation or a quota
// guarantee. Later write/fsync failures retain the existing recovery semantics.
func (s *fileStore) spaceCapacity(reserve int) (available bool) {
	root, err := s.openScopedRoot()
	if err != nil {
		return false
	}
	defer func() {
		if root.Close() != nil {
			available = false
		}
	}()
	directory, err := root.Open(".")
	if err != nil {
		return false
	}
	defer func() {
		if directory.Close() != nil {
			available = false
		}
	}()
	probe := s.spaceProbe
	if probe == nil {
		probe = probeStorageSpace
	}
	space, err := probe(directory)
	return err == nil && space.admits(reserve)
}

func (space storageSpace) admits(reserve int) bool {
	if reserve < 0 || reserve >= 10000 || space.ReadOnly || space.BlockSize == 0 {
		return false
	}
	// Each future record needs its maximum payload and up to one block of
	// rounding/directory growth. Four more blocks and three inodes provide a
	// staging/ownership allowance, not a universal filesystem metadata bound.
	records := uint64(reserve) + 1
	if space.BlockSize > (math.MaxUint64-maxRecordBytes*records)/(records+4) {
		return false
	}
	bytes := maxRecordBytes*records + space.BlockSize*(records+4)
	return space.AvailableBytes >= bytes && space.AvailableInodes >= records+3
}
