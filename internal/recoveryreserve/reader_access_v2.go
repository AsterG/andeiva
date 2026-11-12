package recoveryreserve

import "os"

// ReaderAccessV2 is a trusted supervisor input, never a public request. Version
// 1 pins an API-owned 02750 directory and 0640 files to a dedicated reader group.
// It does not authorize migration, selected configuration, or engine effects.
type ReaderAccessV2 struct {
	Version   uint32
	OwnerUID  uint32
	ReaderGID uint32
	Device    uint64
	Inode     uint64
}

func (a ReaderAccessV2) valid() bool {
	return a.Version == 1 && a.OwnerUID != 0 && a.ReaderGID != 0 && a.Inode != 0
}

// PrepareSharedV2 creates a new pool in an already provisioned, empty directory.
// It never converts an existing private pool or changes directory permissions.
func PrepareSharedV2(area *os.Root, slots, capacity int, role RoleV2, access ReaderAccessV2) (*PoolV2, error) {
	if !access.valid() || !accessWriterV2(access) {
		return nil, ErrInvalid
	}
	return prepareV2(area, slots, capacity, role, &access)
}

// OpenSharedV2 retains the ordinary exclusive writer lock. The caller must first
// verify the canonical opt-in marker and the supervisor's incarnation barrier.
func OpenSharedV2(area *os.Root, access ReaderAccessV2) (*PoolV2, error) {
	if !access.valid() || !accessWriterV2(access) {
		return nil, ErrInvalid
	}
	return openAccessV2(area, &access, false)
}
