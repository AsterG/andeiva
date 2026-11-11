package configpoc

import (
	"math"
	"os"
	"syscall"
)

func probeStorageSpace(directory *os.File) (storageSpace, error) {
	var stat syscall.Statfs_t
	if directory == nil || syscall.Fstatfs(int(directory.Fd()), &stat) != nil {
		return storageSpace{}, ErrStorage
	}
	return storageSpaceFromStat(stat)
}

func storageSpaceFromStat(stat syscall.Statfs_t) (storageSpace, error) {
	if stat.Bsize <= 0 || stat.Frsize <= 0 || stat.Blocks == 0 || stat.Files == 0 || stat.Bavail > stat.Blocks || stat.Ffree > stat.Files {
		return storageSpace{}, ErrStorage
	}
	// statfs block counts use fragment size; Bsize is the preferred I/O size.
	// Budget metadata using the larger granularity without overstating free bytes.
	fragmentSize := uint64(stat.Frsize)
	if stat.Bavail > math.MaxUint64/fragmentSize {
		return storageSpace{}, ErrStorage
	}
	return storageSpace{
		AvailableBytes: stat.Bavail * fragmentSize, AvailableInodes: stat.Ffree,
		BlockSize: max(uint64(stat.Bsize), fragmentSize), ReadOnly: stat.Flags&1 != 0, // Linux ST_RDONLY.
	}, nil
}
