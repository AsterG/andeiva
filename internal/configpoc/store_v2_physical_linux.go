package configpoc

import (
	"math"
	"os"
	"syscall"
)

// File.Stat obtains fstat metadata from the descriptor held by the caller.
// Linux st_blocks is expressed in 512-byte units, independently of st_blksize.
func v2Allocated(info os.FileInfo) (uint64, error) {
	if info == nil || info.Size() < 0 {
		return 0, errV2Unavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Blocks < 0 || uint64(stat.Blocks) > math.MaxUint64/512 {
		return 0, errV2Unavailable
	}
	return uint64(stat.Blocks) * 512, nil
}

func v2PhysicalSameDevice(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	x, xOK := a.Sys().(*syscall.Stat_t)
	y, yOK := b.Sys().(*syscall.Stat_t)
	return xOK && yOK && x.Dev == y.Dev
}
