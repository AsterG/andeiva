//go:build linux

package configpoc

import (
	"io"
	"os"
	"syscall"
)

func selectedCacheOpenV2(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
func selectedCacheSameV2(a, b os.FileInfo) bool {
	x, ok := infoSysV2(a)
	y, yes := infoSysV2(b)
	return ok && yes && os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime()) && x.Ctim == y.Ctim && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink
}

// Reserve half the soft limit and at least 32 currently free descriptors for
// pools, channels and transient validation. The proc count is a capacity hint,
// never storage authority; inability to inspect it disables descriptor caching.
func selectedCacheFileLimitV2() int {
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) != nil {
		return 0
	}
	used, ok := selectedCacheDescriptorCountV2()
	if !ok {
		return 0
	}
	return selectedCacheFilesForUsageV2(limit.Cur, used)
}
func selectedCacheDescriptorCountV2() (uint64, bool) {
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0, false
	}
	var count uint64
	for count <= 4096 {
		names, err := dir.Readdirnames(128)
		count += uint64(len(names))
		if err == io.EOF {
			return count, dir.Close() == nil
		}
		if err != nil {
			_ = dir.Close()
			return 0, false
		}
	}
	_ = dir.Close()
	return 0, false
}
