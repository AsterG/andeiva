//go:build !linux

package configpoc

import "os"

func selectedCacheOpenV2(*os.Root, string) (*os.File, error) { return nil, errV2Unavailable }
func selectedCacheSameV2(os.FileInfo, os.FileInfo) bool      { return false }

func selectedCacheFileLimitV2() int { return 0 }
