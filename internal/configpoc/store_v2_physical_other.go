//go:build !linux

package configpoc

import "os"

func v2Allocated(os.FileInfo) (uint64, error)            { return 0, errV2Unavailable }
func v2PhysicalSameDevice(os.FileInfo, os.FileInfo) bool { return false }
