//go:build !linux

package configpoc

import "os"

func probeStorageSpace(*os.File) (storageSpace, error) { return storageSpace{}, ErrStorage }
