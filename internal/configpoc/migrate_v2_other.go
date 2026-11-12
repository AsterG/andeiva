//go:build !linux

package configpoc

import "os"

func lockLegacyV2(*os.Root) (*os.File, error) { return nil, errV2Unavailable }
