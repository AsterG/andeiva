//go:build !linux

package configpoc

import "os"

func v2Directory(*os.Root) (*os.File, error) { return nil, errV2Unavailable }
