//go:build !linux

package configpoc

import "os"

func openInactiveLocalSourceV3(*os.Root) (*fileStore, error) { return nil, ErrStorage }
