//go:build !linux

package configpoc

import "os"

func lockCheckpoint(*os.Root) (*os.File, error) { return nil, ErrStorage }
