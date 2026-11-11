//go:build !linux

package configpoc

import "os"

func lockCheckpoint(*os.Root) (*os.File, error) { return nil, ErrStorage }

func publishCheckpointImage(*os.Root, string) error { return ErrStorage }
