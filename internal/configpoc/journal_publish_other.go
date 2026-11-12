//go:build !linux

package configpoc

import "os"

func (*fileStore) publishJournalRecord(*os.Root, uint64, os.FileInfo) error { return ErrStorage }
