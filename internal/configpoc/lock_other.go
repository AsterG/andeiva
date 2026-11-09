//go:build !linux

package configpoc

import "os"

func owned(os.FileInfo) bool             { return false }
func singleLink(os.FileInfo) bool        { return false }
func lockStore(string) (*os.File, error) { return nil, ErrStorage }
