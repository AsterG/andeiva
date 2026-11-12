//go:build linux

package configpoc

import "os"

func v2Directory(area *os.Root) (*os.File, error) { return journalDirectory(area, ".") }
