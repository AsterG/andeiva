//go:build !linux

package configpoc

import "os"

func openRecordFile(*os.Root, string) (*os.File, error) {
	return nil, ErrStorage
}
