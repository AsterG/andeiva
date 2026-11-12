//go:build !linux

package configpoc

import "os"

func (r *v2ReachabilityReader) lockExisting() (*os.File, os.FileInfo, error) {
	return nil, nil, ErrStorage
}
func (r *v2ReachabilityReader) verifyScope(*os.File) error { return ErrStorage }
