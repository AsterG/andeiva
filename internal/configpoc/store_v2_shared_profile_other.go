//go:build !linux

package configpoc

import "os"

func (s *v2Store) recordDirectoryV2() (*os.File, error)    { return nil, errV2Unavailable }
func (s *v2Store) lockSharedProfileV2() (*os.File, error)  { return nil, errV2Unavailable }
func (s *v2Store) createRecordV2(string) (*os.File, error) { return nil, errV2Unavailable }
