//go:build !linux

package recoveryreserve

import "os"

func accessWriterV2(ReaderAccessV2) bool                                    { return false }
func accessReaderV2(ReaderAccessV2) bool                                    { return false }
func accessDirectoryV2(*os.Root, os.FileInfo, *ReaderAccessV2) bool         { return false }
func accessFileV2(*os.File, os.FileInfo, os.FileInfo, *ReaderAccessV2) bool { return false }
func openAccessFileV2(*os.Root, string, bool) (*os.File, error)             { return nil, ErrUnavailable }
func createAccessFileV2(*os.Root, string, *ReaderAccessV2) (*os.File, error) {
	return nil, ErrUnavailable
}
