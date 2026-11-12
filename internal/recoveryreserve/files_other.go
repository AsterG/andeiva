//go:build !linux

package recoveryreserve

import "os"

func platform() error                               { return ErrUnavailable }
func privateDirectory(os.FileInfo) bool             { return false }
func privateFile(os.FileInfo, os.FileInfo) bool     { return false }
func createFile(*os.Root, string) (*os.File, error) { return nil, ErrUnavailable }
func openFile(*os.Root, string) (*os.File, error)   { return nil, ErrUnavailable }
func allocate(*os.File, int64) error                { return ErrUnavailable }
func fullyAllocated(os.FileInfo) bool               { return false }
func lock(*os.File) error                           { return ErrUnavailable }
func syncArea(*os.Root) error                       { return ErrUnavailable }
