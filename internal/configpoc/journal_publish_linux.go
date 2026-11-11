//go:build linux

package configpoc

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func (s *fileStore) publishJournalRecord(root *os.Root, sequence uint64, expected os.FileInfo) error {
	return s.renameJournalRecord(root, sequence, expected, unix.Renameat2)
}

// rename is a private syscall fault boundary. Destination names are generated
// from the store's next sequence; neither directory paths nor flags are inputs.
func (s *fileStore) renameJournalRecord(root *os.Root, sequence uint64, expected os.FileInfo, rename func(int, string, int, string, uint) error) (result error) {
	if s == nil || root == nil || rename == nil || expected == nil || sequence == 0 || sequence > 99999999 || sequence != uint64(len(s.records))+1 || !s.capacity(0) {
		return ErrStorage
	}
	before, err := os.Lstat(s.dir)
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || !owned(before) {
		return ErrStorage
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return ErrStorage
	}
	destination, err := journalDirectory(root, ".")
	if err != nil {
		return err
	}
	defer func() {
		if destination.Close() != nil {
			result = ErrStorage
		}
	}()
	source, err := journalDirectory(root, stagingDirectory)
	if err != nil {
		return err
	}
	defer func() {
		if source.Close() != nil {
			result = ErrStorage
		}
	}()
	payload, err := s.validateStaging(root)
	if err != nil || payload == nil || !sameRecordFile(expected, payload) {
		return ErrStorage
	}
	name := fmt.Sprintf("%08d.json", sequence)
	// An existence guard cannot protect an append-only record. Unsupported
	// kernels/filesystems and collisions fail without a replacing fallback.
	if err := rename(int(source.Fd()), stagingPayload, int(destination.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return ErrStorage
	}
	return nil
}

func journalDirectory(root *os.Root, name string) (*os.File, error) {
	if name != "." && name != stagingDirectory {
		return nil, ErrStorage
	}
	before, err := root.Lstat(name)
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || !owned(before) {
		return nil, ErrStorage
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, ErrStorage
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.IsDir() || opened.Mode().Perm() != 0700 || !owned(opened) {
		_ = file.Close()
		return nil, ErrStorage
	}
	return file, nil
}
