//go:build linux

package configpoc

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func lockCheckpoint(area *os.Root) (*os.File, error) {
	file, err := area.OpenFile("checkpoint.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	info, err := file.Stat()
	if err != nil || !regularOwned(info, 0) {
		_ = file.Close()
		return nil, ErrStorage
	}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = file.Close()
		return nil, ErrLocked
	}
	return file, nil
}

// The existence guard is diagnostic only: a noncooperating writer can create a
// destination after it. Kernel no-replace publication preserves that entry.
func publishCheckpointImage(area *os.Root, name string) error {
	return checkpointRenameNoReplace(area, name, unix.Renameat2)
}

// rename is an internal syscall fault boundary, not a runtime extension point.
func checkpointRenameNoReplace(area *os.Root, name string, rename func(int, string, int, string, uint) error) (result error) {
	if area == nil || rename == nil || (name != "checkpoint-1.json" && name != "checkpoint-2.json") {
		return ErrStorage
	}
	before, err := area.Stat(".")
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || !owned(before) {
		return ErrStorage
	}
	directory, err := area.Open(".")
	if err != nil {
		return ErrStorage
	}
	defer func() {
		if directory.Close() != nil {
			result = ErrStorage
		}
	}()
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(before, opened) || opened.Mode().Perm() != 0700 || !owned(opened) {
		return ErrStorage
	}
	fd := int(directory.Fd())
	// No fallback: unsupported kernels/filesystems must not replace an existing
	// destination through a plain rename or an existence-check race.
	if err := rename(fd, checkpointTemporaryName, fd, name, unix.RENAME_NOREPLACE); err != nil {
		return ErrStorage
	}
	return nil
}
