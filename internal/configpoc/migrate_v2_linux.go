//go:build linux

package configpoc

import (
	"os"
	"syscall"
)

func lockLegacyV2(area *os.Root) (*os.File, error) {
	before, err := area.Lstat("state.lock")
	if err != nil || !regularOwned(before, 0) {
		return nil, errV2Unavailable
	}
	file, err := area.OpenFile("state.lock", os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errV2Unavailable
	}
	opened, err := file.Stat()
	if err != nil || !sameRecordFile(before, opened) {
		_ = file.Close()
		return nil, errV2Unavailable
	}
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = file.Close()
		return nil, ErrLocked
	}
	return file, nil
}
