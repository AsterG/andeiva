//go:build linux

package configpoc

import (
	"os"
	"syscall"
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
