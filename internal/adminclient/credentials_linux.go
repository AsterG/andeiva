//go:build linux

package adminclient

import (
	"os"
	"syscall"
)

func openCredentials(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrCredentials
	}
	file := os.NewFile(uintptr(fd), path)
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, ErrCredentials
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	euid := os.Geteuid()
	if !ok || euid < 0 || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || int64(owner.Uid) != int64(euid) || owner.Nlink != 1 {
		_ = file.Close()
		return nil, ErrCredentials
	}
	return file, nil
}
