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
		file.Close()
		return nil, ErrCredentials
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		file.Close()
		return nil, ErrCredentials
	}
	return file, nil
}
