//go:build linux

package recoveryreserve

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func platform() error { return nil }
func privateDirectory(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && info.Mode().Perm() == 0700 && int64(s.Uid) == int64(os.Geteuid())
}
func privateFile(info, root os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	r, rok := root.Sys().(*syscall.Stat_t)
	return ok && rok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && int64(s.Uid) == int64(os.Geteuid()) && s.Nlink == 1 && s.Dev == r.Dev
}
func createFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
}
func openFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
func allocate(file *os.File, size int64) error {
	if unix.Fallocate(int(file.Fd()), 0, 0, size) != nil {
		return ErrUnavailable
	}
	if file.Truncate(size) != nil {
		return ErrUnavailable
	}
	info, err := file.Stat()
	if err != nil || !fullyAllocated(info) {
		return ErrUnavailable
	}
	return nil
}
func fullyAllocated(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	size := info.Size()
	if !ok || s.Blocks < 0 || size <= 0 {
		return false
	}
	needed := size / 512
	if size%512 != 0 {
		needed++
	}
	return s.Blocks >= needed
}
func lock(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) }
func syncArea(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	err = f.Sync()
	if f.Close() != nil {
		return ErrUnavailable
	}
	return err
}
