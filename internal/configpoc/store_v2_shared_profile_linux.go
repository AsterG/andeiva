//go:build linux

package configpoc

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func (s *v2Store) recordDirectoryV2() (*os.File, error) {
	if s.access == nil {
		return v2Directory(s.root)
	}
	if s.access.CheckDirectory(s.root) != nil {
		return nil, errV2Unavailable
	}
	f, err := s.root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errV2Unavailable
	}
	info, err := f.Stat()
	stat, ok := infoSysV2(info)
	if err != nil || !ok || stat.Dev != s.access.Device || stat.Ino != s.access.Inode || s.access.CheckDirectory(s.root) != nil {
		_ = f.Close()
		return nil, errV2Unavailable
	}
	return f, nil
}

func infoSysV2(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return s, ok
}

func (s *v2Store) lockSharedProfileV2() (*os.File, error) {
	if s.access == nil {
		return lockCheckpoint(s.root)
	}
	if int64(os.Geteuid()) != int64(s.access.OwnerUID) || s.access.CheckDirectory(s.root) != nil {
		return nil, errV2Unavailable
	}
	f, err := lockCheckpoint(s.root)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	stat, ok := infoSysV2(info)
	_, acl := unix.Fgetxattr(int(f.Fd()), "system.posix_acl_access", nil)
	if err != nil || !ok || stat.Gid != s.access.ReaderGID || !errors.Is(acl, unix.ENODATA) || s.access.CheckDirectory(s.root) != nil {
		_ = f.Close()
		return nil, errV2Unavailable
	}
	return f, nil
}

func (s *v2Store) createRecordV2(name string) (*os.File, error) {
	if s.readOnly {
		return nil, errV2Unavailable
	}
	if s.access == nil {
		return s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	}
	if int64(os.Geteuid()) != int64(s.access.OwnerUID) || s.access.CheckDirectory(s.root) != nil {
		return nil, errV2Unavailable
	}
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errV2Unavailable
	}
	// Only this newly created exclusive inode changes mode; never adopt or
	// repair existing records. Exact inherited group and ACL are checked next.
	if f.Chmod(0640) != nil {
		_ = f.Close()
		return nil, errV2Unavailable
	}
	info, err := f.Stat()
	if err != nil || !s.recordMetadataV2(name, info, 0) {
		_ = f.Close()
		return nil, errV2Unavailable
	}
	return f, nil
}
