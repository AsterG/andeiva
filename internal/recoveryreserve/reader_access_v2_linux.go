//go:build linux

package recoveryreserve

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func accessWriterV2(a ReaderAccessV2) bool { return int64(os.Geteuid()) == int64(a.OwnerUID) }

func accessReaderV2(a ReaderAccessV2) bool {
	if os.Geteuid() == 0 {
		return false
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	groups = append(groups, os.Getegid())
	for _, gid := range groups {
		if int64(gid) == int64(a.ReaderGID) {
			return true
		}
	}
	return false
}

// ENOTSUP is not evidence of an absent ACL. This prepared Linux profile refuses
// filesystems that cannot answer the descriptor-based ACL query.
func noAccessACLV2(f *os.File, directory bool) bool {
	if f == nil {
		return false
	}
	names := []string{"system.posix_acl_access"}
	if directory {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		_, err := unix.Fgetxattr(int(f.Fd()), name, nil)
		if !errors.Is(err, unix.ENODATA) {
			return false
		}
	}
	return true
}

func accessDirectoryV2(root *os.Root, info os.FileInfo, a *ReaderAccessV2) bool {
	if a == nil {
		return info != nil && privateDirectory(info)
	}
	if root == nil || info == nil || !a.valid() {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode() != os.ModeDir|os.ModeSetgid|0750 || s.Uid != a.OwnerUID || s.Gid != a.ReaderGID || s.Dev != a.Device || s.Ino != a.Inode {
		return false
	}
	f, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	actual, err := f.Stat()
	valid := false
	if err == nil {
		opened, ok := actual.Sys().(*syscall.Stat_t)
		valid = ok && opened.Uid == a.OwnerUID && opened.Gid == a.ReaderGID && os.SameFile(info, actual) && actual.Mode() == info.Mode() && noAccessACLV2(f, true)
	}
	return f.Close() == nil && valid
}

func accessFileV2(f *os.File, info, root os.FileInfo, a *ReaderAccessV2) bool {
	if a == nil {
		return info != nil && root != nil && privateFile(info, root)
	}
	if info == nil || root == nil || f == nil || !a.valid() {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	r, rok := root.Sys().(*syscall.Stat_t)
	if !ok || !rok || info.Mode() != 0640 || s.Uid != a.OwnerUID || s.Gid != a.ReaderGID || s.Nlink != 1 || s.Dev != r.Dev || s.Dev != a.Device {
		return false
	}
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) || actual.Mode() != info.Mode() {
		return false
	}
	as, ok := actual.Sys().(*syscall.Stat_t)
	return ok && as.Uid == a.OwnerUID && as.Gid == a.ReaderGID && as.Nlink == 1 && noAccessACLV2(f, false)
}

func openAccessFileV2(root *os.Root, name string, readOnly bool) (*os.File, error) {
	if !readOnly {
		return openFile(root, name)
	}
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func createAccessFileV2(root *os.Root, name string, a *ReaderAccessV2) (*os.File, error) {
	if a == nil {
		return createFile(root, name)
	}
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	// Only the inode just created with O_EXCL is changed. Group inheritance is
	// mandatory; no chown, adoption, or repair of existing files is attempted.
	i, err := f.Stat()
	if err == nil {
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != a.OwnerUID || s.Gid != a.ReaderGID || s.Nlink != 1 || s.Dev != a.Device || !noAccessACLV2(f, false) {
			err = ErrUnavailable
		}
	}
	if err == nil {
		err = f.Chmod(0640)
	}
	if err != nil {
		if f.Close() != nil {
			return nil, ErrUnavailable
		}
		return nil, ErrUnavailable
	}
	return f, nil
}
