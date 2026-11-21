//go:build linux

package previewruntime

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const (
	routedKernelProcRoot    = "/proc"
	routedKernelBootIDName  = "sys/kernel/random/boot_id"
	routedKernelBootIDPath  = routedKernelProcRoot + "/" + routedKernelBootIDName
	routedKernelProcRootIno = 1
)

// The system launcher and its children read the running kernel independently.
// Operational records can be compared with this value but cannot supply it.
func readRoutedKernelBootID() (string, error) {
	return readRoutedProcIdentity(routedKernelBootIDName)
}

// A boot identity is stable for the whole boot. Two independent opens must
// agree, so a per-read generator placed at the fixed name cannot imitate it.
func readRoutedProcIdentity(name string) (string, error) {
	first, err := openRoutedProcIdentity(name)
	if err != nil {
		return "", err
	}
	second, err := openRoutedProcIdentity(name)
	if err != nil || first != second {
		return "", ErrIdentity
	}
	return first, nil
}

func routedProcMountID(fd int) (mount, inode uint64, ok bool) {
	var fs unix.Statfs_t
	var st unix.Statx_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID|unix.STATX_INO|unix.STATX_TYPE, &st) != nil ||
		st.Mask&(unix.STATX_MNT_ID|unix.STATX_INO|unix.STATX_TYPE) != unix.STATX_MNT_ID|unix.STATX_INO|unix.STATX_TYPE {
		return 0, 0, false
	}
	return st.Mnt_id, st.Ino, true
}

func openRoutedProcIdentity(name string) (string, error) {
	root, err := unix.Open(routedKernelProcRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", ErrIdentity
	}
	defer unix.Close(root)
	mount, inode, ok := routedProcMountID(root)
	if !ok || inode != routedKernelProcRootIno {
		return "", ErrIdentity
	}
	fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", ErrIdentity
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	return readRoutedProcBootID(file, mount)
}

// The file must belong to the procfs mount whose root was opened. A file or
// directory mounted over the fixed name carries another mount identity.
func readRoutedProcBootID(file *os.File, procMount uint64) (string, error) {
	fd := int(file.Fd())
	var st unix.Stat_t
	mount, _, ok := routedProcMountID(fd)
	if !ok || mount != procMount || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", ErrIdentity
	}
	// Linux returns the canonical 36-byte UUID plus a newline. Extra bytes,
	// truncation and noncanonical values cannot become recovery authority.
	var content [38]byte
	n, err := io.ReadFull(file, content[:])
	if err != io.ErrUnexpectedEOF || n != 37 || content[36] != '\n' || !bootPattern.Match(content[:36]) {
		return "", ErrIdentity
	}
	return string(content[:36]), nil
}
