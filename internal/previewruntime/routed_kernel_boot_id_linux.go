//go:build linux

package previewruntime

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"

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
	leafMount, _, ok := routedProcMountID(fd)
	if !ok {
		return "", ErrIdentity
	}
	if leafMount != mount {
		if name != routedKernelBootIDName || !routedProtectedKernelMount(root, mount, leafMount) {
			return "", ErrIdentity
		}
		mount = leafMount
	}
	return readRoutedProcBootID(file, mount)
}

// The grouped unit mounts the genuine /sys/kernel subtree of procfs read-only.
// Match that exact mount in the caller's kernel mount table. A separate mount
// at the leaf or any other subtree must never supply the boot identity.
func routedProtectedKernelMount(root int, rootMount, leafMount uint64) bool {
	var proc unix.Stat_t
	if unix.Fstat(root, &proc) != nil {
		return false
	}
	fd, err := unix.Openat(root, "thread-self/mountinfo", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), "proc mountinfo")
	defer file.Close()
	if mount, _, ok := routedProcMountID(fd); !ok || mount != rootMount {
		return false
	}
	device := strconv.FormatUint(uint64(unix.Major(uint64(proc.Dev))), 10) + ":" + strconv.FormatUint(uint64(unix.Minor(uint64(proc.Dev))), 10)
	return routedProtectedKernelMountInfo(file, rootMount, leafMount, device)
}

func routedProtectedKernelMountInfo(src io.Reader, root, leaf uint64, device string) bool {
	rootID, leafID := strconv.FormatUint(root, 10), strconv.FormatUint(leaf, 10)
	scan := bufio.NewScanner(io.LimitReader(src, 1<<20))
	for scan.Scan() {
		line, fs, found := strings.Cut(scan.Text(), " - ")
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != leafID {
			continue
		}
		mode, _, _ := strings.Cut(fields[5], ",")
		kind, _, _ := strings.Cut(fs, " ")
		return found && kind == "proc" && fields[1] == rootID && fields[2] == device &&
			fields[3] == "/sys/kernel" && fields[4] == "/proc/sys/kernel" && mode == "ro"
	}
	return false
}

// The file must belong to the already validated procfs mount.
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
