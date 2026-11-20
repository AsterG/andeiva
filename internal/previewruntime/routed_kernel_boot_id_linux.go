//go:build linux

package previewruntime

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const routedKernelBootIDPath = "/proc/sys/kernel/random/boot_id"

// The system launcher and its children read the running kernel independently.
// Operational records can be compared with this value but cannot supply it.
func readRoutedKernelBootID() (string, error) {
	file, err := os.OpenFile(routedKernelBootIDPath, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", ErrIdentity
	}
	defer file.Close()
	return readRoutedProcBootID(file)
}

func readRoutedProcBootID(file *os.File) (string, error) {
	fd := int(file.Fd())
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC ||
		unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
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
