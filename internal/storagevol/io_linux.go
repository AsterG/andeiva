//go:build linux

package storagevol

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func qualifiedPlatform() error {
	if runtime.GOARCH != "amd64" || os.Geteuid() != 0 || os.Getegid() != 0 {
		return ErrPlatform
	}
	data, err := trustedRead("/usr/lib/os-release", 4096)
	if err != nil {
		return ErrPlatform
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = strings.Trim(value, "\"")
		}
	}
	if fields["ID"] != "debian" || fields["VERSION_ID"] != "13" {
		return ErrPlatform
	}
	return nil
}

func checkFormatter() error {
	if _, err := trustedRead("/etc/mke2fs.conf", 65536); err != nil {
		return ErrFormatter
	}
	file, err := trustedOpen("/usr/sbin/mke2fs")
	if err != nil {
		return ErrFormatter
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().Perm()&0111 == 0 {
		return ErrFormatter
	}
	return nil
}

func trustedOpen(path string) (*os.File, error) {
	switch path {
	case "/usr/lib/os-release", "/etc/mke2fs.conf", "/usr/sbin/mke2fs":
	default:
		return nil, ErrUnsafe
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrUnsafe
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !ownedDirectory(info, 0, 0) || info.Mode().Perm()&0022 != 0 {
			return nil, ErrUnsafe
		}
		if parent == "/" {
			break
		}
	}
	scope, err := os.OpenRoot("/")
	if err != nil {
		return nil, ErrUnsafe
	}
	defer scope.Close()
	file, err := scope.OpenFile(strings.TrimPrefix(path, "/"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		_ = file.Close()
		return nil, ErrUnsafe
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != 0 || native.Gid != 0 || native.Nlink != 1 {
		_ = file.Close()
		return nil, ErrUnsafe
	}
	return file, nil
}
func trustedRead(path string, limit int64) ([]byte, error) {
	file, err := trustedOpen(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() < 1 || before.Size() > limit {
		return nil, ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || int64(len(data)) != before.Size() || !sameFile(before, after) {
		return nil, ErrUnsafe
	}
	return data, nil
}

func validBaseEntries(names []string) bool {
	if len(names) == 0 {
		return true
	}
	lock := false
	areas := 0
	for _, name := range names {
		if name == "preparation.lock" {
			lock = true
			continue
		}
		if strings.HasPrefix(name, "volumes-") && validID(strings.TrimPrefix(name, "volumes-")) {
			areas++
			continue
		}
		return false
	}
	return lock && areas <= 1
}

func openBase(create bool) (*os.Root, *os.File, error) {
	for _, name := range []string{"/", "/var", "/var/lib"} {
		info, err := os.Lstat(name)
		if err != nil || !ownedDirectory(info, 0, 0) || info.Mode().Perm()&0022 != 0 {
			return nil, nil, ErrUnsafe
		}
	}
	if create {
		if err := os.Mkdir(BaseDirectory, 0700); err != nil && !os.IsExist(err) {
			return nil, nil, ErrStorage
		}
	}
	info, err := os.Lstat(BaseDirectory)
	if err != nil || !ownedDirectory(info, 0, 0) || info.Mode().Perm() != 0700 {
		return nil, nil, ErrUnsafe
	}
	root, err := os.OpenRoot(BaseDirectory)
	if err != nil {
		return nil, nil, ErrStorage
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, nil, ErrUnsafe
	}
	names, err := directoryNames(root, 3)
	if err != nil || !validBaseEntries(names) {
		_ = root.Close()
		return nil, nil, ErrUnsafe
	}
	flags := preparationLockFlags(create)
	if len(names) == 0 {
		if !create {
			_ = root.Close()
			return nil, nil, ErrIncomplete
		}
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := root.OpenFile("preparation.lock", flags, 0600)
	if err != nil {
		_ = root.Close()
		return nil, nil, ErrStorage
	}
	lockInfo, err := file.Stat()
	pathInfo, pathErr := root.Lstat("preparation.lock")
	if err != nil || pathErr != nil || !sameFile(lockInfo, pathInfo) || !regular(lockInfo, 0, 0) || lockInfo.Size() != 0 {
		_ = file.Close()
		_ = root.Close()
		return nil, nil, ErrUnsafe
	}
	if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = file.Close()
		_ = root.Close()
		return nil, nil, ErrLocked
	}
	if create {
		if file.Sync() != nil || syncRoot(root) != nil {
			_ = file.Close()
			_ = root.Close()
			return nil, nil, ErrStorage
		}
		parent, err := os.Open("/var/lib")
		if err != nil {
			_ = file.Close()
			_ = root.Close()
			return nil, nil, ErrStorage
		}
		syncErr := parent.Sync()
		closeErr := parent.Close()
		if syncErr != nil || closeErr != nil {
			_ = file.Close()
			_ = root.Close()
			return nil, nil, ErrStorage
		}
	}
	return root, file, nil
}
func checkRoot(root *os.Root, uid, gid uint32) error {
	info, err := root.Stat(".")
	if err != nil || !ownedDirectory(info, uid, gid) || info.Mode().Perm() != 0700 {
		return ErrUnsafe
	}
	return nil
}
func ownedDirectory(info os.FileInfo, uid, gid uint32) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	return ok && native.Uid == uid && native.Gid == gid
}
func regular(info os.FileInfo, uid, gid uint32) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return false
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	return ok && native.Uid == uid && native.Gid == gid && native.Nlink == 1
}
func fileBlocks(info os.FileInfo) uint64 {
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Blocks < 0 || native.Blocks > int64((128*mib+mib)/512) {
		return 0
	}
	return uint64(native.Blocks) * 512
}
func allocated(info os.FileInfo, p VolumePlan, o preparationOptions) bool {
	return p.Bytes >= 4*mib && p.Bytes <= 128*mib && regular(info, o.uid, o.gid) && info.Size() == int64(p.Bytes) && fileBlocks(info) >= p.Bytes && fileBlocks(info) <= p.Bytes+mib
}
func sameFile(before, after os.FileInfo) bool {
	if before == nil || after == nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return false
	}
	a, ok := before.Sys().(*syscall.Stat_t)
	b, other := after.Sys().(*syscall.Stat_t)
	return ok && other && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Blocks == b.Blocks
}
func directoryNames(root *os.Root, limit int) ([]string, error) {
	file, err := root.Open(".")
	if err != nil {
		return nil, ErrStorage
	}
	defer file.Close()
	entries, err := file.ReadDir(limit)
	if err != nil && err != io.EOF {
		return nil, ErrStorage
	}
	if len(entries) >= limit {
		return nil, ErrUnsafe
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
func syncRoot(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return ErrStorage
	}
	defer file.Close()
	if file.Sync() != nil {
		return ErrStorage
	}
	return nil
}

func checkSpace(root *os.Root, total uint64) error {
	file, err := root.Open(".")
	if err != nil {
		return ErrStorage
	}
	defer file.Close()
	var stat unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &stat) != nil || stat.Type != unix.EXT4_SUPER_MAGIC || stat.Bsize <= 0 {
		return ErrPlatform
	}
	unit := uint64(stat.Bsize)
	if stat.Bavail > ^uint64(0)/unit || stat.Bavail*unit < total+64*mib || stat.Ffree < 64 {
		return ErrCapacity
	}
	return nil
}
func allocateImage(file *os.File, size uint64) error {
	if size < 4*mib || size > 128*mib || size%4096 != 0 {
		return ErrInvalid
	}
	return unix.Fallocate(int(file.Fd()), 0, 0, int64(size))
}

func materializeImage(ctx context.Context, file *os.File, size uint64) error {
	if size < 4*mib || size > 128*mib || size%4096 != 0 {
		return ErrInvalid
	}
	// Preserve every byte while converting reserved ranges after formatting.
	// A formatter may have used zero-range even when discard was disabled.
	buffer := make([]byte, 64*1024)
	for offset := uint64(0); offset < size; {
		if ctx.Err() != nil {
			return ErrStorage
		}
		length := uint64(len(buffer))
		if size-offset < length {
			length = size - offset
		}
		count, err := file.ReadAt(buffer[:int(length)], int64(offset))
		if err != nil {
			return err
		}
		if count != int(length) {
			return io.ErrUnexpectedEOF
		}
		count, err = file.WriteAt(buffer[:int(length)], int64(offset))
		if err != nil {
			return err
		}
		if count != int(length) {
			return io.ErrShortWrite
		}
		offset += length
	}
	return nil
}
func formatterLabel(domain string) string {
	if domain == "observations" {
		return "ANDEIVA_OBS"
	}
	return "ANDEIVA_" + domain
}

func formatterArguments(p VolumePlan) ([]string, error) {
	matched := false
	for _, standard := range LabPlan().Volumes {
		if standard == p {
			matched = true
		}
	}
	if !matched {
		return nil, ErrInvalid
	}
	return []string{"-t", "ext4", "-q", "-F", "-b", "4096", "-I", "256", "-N", strconv.FormatUint(uint64(p.Inodes), 10), "-m", "0", "-E", "nodiscard,lazy_itable_init=0,lazy_journal_init=0", "-L", formatterLabel(p.Domain), "/proc/self/fd/3"}, nil
}

func formatImage(ctx context.Context, file *os.File, p VolumePlan) error {
	args, err := formatterArguments(p)
	if err != nil {
		return err
	}
	// FD 3 refers only to the new exclusive regular image. No operator path is
	// passed to the formatter, and the environment cannot select another config.
	command := exec.CommandContext(ctx, "/usr/sbin/mke2fs", args...) // #nosec G204 -- Fixed formatter and arguments from the private laboratory profile; the only target is inherited FD 3 of a new exclusive regular image.
	command.ExtraFiles = []*os.File{file}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "TZ=UTC"}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = 2 * time.Second
	if command.Run() != nil {
		return ErrFormatter
	}
	return nil
}
func readPinned(root *os.Root, name string, pinned os.FileInfo, o preparationOptions) ([]byte, error) {
	if name != manifestName && name != pendingName || !regular(pinned, o.uid, o.gid) || pinned.Size() < 1 || pinned.Size() > maxManifestBytes {
		return nil, ErrUnsafe
	}
	file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameFile(pinned, opened) {
		return nil, ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	after, statErr := file.Stat()
	pathInfo, pathErr := root.Lstat(name)
	if err != nil || statErr != nil || pathErr != nil || int64(len(data)) != pinned.Size() || !sameFile(pinned, after) || !sameFile(pinned, pathInfo) {
		return nil, ErrUnsafe
	}
	return data, nil
}
func publishManifest(root *os.Root, o preparationOptions) error {
	if err := checkRoot(root, o.uid, o.gid); err != nil {
		return err
	}
	before, err := root.Stat(".")
	if err != nil {
		return ErrUnsafe
	}
	directory, err := root.Open(".")
	if err != nil {
		return ErrStorage
	}
	defer directory.Close()
	after, err := directory.Stat()
	if err != nil || !os.SameFile(before, after) {
		return ErrUnsafe
	}
	if unix.Renameat2(int(directory.Fd()), pendingName, int(directory.Fd()), manifestName, unix.RENAME_NOREPLACE) != nil {
		return ErrStorage
	}
	return nil
}

func openArea(base *os.Root, name string, uid, gid uint32) (*os.Root, error) {
	if base == nil || !strings.HasPrefix(name, "volumes-") || !validID(strings.TrimPrefix(name, "volumes-")) {
		return nil, ErrInvalid
	}
	before, err := base.Lstat(name)
	if err != nil || !ownedDirectory(before, uid, gid) || before.Mode().Perm() != 0700 {
		return nil, ErrUnsafe
	}
	root, err := base.OpenRoot(name)
	if err != nil {
		return nil, ErrUnsafe
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		_ = root.Close()
		return nil, ErrUnsafe
	}
	return root, nil
}

// Inspection needs an exclusive lock, but never write access to its inode.
func preparationLockFlags(create bool) int {
	flags := os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if create {
		flags = os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK
	}
	return flags
}
