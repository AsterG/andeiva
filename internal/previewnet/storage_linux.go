package previewnet

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

func decode(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrRuntime
	}
	return nil
}

func secureDirectory(path string, create bool) error {
	if create {
		// Runtime metadata and namespace traversal are shared with both service UIDs;
		// only root can write this directory, and control sockets remain root-only.
		if err := os.Mkdir(path, 0755); err == nil { // #nosec G301 -- shared traversal, ownership and exact mode checked below.
			if err = os.Chmod(path, 0755); err != nil { // #nosec G302 -- directory traversal, not a secret file.
				return err
			}
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	i, e := os.Lstat(path)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0755 || i.Sys().(*syscall.Stat_t).Uid != 0 {
		return ErrRuntime
	}
	return nil
}

func ownedRegular(path string, mode os.FileMode, limit int64) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != mode || i.Size() > limit {
		return nil, ErrRuntime
	}
	s := i.Sys().(*syscall.Stat_t)
	if s.Uid != 0 || s.Nlink != 1 {
		return nil, ErrRuntime
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func kernelBootID() (string, error) {
	b, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	value := strings.TrimSpace(string(b))
	if e != nil || !validBootID(value) {
		return "", ErrRuntime
	}
	return value, nil
}

func readMetadataPath(path string) (Metadata, error) {
	var m Metadata
	b, e := ownedRegular(path, 0644, 4096)
	if e != nil {
		return m, e
	}
	if decode(b, &m) != nil || m.Validate() != nil {
		return Metadata{}, ErrRuntime
	}
	return m, nil
}

func ReadMetadata() (Metadata, error) {
	if secureDirectory(RuntimeDir, false) != nil {
		return Metadata{}, ErrRuntime
	}
	m, e := readMetadataPath(MetadataPath)
	if e != nil {
		return Metadata{}, ErrRuntime
	}
	boot, e := kernelBootID()
	if e != nil || boot != m.BootID {
		return Metadata{}, ErrRuntime
	}
	return m, nil
}

func namespaceInode(path string) (uint64, error) {
	i, e := os.Stat(path)
	if e != nil {
		return 0, e
	}
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok || s.Ino == 0 {
		return 0, ErrRuntime
	}
	return s.Ino, nil
}

func lockRuntime() (*os.File, error) {
	fd, e := syscall.Open(RuntimeDir+"/runtime.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "runtime.lock")
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 || i.Sys().(*syscall.Stat_t).Uid != 0 || i.Sys().(*syscall.Stat_t).Nlink != 1 {
		_ = f.Close()
		return nil, ErrRuntime
	}
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		_ = f.Close()
		return nil, ErrRuntime
	}
	return f, nil
}

func writeMetadata(m Metadata) error {
	if m.Validate() != nil {
		return ErrRuntime
	}
	data, e := json.Marshal(m)
	if e != nil {
		return e
	}
	path := RuntimeDir + "/runtime.pending"
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	e = f.Chmod(0644) // #nosec G302 -- non-secret namespace IDs read by separate service UIDs; root-only writes.
	if e == nil {
		_, e = f.Write(append(data, '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if _, e = os.Lstat(MetadataPath); !errors.Is(e, os.ErrNotExist) {
		return ErrRuntime
	}
	if e = os.Rename(path, MetadataPath); e != nil {
		return e
	}
	d, e := os.Open(RuntimeDir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

func unpinGateway(m Metadata) error {
	i, e := os.Lstat(NamespacePath)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	var stat syscall.Statfs_t
	if syscall.Statfs(NamespacePath, &stat) != nil {
		return ErrRuntime
	}
	if stat.Type == 0x6e736673 { // NSFS_MAGIC; never detach a different mount.
		if i.Sys().(*syscall.Stat_t).Ino != m.GatewayNamespace {
			return ErrRuntime
		}
		if e = syscall.Unmount(NamespacePath, 0); e != nil {
			return e
		}
	}
	b, e := ownedRegular(NamespacePath, 0600, 0)
	if e != nil || len(b) != 0 {
		return ErrRuntime
	}
	return os.Remove(NamespacePath)
}

func removeOwnedSocket(path string) error {
	i, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if i.Mode()&os.ModeSocket == 0 || i.Mode().Perm() != 0600 || i.Sys().(*syscall.Stat_t).Uid != 0 {
		return ErrRuntime
	}
	return os.Remove(path)
}

// A crash may leave a namespace referenced by a thread or a mounted-path FD.
// This preview never infers absence from a partial process scan. Preserve every
// stale artifact and require an authorized VM reboot to clear volatile runtime.
func recoverRuntime() error {
	return requireAbsent(MetadataPath, NamespacePath, RuntimeDir+"/runtime.pending", ControlPath)
}

func requireAbsent(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return ErrRecovery
		}
	}
	return nil
}
