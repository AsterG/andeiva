//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// EnsureRoutedDHCPSubnetIDsV1 receives the protected operational root, never a
// request path. Bootstrap must separately verify the maintained engine's lease
// owner. The fixed leases child must match the supplied pin. No engine effect
// is authorized until this returns IDs successfully. Directory FDs are borrowed.
func EnsureRoutedDHCPSubnetIDsV1(ctx context.Context, directory, leases *os.File, bindings []RoutedDHCPSubnetBindingV1) ([]uint32, error) {
	if os.Geteuid() != 0 {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	return ensureDHCPSubnetIDsV1(ctx, directory, leases, bindings, 0, 0)
}

// Owner parameters keep filesystem validation independently testable without
// root. The production entry point fixes both to zero.
func ensureDHCPSubnetIDsV1(ctx context.Context, directory, leases *os.File, bindings []RoutedDHCPSubnetBindingV1, uid, gid uint32) ([]uint32, error) {
	return ensureDHCPSubnetIDsWithDirectorySyncV1(ctx, directory, leases, bindings, uid, gid, (*os.File).Sync)
}

func ensureDHCPSubnetIDsWithDirectorySyncV1(ctx context.Context, directory, leases *os.File, bindings []RoutedDHCPSubnetBindingV1, uid, gid uint32, syncDirectory func(*os.File) error) (ids []uint32, result error) {
	if ctx == nil || ctx.Err() != nil || directory == nil || leases == nil {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	if _, _, _, err := allocateDHCPSubnetRegistryV1(routedDHCPSubnetRegistryV1{Version: 1, Entries: []routedDHCPSubnetEntryV1{}}, bindings); err != nil {
		return nil, err
	}
	dir, err := dhcpRegistryDirectoryV1(directory, uid, gid)
	if err != nil {
		return nil, err
	}
	defer func() {
		if dir.Close() != nil {
			ids = nil
			result = ErrRoutedDHCPSubnetRegistryV1
		}
	}()
	for {
		err = unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || ctx.Err() != nil {
			return nil, ErrRoutedDHCPSubnetRegistryV1
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ErrRoutedDHCPSubnetRegistryV1
		case <-timer.C:
		}
	}
	// Closing this independently opened description releases its flock.
	if ctx.Err() != nil {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	leaseDir, e := dhcpRegistryLeaseDirectoryV1(dir, leases)
	if e != nil {
		return nil, e
	}
	defer func() {
		if leaseDir.Close() != nil {
			ids = nil
			result = ErrRoutedDHCPSubnetRegistryV1
		}
	}()
	for _, name := range [...]string{routedDHCPSubnetRegistryPendingV1, routedDHCPSubnetRegistryPublishV1} {
		var pending unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), name, &pending, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			return nil, ErrRoutedDHCPSubnetRegistryV1
		}
	}
	r, missing, err := readDHCPSubnetRegistryV1(dir, uid, gid)
	if err != nil {
		return nil, err
	}
	if missing || len(r.Entries) == 0 && len(bindings) > 0 {
		// Lock a fresh description, never the caller's lease lock. An existing
		// engine or any lease entry prevents the first association.
		if unix.Flock(int(leaseDir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
			return nil, ErrRoutedDHCPSubnetRegistryV1
		}
		names, e := leaseDir.Readdirnames(1)
		if e != io.EOF || len(names) != 0 {
			return nil, ErrRoutedDHCPSubnetRegistryV1
		}
	}
	if missing {
		r = routedDHCPSubnetRegistryV1{Version: 1, Entries: []routedDHCPSubnetEntryV1{}}
	}
	next, ids, changed, err := allocateDHCPSubnetRegistryV1(r, bindings)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	if changed || missing {
		if err := publishDHCPSubnetRegistryV1(ctx, dir, next, uid, gid, syncDirectory); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

func dhcpRegistryDirectoryV1(pin *os.File, uid, gid uint32) (*os.File, error) {
	var st unix.Stat_t
	flags, e := unix.FcntlInt(pin.Fd(), unix.F_GETFL, 0)
	if e != nil || flags&unix.O_PATH != 0 || unix.Fstat(int(pin.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != uid || st.Gid != gid || !fenceNoACLV3(pin, true) {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	fd, e := unix.Openat(int(pin.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	f := os.NewFile(uintptr(fd), "dhcp-subnet-registry")
	var actual unix.Stat_t
	if unix.Fstat(fd, &actual) != nil || actual.Dev != st.Dev || actual.Ino != st.Ino {
		_ = f.Close()
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	return f, nil
}

func dhcpRegistryLeaseDirectoryV1(root, pin *os.File) (*os.File, error) {
	var st, actual unix.Stat_t
	if unix.Fstat(int(pin.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || !fenceNoACLV3(pin, true) {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	fd, e := unix.Openat(int(root.Fd()), "leases", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	f := os.NewFile(uintptr(fd), "dhcp-registry-leases")
	if unix.Fstat(fd, &actual) != nil || st.Dev != actual.Dev || st.Ino != actual.Ino {
		_ = f.Close()
		return nil, ErrRoutedDHCPSubnetRegistryV1
	}
	return f, nil
}

func dhcpRegistryFileV1(f *os.File, uid, gid uint32, allowEmpty bool) (unix.Stat_t, error) {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != uid || st.Gid != gid || st.Nlink != 1 || st.Size < 0 || !allowEmpty && st.Size == 0 || st.Size > routedDHCPSubnetRegistryBytesV1 || !fenceNoACLV3(f, false) {
		return st, ErrRoutedDHCPSubnetRegistryV1
	}
	return st, nil
}

func readDHCPSubnetRegistryV1(dir *os.File, uid, gid uint32) (r routedDHCPSubnetRegistryV1, missing bool, result error) {
	fd, e := unix.Openat(int(dir.Fd()), routedDHCPSubnetRegistryNameV1, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(e, unix.ENOENT) {
		return r, true, nil
	}
	if e != nil {
		return r, false, ErrRoutedDHCPSubnetRegistryV1
	}
	f := os.NewFile(uintptr(fd), "dhcp-subnet-bindings")
	defer func() {
		if f.Close() != nil {
			result = ErrRoutedDHCPSubnetRegistryV1
		}
	}()
	before, e := dhcpRegistryFileV1(f, uid, gid, false)
	if e != nil {
		return r, false, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, routedDHCPSubnetRegistryBytesV1+1))
	if e != nil {
		return r, false, ErrRoutedDHCPSubnetRegistryV1
	}
	after, e := dhcpRegistryFileV1(f, uid, gid, false)
	var path unix.Stat_t
	if e != nil || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || unix.Fstatat(int(dir.Fd()), routedDHCPSubnetRegistryNameV1, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || path.Dev != before.Dev || path.Ino != before.Ino {
		return r, false, ErrRoutedDHCPSubnetRegistryV1
	}
	r, e = decodeDHCPSubnetRegistryV1(raw)
	return r, false, e
}

func publishDHCPSubnetRegistryV1(ctx context.Context, dir *os.File, r routedDHCPSubnetRegistryV1, uid, gid uint32, syncDirectory func(*os.File) error) error {
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > routedDHCPSubnetRegistryBytesV1 {
		return ErrRoutedDHCPSubnetRegistryFullV1
	}
	if ctx.Err() != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	// Persist the marker before the rename and retain it through the sync
	// that commits the manifest. A retry cannot clear a prior writeback error.
	if err := writeDHCPSubnetRegistryFileV1(dir, routedDHCPSubnetRegistryPendingV1, nil, uid, gid); err != nil || syncDirectory(dir) != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	if err := writeDHCPSubnetRegistryFileV1(dir, routedDHCPSubnetRegistryPublishV1, raw, uid, gid); err != nil || ctx.Err() != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	fd := int(dir.Fd())
	if unix.Renameat(fd, routedDHCPSubnetRegistryPublishV1, fd, routedDHCPSubnetRegistryNameV1) != nil || syncDirectory(dir) != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	// The manifest is already durable. If syncing marker removal fails, a
	// surviving marker still forces protected recovery after restart.
	if unix.Unlinkat(fd, routedDHCPSubnetRegistryPendingV1, 0) != nil || syncDirectory(dir) != nil || ctx.Err() != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	return nil
}

func writeDHCPSubnetRegistryFileV1(dir *os.File, name string, data []byte, uid, gid uint32) (result error) {
	fd, e := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() {
		if f.Close() != nil {
			result = ErrRoutedDHCPSubnetRegistryV1
		}
	}()
	if f.Chmod(0600) != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	if _, e = dhcpRegistryFileV1(f, uid, gid, true); e != nil {
		return e
	}
	n, e := f.Write(data)
	if e != nil || n != len(data) || f.Sync() != nil {
		return ErrRoutedDHCPSubnetRegistryV1
	}
	return nil
}
