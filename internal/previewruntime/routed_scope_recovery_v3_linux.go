//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// All descriptors are borrowed from root assembly or systemd's named FD store.
// They must never be supplied by API input. Record is an allocated root 0600
// regular file; Underlay is the original pre-bind file, not a reopened pathname.
type RoutedScopeRecoveryAnchorsV3 struct {
	Record, Gateway, Mount, Underlay, Directory, Cgroup, CgroupEvents *os.File
}

// RoutedScopeRecoveryV3 retains identity-checked descriptors only. It deliberately
// has no Retire or Receipt method: stored FDs alone do not establish drainage.
type RoutedScopeRecoveryV3 struct {
	mu     sync.Mutex
	record RoutedScopeRecoveryRecordV3
	files  [7]*os.File
	closed bool
}

func scopeRecoveryFilesV3(a RoutedScopeRecoveryAnchorsV3) [7]*os.File {
	return [7]*os.File{a.Record, a.Gateway, a.Mount, a.Underlay, a.Directory, a.Cgroup, a.CgroupEvents}
}
func scopeRecoveryIdentityV3(f *os.File) (RoutedScopeRecoveryFileV3, unix.Stat_t, error) {
	var st unix.Stat_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil {
		return RoutedScopeRecoveryFileV3{}, st, ErrIdentity
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return RoutedScopeRecoveryFileV3{}, st, ErrIdentity
	}
	return RoutedScopeRecoveryFileV3{Device: uint64(st.Dev), Inode: st.Ino}, st, nil
}
func scopeRecoveryNamespaceV3(f *os.File, kind uintptr) bool {
	var fs unix.Statfs_t
	actual, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), unix.NS_GET_NSTYPE, 0)
	return errno == 0 && actual == kind && unix.Fstatfs(int(f.Fd()), &fs) == nil && fs.Type == unix.NSFS_MAGIC
}
func validateScopeRecoveryAnchorsV3(a RoutedScopeRecoveryAnchorsV3, r RoutedScopeRecoveryRecordV3) error {
	if !r.valid() {
		return ErrIdentity
	}
	files := scopeRecoveryFilesV3(a)
	wanted := [7]RoutedScopeRecoveryFileV3{{}, r.Gateway, r.Mount, r.Underlay, r.Directory, r.Cgroup, r.CgroupEvents}
	seen := map[RoutedScopeRecoveryFileV3]bool{}
	for i, f := range files {
		id, st, err := scopeRecoveryIdentityV3(f)
		if err != nil || seen[id] || (i != 0 && id != wanted[i]) {
			return ErrIdentity
		}
		seen[id] = true
		switch i {
		case 0:
			if validateScopeRecoveryRecordFileV3(f) != nil {
				return ErrIdentity
			}
		case 1:
			if !scopeRecoveryNamespaceV3(f, unix.CLONE_NEWNET) {
				return ErrIdentity
			}
		case 2:
			if !scopeRecoveryNamespaceV3(f, unix.CLONE_NEWNS) {
				return ErrIdentity
			}
		case 3:
			if st.Mode != unix.S_IFREG|0600 || st.Size != 0 || st.Nlink != 1 || st.Uid != 0 || st.Gid != 0 || !fenceNoACLV3(f, false) {
				return ErrIdentity
			}
		case 4:
			if st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 || !fenceNoACLV3(f, true) {
				return ErrIdentity
			}
		case 5:
			var fs unix.Statfs_t
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Gid != 0 || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
				return ErrIdentity
			}
		case 6:
			var fs unix.Statfs_t
			if st.Mode != unix.S_IFREG|0444 || st.Uid != 0 || st.Gid != 0 || uint64(st.Dev) != r.Cgroup.Device || unix.Fstatfs(int(f.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
				return ErrIdentity
			}
		}
	}
	return nil
}

// OpenRoutedScopeRecoveryV3 is read-only and duplicates every accepted FD with
// CLOEXEC. Old records cannot cross OS boots. A root-created manifest remains
// necessary; runtime.json alone lacks these pin and cgroup identities.
func OpenRoutedScopeRecoveryV3(ctx context.Context, a RoutedScopeRecoveryAnchorsV3) (out *RoutedScopeRecoveryV3, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrIdentity
	}
	r := &RoutedScopeRecoveryV3{}
	defer func() {
		if result != nil {
			result = errors.Join(result, r.Close())
		}
	}()
	for i, f := range scopeRecoveryFilesV3(a) {
		if f == nil {
			return nil, ErrIdentity
		}
		fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil || fd < 0 {
			return nil, ErrIdentity
		}
		r.files[i] = os.NewFile(uintptr(fd), "routed-scope-recovery")
	}
	held := RoutedScopeRecoveryAnchorsV3{r.files[0], r.files[1], r.files[2], r.files[3], r.files[4], r.files[5], r.files[6]}
	if validateScopeRecoveryRecordFileV3(held.Record) != nil {
		return nil, ErrIdentity
	}
	raw := make([]byte, RoutedScopeRecoveryRecordSizeV3)
	if n, err := held.Record.ReadAt(raw, 0); err != nil || n != len(raw) {
		return nil, ErrIdentity
	}
	record, err := DecodeRoutedScopeRecoveryV3(raw)
	if err != nil || validateScopeRecoveryAnchorsV3(held, record) != nil {
		return nil, ErrIdentity
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, ErrIdentity
	}
	actual, err := canonicalBoot(boot)
	if err != nil || actual != record.Metadata.BootID {
		return nil, ErrIdentity
	}
	host, err := namespaceID("/proc/self/ns/net")
	if err != nil || host != record.Metadata.HostNamespace {
		return nil, ErrIdentity
	}
	// Reread the entire fixed record to detect replacement/torn publication while
	// descriptors were being validated. Root owns the serialized lifecycle.
	final := make([]byte, len(raw))
	if n, err := held.Record.ReadAt(final, 0); err != nil || n != len(final) || retirementDigestV3(raw) != retirementDigestV3(final) || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	r.record = record
	return r, nil
}
func (r *RoutedScopeRecoveryV3) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var result error
	for i, f := range r.files {
		if f != nil {
			result = errors.Join(result, f.Close())
			r.files[i] = nil
		}
	}
	return result
}

func validateScopeRecoveryRecordFileV3(f *os.File) error {
	_, st, err := scopeRecoveryIdentityV3(f)
	if err != nil || st.Mode != unix.S_IFREG|0600 || st.Size != RoutedScopeRecoveryRecordSizeV3 || st.Nlink != 1 || st.Blocks < RoutedScopeRecoveryRecordSizeV3/512 || st.Uid != 0 || st.Gid != 0 || !fenceNoACLV3(f, false) {
		return ErrIdentity
	}
	return nil
}

// PrepareRoutedScopeRecoveryRecordV3 captures actual creation-time anchors before
// L2 effects. The caller must persist/fsync these bytes in a preallocated slot,
// store all named FDs and verify manager readback before admitting any effect.
// Returning bytes does not assert that any of those publication steps happened.
func PrepareRoutedScopeRecoveryRecordV3(ctx context.Context, m Metadata, ids Identities, a RoutedScopeRecoveryAnchorsV3) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || m.ValidateRouted() != nil || ids.Validate() != nil {
		return nil, ErrIdentity
	}
	r := RoutedScopeRecoveryRecordV3{Version: 3, Phase: "pinned", Metadata: m, Identities: ids, MetadataSHA256: retirementDigestV3(marshal(m))}
	destinations := []*RoutedScopeRecoveryFileV3{&r.Gateway, &r.Mount, &r.Underlay, &r.Directory, &r.Cgroup, &r.CgroupEvents}
	for i, f := range []*os.File{a.Gateway, a.Mount, a.Underlay, a.Directory, a.Cgroup, a.CgroupEvents} {
		id, _, err := scopeRecoveryIdentityV3(f)
		if err != nil {
			return nil, err
		}
		*destinations[i] = id
	}
	if validateScopeRecoveryAnchorsV3(a, r) != nil {
		return nil, ErrIdentity
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, ErrIdentity
	}
	actual, err := canonicalBoot(boot)
	if err != nil || actual != m.BootID {
		return nil, ErrIdentity
	}
	host, err := namespaceID("/proc/self/ns/net")
	if err != nil || host != m.HostNamespace {
		return nil, ErrIdentity
	}
	mount, err := namespaceID("/proc/self/ns/mnt")
	if err != nil || mount != r.Mount.Inode {
		return nil, ErrIdentity
	}
	group, err := os.Open("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		return nil, ErrIdentity
	}
	defer group.Close()
	actualGroup, _, err := scopeRecoveryIdentityV3(group)
	if err != nil || actualGroup != r.Cgroup || waitRoutedCgroupDrainedV3() != nil || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	eventsFD, err := unix.Openat(int(a.Cgroup.Fd()), "cgroup.events", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrIdentity
	}
	events := os.NewFile(uintptr(eventsFD), "root-cgroup-events")
	defer events.Close()
	eventIdentity, _, err := scopeRecoveryIdentityV3(events)
	if err != nil || eventIdentity != r.CgroupEvents {
		return nil, ErrIdentity
	}
	return EncodeRoutedScopeRecoveryV3(r)
}

func (r *RoutedScopeRecoveryV3) revalidateLocked(ctx context.Context) error {
	if r.closed || ctx.Err() != nil {
		return ErrIdentity
	}
	a := RoutedScopeRecoveryAnchorsV3{r.files[0], r.files[1], r.files[2], r.files[3], r.files[4], r.files[5], r.files[6]}
	if validateScopeRecoveryAnchorsV3(a, r.record) != nil {
		return ErrIdentity
	}
	raw := make([]byte, RoutedScopeRecoveryRecordSizeV3)
	if n, err := a.Record.ReadAt(raw, 0); err != nil || n != len(raw) {
		return ErrIdentity
	}
	actual, err := DecodeRoutedScopeRecoveryV3(raw)
	if err != nil || actual != r.record || ctx.Err() != nil {
		return ErrIdentity
	}
	return nil
}
