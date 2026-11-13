//go:build linux

package previewruntime

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func scopeRecoveryReadControlV3(directory *os.Root, name string, max int) ([]byte, error) {
	if directory == nil || (name != "cgroup.procs" && name != "cgroup.type" && name != "cgroup.subtree_control") || max < 1 || max > 32768 {
		return nil, ErrIdentity
	}
	f, err := directory.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, ErrIdentity
	}
	return raw, nil
}
func scopeRecoveryLiveCgroupV3(ctx context.Context, directory *os.File, allowSelf bool) error {
	if ctx == nil || ctx.Err() != nil || directory == nil {
		return ErrIdentity
	}
	area, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", directory.Fd()))
	if err != nil {
		return err
	}
	defer area.Close()
	before, err := directory.Stat()
	if err != nil {
		return err
	}
	after, err := area.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return ErrIdentity
	}
	check, err := area.Open(".")
	if err != nil {
		return err
	}
	defer check.Close()
	entries, err := check.ReadDir(257)
	if err != nil && err != io.EOF || len(entries) > 256 {
		return ErrIdentity
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrIdentity
		}
	}
	kind, err := scopeRecoveryReadControlV3(area, "cgroup.type", 128)
	if err != nil || string(kind) != "domain\n" {
		return ErrIdentity
	}
	subtree, err := scopeRecoveryReadControlV3(area, "cgroup.subtree_control", 128)
	if err != nil || len(strings.Fields(string(subtree))) != 0 {
		return ErrIdentity
	}
	members, err := scopeRecoveryReadControlV3(area, "cgroup.procs", 32768)
	if err != nil {
		return err
	}
	if allowSelf {
		if !routedCgroupOnlySupervisorV3(members, os.Getpid()) {
			return ErrUnavailable
		}
	} else if len(strings.Fields(string(members))) != 0 {
		return ErrUnavailable
	}
	return ctx.Err()
}

// These callbacks are assembled only from retained Root handles below. Keeping
// the ordering separate permits failure tests without simulating a real cgroup.
type scopeRecoveryDrainChecksV3 struct {
	selected, anchors, currentLive, drained func() error
	unit                                    func() (scopeRecoveryUnitV3, error)
	current                                 func() (RoutedScopeRecoveryFileV3, error)
	events                                  func() ([]byte, error)
	oldLive                                 func(bool) error
}

func verifyScopeRecoveryDrainV3(ctx context.Context, old RoutedScopeRecoveryFileV3, invocation string, c scopeRecoveryDrainChecksV3) error {
	if ctx == nil || ctx.Err() != nil || c.selected == nil || c.anchors == nil || c.unit == nil || c.current == nil || c.events == nil || c.oldLive == nil || c.currentLive == nil || c.drained == nil {
		return ErrIdentity
	}
	if err := c.selected(); err != nil {
		return err
	}
	if err := c.anchors(); err != nil {
		return err
	}
	unit, err := c.unit()
	if err != nil || unit.mainPID <= 1 {
		return ErrIdentity
	}
	current, err := c.current()
	if err != nil {
		return err
	}
	raw, readErr := c.events()
	deactivated, populated, err := scopeRecoveryOldEventsObservationV3(raw, readErr, old, current, invocation, unit.invocation)
	if err != nil {
		return err
	}
	if !deactivated {
		same := current == old
		if populated != same {
			return ErrUnavailable
		}
		if err = c.oldLive(same); err != nil {
			return err
		}
	}
	// ENODEV on the original core events FD excludes live access to that removed
	// cgroup; it says nothing about the replacement group's descendants. Both
	// selected-state checks and current-group drainage remain mandatory.
	if err = c.currentLive(); err != nil {
		return err
	}
	if err = c.drained(); err != nil {
		return err
	}
	if err = c.selected(); err != nil {
		return err
	}
	if err = c.anchors(); err != nil {
		return err
	}
	finalUnit, err := c.unit()
	if err != nil || finalUnit != unit {
		return ErrIdentity
	}
	finalGroup, err := c.current()
	if err != nil || finalGroup != current {
		return ErrIdentity
	}
	raw, readErr = c.events()
	againDeactivated, againPopulated, err := scopeRecoveryOldEventsObservationV3(raw, readErr, old, current, invocation, unit.invocation)
	if err != nil || againDeactivated != deactivated || againPopulated != populated {
		return ErrIdentity
	}
	if !deactivated {
		if err = c.oldLive(current == old); err != nil {
			return err
		}
	}
	if err = c.currentLive(); err != nil {
		return err
	}
	if err = c.drained(); err != nil {
		return err
	}
	return ctx.Err()
}

func scopeRecoveryRuntimeIdentityV3(m Metadata, boot []byte, process, thread uint64) error {
	actual, err := canonicalBoot(boot)
	if m.ValidateRouted() != nil || err != nil || actual != m.BootID || process != m.HostNamespace || thread != m.HostNamespace {
		return ErrIdentity
	}
	return nil
}

func (r *RoutedScopeRecoveryV3) checkDrainedV3(ctx context.Context, checkSelected func() error) error {
	if r == nil || ctx == nil || ctx.Err() != nil || checkSelected == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	group, err := os.Open("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		return err
	}
	defer group.Close()
	checks := scopeRecoveryDrainChecksV3{
		selected: checkSelected,
		anchors: func() error {
			if err := r.revalidateLocked(ctx); err != nil {
				return err
			}
			boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			process, pe := namespaceID("/proc/self/ns/net")
			thread, te := namespaceID("/proc/thread-self/ns/net")
			if err != nil || pe != nil || te != nil {
				return ErrIdentity
			}
			return scopeRecoveryRuntimeIdentityV3(r.record.Metadata, boot, process, thread)
		},
		unit: func() (scopeRecoveryUnitV3, error) { return readScopeRecoveryUnitV3(ctx) },
		current: func() (RoutedScopeRecoveryFileV3, error) {
			id, st, err := scopeRecoveryIdentityV3(group)
			var fs unix.Statfs_t
			if err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 || st.Uid != 0 || st.Gid != 0 || unix.Fstatfs(int(group.Fd()), &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || scopeRecoveryCgroupControlsV3(group) != nil {
				return RoutedScopeRecoveryFileV3{}, ErrIdentity
			}
			actual, err := group.Stat()
			named, ne := os.Lstat("/sys/fs/cgroup" + routedSupervisorCgroupV3)
			if err != nil || ne != nil || !os.SameFile(actual, named) {
				return RoutedScopeRecoveryFileV3{}, ErrIdentity
			}
			return id, nil
		},
		events: func() ([]byte, error) {
			raw := make([]byte, 129)
			n, err := r.files[6].ReadAt(raw, 0)
			return raw[:n], err
		},
		oldLive:     func(allowSelf bool) error { return scopeRecoveryLiveCgroupV3(ctx, r.files[5], allowSelf) },
		currentLive: func() error { return scopeRecoveryLiveCgroupV3(ctx, group, true) },
		drained:     waitRoutedCgroupDrainedV3,
	}
	return verifyScopeRecoveryDrainV3(ctx, r.record.Cgroup, r.record.CgroupInvocation, checks)
}
