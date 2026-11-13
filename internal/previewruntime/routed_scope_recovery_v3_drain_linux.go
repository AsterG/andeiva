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
func (r *RoutedScopeRecoveryV3) checkDrainedV3(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revalidateLocked(ctx) != nil {
		return ErrIdentity
	}
	unit, err := readScopeRecoveryUnitV3(ctx)
	if err != nil {
		return err
	}
	group, err := os.Open("/sys/fs/cgroup" + routedSupervisorCgroupV3)
	if err != nil {
		return err
	}
	defer group.Close()
	current, _, err := scopeRecoveryIdentityV3(group)
	if err != nil {
		return err
	}
	raw := make([]byte, 129)
	n, readErr := r.files[6].ReadAt(raw, 0)
	deactivated, populated, err := scopeRecoveryOldEventsObservationV3(raw[:n], readErr, r.record.Cgroup, current, r.record.CgroupInvocation, unit.invocation)
	if err != nil {
		return err
	}
	if deactivated {
		// Native ENODEV behavior is observed, but promotion to retirement authority
		// remains blocked until the complete selected/anchor predicate is reviewed.
		return ErrUnavailable
	}
	same := current == r.record.Cgroup
	if populated != same {
		return ErrUnavailable
	}
	if err = scopeRecoveryLiveCgroupV3(ctx, r.files[5], same); err != nil {
		return err
	}
	// The current helper/reader has exited. Reject any unexpected descendant in
	// Root's current cgroup too; it must not retain old namespace descriptors.
	if err = waitRoutedCgroupDrainedV3(); err != nil {
		return err
	}
	n, readErr = r.files[6].ReadAt(raw, 0)
	deactivated, again, err := scopeRecoveryOldEventsObservationV3(raw[:n], readErr, r.record.Cgroup, current, r.record.CgroupInvocation, unit.invocation)
	if err != nil || deactivated || again != populated || ctx.Err() != nil {
		return ErrIdentity
	}
	return nil
}
