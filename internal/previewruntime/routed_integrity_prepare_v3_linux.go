//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

const RoutedIntegrityPrepareRoleV3 = "--andeiva-routed-integrity-prepare-v3"

func validateRoutedIntegrityDirectoryV3(file *os.File, uid, gid uint32, others []os.FileInfo) error {
	if file == nil || uid == 0 || gid == 0 {
		return ErrIdentity
	}
	info, err := file.Stat()
	_, owner := fenceOwnerV3(info, uid, gid)
	flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flagErr != nil || !owner || info.Mode() != os.ModeDir|0700 || flags&unix.O_ACCMODE != unix.O_RDONLY || !fenceNoACLV3(file, true) {
		return ErrIdentity
	}
	for _, other := range others {
		if other != nil && os.SameFile(info, other) {
			return ErrIdentity
		}
	}
	return nil
}

// PrepareRoutedIntegrityLaunchV3 is an explicit installer operation. The root
// supervisor supplies an already helper-owned empty directory. Only its pinned
// FD is transferred to a capless, fixed helper-identity preparation process.
// It never changes ownership, repairs a marker, or participates in runtime open.
func PrepareRoutedIntegrityLaunchV3(ctx context.Context, ids Identities, area *os.Root, stderr io.Writer) error {
	if ctx == nil || ctx.Err() != nil || ids.Validate() != nil || area == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	file, err := area.Open(".")
	if err != nil {
		return ErrIdentity
	}
	defer file.Close()
	if validateRoutedIntegrityDirectoryV3(file, ids.HelperUID, ids.IPCGID, nil) != nil {
		return ErrIdentity
	}
	self, err := os.Executable()
	if err != nil {
		return ErrIdentity
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/setpriv") != nil {
		return ErrIdentity
	}
	args := []string{"--reuid=" + strconv.FormatUint(uint64(ids.HelperUID), 10), "--regid=" + strconv.FormatUint(uint64(ids.IPCGID), 10), "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, RoutedIntegrityPrepareRoleV3}
	// #nosec G204 -- Fixed executable and role; only validated numeric identities and the trusted root-owned current binary are used, without a shell or request data.
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", args...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C", "ANDEIVA_PREPARE_UID=" + strconv.FormatUint(uint64(ids.HelperUID), 10), "ANDEIVA_PREPARE_GID=" + strconv.FormatUint(uint64(ids.IPCGID), 10), "ANDEIVA_PREPARE_PARENT=" + strconv.Itoa(os.Getpid())}
	cmd.ExtraFiles = []*os.File{file}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// PDEATHSIG follows the creating OS thread; keep it alive through Wait.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return cmd.Run()
}

// RunRoutedIntegrityPrepareRoleV3 is dispatched only by the fixed installer
// role. It adopts FD3, validates the actual capless process and root parent,
// creates the marker exclusively, closes its resources, and must then exit.
func RunRoutedIntegrityPrepareRoleV3(ctx context.Context) (result error) {
	if ctx == nil || ctx.Err() != nil {
		return ErrIdentity
	}
	parse := func(name string) (uint32, error) {
		value, err := strconv.ParseUint(os.Getenv(name), 10, 32)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != os.Getenv(name) {
			return 0, ErrIdentity
		}
		return uint32(value), nil
	}
	uid, err := parse("ANDEIVA_PREPARE_UID")
	if err != nil {
		return err
	}
	gid, err := parse("ANDEIVA_PREPARE_GID")
	if err != nil {
		return err
	}
	parent, err := parse("ANDEIVA_PREPARE_PARENT")
	if err != nil || uint64(parent) > uint64(^uint(0)>>1) || int(parent) <= 1 || os.Getppid() != int(parent) {
		return ErrIdentity
	}
	groups, err := os.Getgroups()
	if err != nil {
		return ErrIdentity
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || routedIntegrityPrepareProcessV3(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), groups, string(status), uid, gid) != nil {
		return ErrIdentity
	}
	parentFile, err := os.Open("/proc/" + strconv.FormatUint(uint64(parent), 10) + "/status")
	if err != nil {
		return ErrIdentity
	}
	data, readErr := io.ReadAll(io.LimitReader(parentFile, 65537))
	closeErr := parentFile.Close()
	parentInfo, statErr := os.Stat("/proc/" + strconv.FormatUint(uint64(parent), 10))
	if statErr != nil {
		return ErrIdentity
	}
	owner, ok := parentInfo.Sys().(*syscall.Stat_t)
	if readErr != nil || closeErr != nil || !ok || owner.Uid != 0 || !rootRoutedParentStatusV3(data, int(parent)) || unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0) != nil || os.Getppid() != int(parent) {
		return ErrIdentity
	}
	file := os.NewFile(3, "routed-integrity-prepare-root")
	if file == nil {
		return ErrIdentity
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	if validateRoutedIntegrityDirectoryV3(file, uid, gid, nil) != nil {
		return ErrIdentity
	}
	unix.CloseOnExec(3)
	area, err := os.OpenRoot("/proc/self/fd/3")
	if err != nil {
		return ErrIdentity
	}
	defer func() { result = errors.Join(result, area.Close()) }()
	before, err := file.Stat()
	after, ae := area.Stat(".")
	if err != nil || ae != nil || !os.SameFile(before, after) || ctx.Err() != nil {
		return ErrIdentity
	}
	return prepareRoutedIntegrityFenceV3(area, uid, gid)
}

func routedIntegrityPrepareProcessV3(uid, euid, gid, egid int, groups []int, status string, wantUID, wantGID uint32) error {
	if wantUID == 0 || wantGID == 0 || len(status) > 65536 || !matchesIdentity(uid, wantUID) || !matchesIdentity(euid, wantUID) || !matchesIdentity(gid, wantGID) || !matchesIdentity(egid, wantGID) || privilegeFields(status, false) != nil {
		return ErrIdentity
	}
	for _, group := range groups {
		if !matchesIdentity(group, wantGID) {
			return ErrIdentity
		}
	}
	return nil
}
