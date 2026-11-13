//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type scopeRecoveryUnitV3 struct {
	invocation string
	mainPID    int
}

func parseScopeRecoveryUnitV3(raw []byte, self int) (scopeRecoveryUnitV3, error) {
	var out scopeRecoveryUnitV3
	if self <= 1 || len(raw) == 0 || len(raw) > 4096 {
		return out, ErrIdentity
	}
	expected := map[string]string{"MainPID": strconv.Itoa(self), "ControlGroup": routedSupervisorCgroupV3, "Delegate": "no"}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || seen[k] {
			return out, ErrIdentity
		}
		seen[k] = true
		if k == "InvocationID" {
			if !validHex(v, 16) {
				return out, ErrIdentity
			}
			out.invocation = v
			continue
		}
		want, ok := expected[k]
		if !ok || v != want {
			return out, ErrIdentity
		}
	}
	if len(seen) != 4 {
		return out, ErrIdentity
	}
	out.mainPID = self
	return out, nil
}
func readScopeRecoveryUnitV3(ctx context.Context) (scopeRecoveryUnitV3, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || trustedRoutedExecutableV3("/usr/bin/systemctl") != nil {
		return scopeRecoveryUnitV3{}, ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/systemctl", "--no-pager", "show", "--property=MainPID", "--property=ControlGroup", "--property=Delegate", "--property=InvocationID", "andeiva-preview-grouped.service")
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C", "SYSTEMD_COLORS=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var output scopeRecoveryOutputV3
	cmd.Stdout = &output
	runtime.LockOSThread()
	err := cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || call.Err() != nil {
		return scopeRecoveryUnitV3{}, ErrIdentity
	}
	unit, err := parseScopeRecoveryUnitV3(output.Bytes(), os.Getpid())
	if err != nil || unit.invocation != os.Getenv("INVOCATION_ID") {
		return scopeRecoveryUnitV3{}, ErrIdentity
	}
	return unit, nil
}

func scopeRecoveryEventsV3(raw []byte) (populated bool, err error) {
	if len(raw) == 0 || len(raw) > 128 {
		return false, ErrIdentity
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] || (fields[1] != "0" && fields[1] != "1") {
			return false, ErrIdentity
		}
		seen[fields[0]] = true
		switch fields[0] {
		case "populated":
			populated = fields[1] == "1"
		case "frozen":
			if fields[1] != "0" {
				return false, ErrIdentity
			}
		default:
			return false, ErrIdentity
		}
	}
	if len(seen) != 2 {
		return false, ErrIdentity
	}
	return populated, nil
}

// This observation is not retirement authority. The caller must independently
// bind the exact current selected scope and preserve its publication barrier.
// ENODEV is meaningful only on the original, authenticated core events FD; it
// never substitutes for opening a missing path in a replacement cgroup.
func scopeRecoveryOldEventsObservationV3(raw []byte, readErr error, old, current RoutedScopeRecoveryFileV3, oldInvocation, currentInvocation string) (deactivated, populated bool, err error) {
	if old.Device == 0 || old.Inode == 0 || current.Device == 0 || current.Inode == 0 || old.Device != current.Device || !validHex(oldInvocation, 16) || !validHex(currentInvocation, 16) || oldInvocation == currentInvocation {
		return false, false, ErrIdentity
	}
	if errors.Is(readErr, unix.ENODEV) {
		if len(raw) != 0 || old == current {
			return false, false, ErrIdentity
		}
		return true, false, nil
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return false, false, ErrIdentity
	}
	populated, err = scopeRecoveryEventsV3(raw)
	return false, populated, err
}

func scopeRecoveryCgroupControlsV3(directory *os.File) error {
	if directory == nil {
		return ErrIdentity
	}
	for _, name := range []string{"cgroup.procs", "cgroup.subtree_control"} {
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return ErrIdentity
		}
		var st unix.Stat_t
		var fs unix.Statfs_t
		statErr, fsErr := unix.Fstat(fd, &st), unix.Fstatfs(fd, &fs)
		closeErr := unix.Close(fd)
		if statErr != nil || fsErr != nil || closeErr != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Uid != 0 || st.Gid != 0 {
			return ErrIdentity
		}
	}
	return nil
}
