//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"golang.org/x/sys/unix"
)

// The source worker and the installer must finish successfully before the
// grouped unit can start. Failure after publication leaves the grouped unit
// inhibited and the marker intact for offline recovery.
func withActivationSourceV1(ctx context.Context, ids Identities, expected configpoc.LegacyFingerprintV2, prepare func(context.Context) error, publish func(context.Context, func() error) error) error {
	if ctx == nil || ctx.Err() != nil || ids.Validate() != nil || prepare == nil || publish == nil || expected.Domain != "firewall" || expected.Source == "" {
		return ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, activationSourceTimeoutV1)
	defer cancel()
	cmd, err := activationChildV1(ctx, RoutedActivationSourceRoleV1, ids.APIUID, ids.APIGID, ids.IPCGID)
	if err != nil {
		return err
	}
	inputR, inputW, err := os.Pipe()
	if err != nil {
		return ErrUnavailable
	}
	defer inputR.Close()
	defer inputW.Close()
	outputR, outputW, err := os.Pipe()
	if err != nil {
		return ErrUnavailable
	}
	defer outputR.Close()
	defer outputW.Close()
	deadline, _ := ctx.Deadline()
	if inputW.SetWriteDeadline(deadline) != nil || outputR.SetReadDeadline(deadline) != nil {
		return ErrUnavailable
	}
	cmd.Stdin, cmd.Stdout = inputR, outputW
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if cmd.Start() != nil {
		return ErrUnavailable
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	_ = inputR.Close()
	_ = outputW.Close()
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer unix.Close(pidfd)
	output := bufio.NewReaderSize(outputR, 32)
	read := func(want string) bool {
		got, err := output.ReadSlice('\n')
		return err == nil && string(got) == want
	}
	request := activationSourceRequestV1{Version: 1, ParentPID: os.Getpid(), Identities: ids, Expected: expected}
	if routedPrivateWriteV4(inputW, request) != nil || !read("locked\n") {
		return ErrUnavailable
	}
	if err := prepare(ctx); err != nil {
		return err
	}
	if _, err := io.WriteString(inputW, "verify\n"); err != nil || !read("verified\n") {
		return ErrUnavailable
	}
	stillAlive := func() error {
		probe := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}} // #nosec G115 -- pidfd is a Linux descriptor returned as a C int.
		if n, err := unix.Poll(probe, 0); err != nil || n != 0 || ctx.Err() != nil {
			return ErrUnavailable
		}
		return nil
	}
	if err := stillAlive(); err != nil {
		return err
	}
	if err := publish(ctx, stillAlive); err != nil {
		return err
	}
	if _, err := io.WriteString(inputW, "release\n"); err != nil {
		return ErrUnavailable
	}
	_ = inputW.Close()
	if _, err := output.ReadByte(); err != io.EOF {
		return ErrUnavailable
	}
	err = cmd.Wait()
	waited = true
	if err != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

func activationChildV1(ctx context.Context, role string, uid, gid, group uint32) (*exec.Cmd, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 ||
		uid == 0 || gid == 0 || group == 0 || (role != RoutedActivationSourceRoleV1 && role != RoutedActivationPreparedRoleV1) {
		return nil, ErrIdentity
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/setpriv") != nil {
		return nil, ErrIdentity
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", // #nosec G204 -- Fixed child roles, trusted executable and validated numeric account IDs.
		"--reuid="+strconv.FormatUint(uint64(uid), 10),
		"--regid="+strconv.FormatUint(uint64(gid), 10),
		"--groups="+strconv.FormatUint(uint64(group), 10),
		"--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", self, role)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	return cmd, nil
}
