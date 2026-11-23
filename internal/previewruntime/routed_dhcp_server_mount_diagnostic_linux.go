//go:build linux && andeiva_native_dhcp_diagnostics

package previewruntime

import (
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var routedDHCPServerMountDiagnosticOnceV1 sync.Once

// The opt-in lab binary reports only the first failure in each role process.
// Neither arbitrary error text nor filesystem/configuration contents are logged.
func routedDHCPServerMountFailureV1(stage string, cause, result error) error {
	routedDHCPServerMountDiagnosticEmitV1(&routedDHCPServerMountDiagnosticOnceV1, os.Stderr, stage, cause)
	return result
}

func routedDHCPServerMountDiagnosticEmitV1(once *sync.Once, output io.Writer, stage string, cause error) {
	once.Do(func() {
		if _, err := io.WriteString(output, routedDHCPServerMountDiagnosticFrameV1(stage, cause)); err != nil {
			return // A failed lab log write must not change cleanup or public errors.
		}
	})
}

func routedDHCPServerMountDiagnosticFrameV1(stage string, cause error) string {
	switch stage {
	case "propagation", "tmpfs_run", "tmpfs_var_lib", "tmpfs_config", "config_create", "config_close",
		"directory_mkdir", "directory_open", "directory_chown", "directory_chmod", "directory_identity",
		"bind", "bind_remount", "bind_identity", "move_mount":
	default:
		stage = "unknown"
	}
	code := "unknown"
	for _, candidate := range []struct {
		err  error
		name string
	}{
		{unix.EPERM, "EPERM"}, {unix.EACCES, "EACCES"}, {unix.EINVAL, "EINVAL"}, {unix.ENOENT, "ENOENT"},
		{unix.EEXIST, "EEXIST"}, {unix.ENOTDIR, "ENOTDIR"}, {unix.ELOOP, "ELOOP"}, {unix.EROFS, "EROFS"},
		{unix.ENOSPC, "ENOSPC"}, {unix.ENOMEM, "ENOMEM"}, {unix.EBUSY, "EBUSY"}, {unix.EBADF, "EBADF"},
		{unix.EMFILE, "EMFILE"}, {unix.ENFILE, "ENFILE"}, {unix.EIO, "EIO"}, {unix.EINTR, "EINTR"},
	} {
		if errors.Is(cause, candidate.err) {
			code = candidate.name
			break
		}
	}
	return "ANDEIVA_DHCP_SERVER_MOUNT_FAILURE stage=" + stage + " errno=" + code + "\n"
}
