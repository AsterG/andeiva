//go:build linux && andeiva_native_dhcp_diagnostics

package previewruntime

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

type routedDHCPServerMountUnreadableErrorV1 struct{}

func (routedDHCPServerMountUnreadableErrorV1) Error() string { panic("must not render cause") }

func TestRoutedDHCPServerMountDiagnosticFrameV1(t *testing.T) {
	for _, tt := range []struct {
		stage, wantStage, wantErrno string
		cause                       error
	}{
		{"tmpfs_config", "tmpfs_config", "EPERM", &os.PathError{Op: "secret-op", Path: "/secret-lease", Err: unix.EPERM}},
		{"bind_remount", "bind_remount", "EACCES", errors.Join(errors.New("secret-config"), unix.EACCES)},
		{"config_create", "config_create", "EEXIST", unix.EEXIST},
		{"directory_identity", "directory_identity", "unknown", nil},
		{strings.Repeat("secret\nstage", 1024), "unknown", "unknown", errors.New("secret\nconfig")},
		{"bind", "bind", "unknown", unix.Errno(9999)},
		{"bind", "bind", "unknown", routedDHCPServerMountUnreadableErrorV1{}},
	} {
		frame := routedDHCPServerMountDiagnosticFrameV1(tt.stage, tt.cause)
		want := "ANDEIVA_DHCP_SERVER_MOUNT_FAILURE stage=" + tt.wantStage + " errno=" + tt.wantErrno + "\n"
		if frame != want || len(frame) > 96 || strings.Count(frame, "\n") != 1 || strings.Contains(frame, "secret") {
			t.Fatalf("unexpected fixed frame: %q", frame)
		}
	}
}

type routedDHCPServerMountFailedWriterV1 struct{ calls int }

func (w *routedDHCPServerMountFailedWriterV1) Write([]byte) (int, error) {
	w.calls++
	return 0, unix.EIO
}

func TestRoutedDHCPServerMountDiagnosticFailedWriteV1(t *testing.T) {
	var once sync.Once
	var output routedDHCPServerMountFailedWriterV1
	for range 3 {
		routedDHCPServerMountDiagnosticEmitV1(&once, &output, "bind", unix.EPERM)
	}
	if output.calls != 1 {
		t.Fatal("failed diagnostic write must not trigger retries")
	}
}

func TestRoutedDHCPServerMountDiagnosticOnceV1(t *testing.T) {
	var once sync.Once
	var output bytes.Buffer
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() { routedDHCPServerMountDiagnosticEmitV1(&once, &output, "propagation", unix.EPERM) })
	}
	workers.Wait()
	if output.String() != "ANDEIVA_DHCP_SERVER_MOUNT_FAILURE stage=propagation errno=EPERM\n" {
		t.Fatal("first failure must be one bounded frame per process")
	}
	for _, result := range []error{nil, ErrIdentity, ErrUnavailable} {
		if got := routedDHCPServerMountFailureV1("bind", unix.EBADF, result); got != result {
			t.Fatal("diagnostic build changed public error")
		}
	}
}
