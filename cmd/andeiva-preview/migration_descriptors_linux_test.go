//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/previewruntime"
	"golang.org/x/sys/unix"
)

var migrationWorkerExecutable = flag.String("andeiva-preview-executable", "", "real Linux executable for the migration descriptor test")

func TestMigrationWorkerExecutableDescriptors(t *testing.T) {
	if *migrationWorkerExecutable == "" {
		t.Skip("requires a separately built andeiva-preview executable")
	}
	if os.Geteuid() != 0 {
		t.Fatal("migration worker control pipes must be root-owned")
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	_, scope, found := strings.Cut(strings.TrimSpace(string(cgroup)), "0::")
	if !found || !strings.HasPrefix(scope, "/") {
		t.Fatal("requires a cgroup v2 CPU controller")
	}
	if _, err = os.Stat(filepath.Join("/sys/fs/cgroup", scope, "cpu.max")); err != nil {
		t.Fatalf("CPU quota file must exist for the regression to be meaningful: %v", err)
	}

	for _, role := range []string{previewruntime.RoutedMigrationInspectRoleV3, previewruntime.RoutedMigrationPrepareRoleV3, previewruntime.RoutedActivationSourceRoleV1, previewruntime.RoutedActivationPreparedRoleV1} {
		t.Run(role, func(t *testing.T) {
			t.Run("protocol-descriptors", func(t *testing.T) { checkMigrationWorkerExecutable(t, role, false) })
			t.Run("unexpected-descriptor", func(t *testing.T) { checkMigrationWorkerExecutable(t, role, true) })
		})
	}
}

func checkMigrationWorkerExecutable(t *testing.T, role string, unexpected bool) {
	input, control := migrationTestPipe(t)
	_, output := migrationTestPipe(t)
	gateway, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, *migrationWorkerExecutable, role)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.Stdin, cmd.Stdout = input, output
	if role == previewruntime.RoutedActivationSourceRoleV1 || role == previewruntime.RoutedActivationPreparedRoleV1 {
		gateway = nil
	} else {
		cmd.ExtraFiles = []*os.File{gateway}
	}
	if unexpected {
		extra, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer extra.Close()
		cmd.ExtraFiles = append(cmd.ExtraFiles, extra)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan struct{})
	var exit error
	go func() {
		exit = cmd.Wait()
		close(waited)
	}()
	defer func() {
		cancel()
		<-waited
	}()

	if !unexpected {
		// The worker sets O_NONBLOCK only after its strict descriptor check.
		// Keep the control pipe open without sending a request.
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			flags, err := unix.FcntlInt(input.Fd(), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			if flags&unix.O_NONBLOCK != 0 {
				break
			}
			select {
			case <-waited:
				t.Fatalf("worker exited before reading the control pipe: %v", exit)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-ticker.C:
			}
		}
		assertMigrationWorkerDescriptors(t, cmd.Process.Pid, gateway)
		if err := control.Close(); err != nil {
			t.Fatal(err)
		}
	}

	<-waited
	var status *exec.ExitError
	if !errors.As(exit, &status) || status.ExitCode() != 1 {
		t.Fatalf("worker must reject the incomplete request or unexpected descriptor: %v", exit)
	}
	if unexpected {
		flags, err := unix.FcntlInt(input.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK != 0 {
			t.Fatalf("worker reached the request pipe with an unexpected descriptor: flags=%#x, err=%v", flags, err)
		}
	}
}

func migrationTestPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	read := os.NewFile(uintptr(fds[0]), "migration-test-input")
	write := os.NewFile(uintptr(fds[1]), "migration-test-output")
	t.Cleanup(func() {
		_ = read.Close()
		_ = write.Close()
	})
	return read, write
}

func assertMigrationWorkerDescriptors(t *testing.T, pid int, gateway *os.File) {
	t.Helper()
	path := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	fds, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	var namespace string
	if gateway != nil {
		namespace, err = os.Readlink(filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(gateway.Fd()), 10)))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(path, fd.Name()))
		if err != nil {
			t.Fatal(err)
		}
		switch fd.Name() {
		case "0", "1", "2":
		case "3":
			if gateway != nil {
				if target != namespace {
					t.Fatalf("unexpected namespace descriptor: %s", target)
				}
				continue
			}
			fallthrough
		default:
			if target != "anon_inode:[eventpoll]" && target != "anon_inode:[eventfd]" {
				t.Fatalf("unexpected worker descriptor %s: %s", fd.Name(), target)
			}
		}
	}
}
