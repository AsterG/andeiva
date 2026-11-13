//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const routedDeathRole = "ANDEIVA_TEST_ROUTED_PARENT_DEATH_ROLE"

// This exercises the builder's process attributes with a test executable, not
// nft, namespace mutation, or reversal of a batch already accepted by the kernel.
func TestRoutedKernelParentDeathV3(t *testing.T) {
	switch os.Getenv(routedDeathRole) {
	case "driver":
		routedDeathDriver(t)
	case "parent":
		routedDeathParent(t)
	case "child":
		ready := os.NewFile(3, "child-ready")
		if ready == nil {
			t.Fatal("missing readiness pipe")
		}
		if _, err := ready.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		_ = ready.Close()
		// No parent-owned pipe controls this lifetime: EOF must not make the
		// mutant without Pdeathsig pass by exiting cooperatively.
		time.Sleep(30 * time.Second)
	default:
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := routedDeathCommand(t, ctx, "driver")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("parent-death subprocess failed: %v\n%s", err, output)
		}
	}
}

func routedDeathCommand(t *testing.T, ctx context.Context, role string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRoutedKernelParentDeathV3$", "-test.count=1", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), routedDeathRole+"="+role)
	return cmd
}

func routedDeathUnix(t *testing.T, file *os.File) *net.UnixConn {
	t.Helper()
	c, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		t.Fatal("control descriptor is not Unix")
	}
	return u
}

func routedDeathExited(fd int, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false, nil
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int((remaining+time.Millisecond-1)/time.Millisecond))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n == 0 {
			return false, err
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			return false, errors.New("unexpected pidfd event")
		}
		return true, nil
	}
}

func routedDeathKill(fd int) error {
	err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func routedDeathDriver(t *testing.T) {
	// Subreaping is confined to this reexecuted driver, never the package's
	// test runner. It lets us reap the orphan child even under a non-reaping PID1.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	control := routedDeathUnix(t, os.NewFile(uintptr(fds[0]), "driver-control"))
	defer control.Close()
	parentControl := os.NewFile(uintptr(fds[1]), "parent-control")
	defer parentControl.Close()
	parent := routedDeathCommand(t, context.Background(), "parent")
	parent.ExtraFiles = []*os.File{parentControl}
	parent.Stdout, parent.Stderr = os.Stderr, os.Stderr
	if err = parent.Start(); err != nil {
		t.Fatal(err)
	}
	_ = parentControl.Close()
	// This direct child cannot have its PID reused before we Wait it.
	parentFD, err := unix.PidfdOpen(parent.Process.Pid, 0)
	if err != nil {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatal(err)
	}
	childFD := -1
	defer func() {
		if err := routedDeathKill(parentFD); err != nil {
			t.Error(err)
		}
		if exited, err := routedDeathExited(parentFD, 2*time.Second); err != nil || !exited {
			t.Errorf("parent cleanup failed: exited=%v err=%v", exited, err)
		} else {
			_ = parent.Wait()
		}
		_ = unix.Close(parentFD)
		if childFD >= 0 {
			if err := routedDeathKill(childFD); err != nil {
				t.Error(err)
			}
			if exited, err := routedDeathExited(childFD, 2*time.Second); err != nil || !exited {
				t.Errorf("child cleanup failed: exited=%v err=%v", exited, err)
			} else if err = unix.Waitid(unix.P_PIDFD, childFD, &unix.Siginfo{}, unix.WEXITED, nil); err != nil {
				t.Errorf("orphan was not reaped: %v", err)
			}
			_ = unix.Close(childFD)
		}
	}()
	if err = control.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	data, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(4))
	n, on, flags, _, err := control.ReadMsgUnix(data, oob)
	if err != nil || n != 1 || data[0] != 1 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		t.Fatalf("pidfd handoff failed: %v", err)
	}
	messages, err := unix.ParseSocketControlMessage(oob[:on])
	if err != nil || len(messages) != 1 {
		t.Fatal("invalid pidfd control message", err)
	}
	rights, err := unix.ParseUnixRights(&messages[0])
	if err != nil || len(rights) != 1 {
		for _, fd := range rights {
			_ = unix.Close(fd)
		}
		t.Fatal("invalid pidfd rights", err)
	}
	childFD = rights[0]
	unix.CloseOnExec(childFD)
	if _, err = io.ReadFull(control, data); err != nil || data[0] != 2 {
		t.Fatal("child readiness missing", err)
	}
	if exited, err := routedDeathExited(childFD, time.Millisecond); err != nil || exited {
		t.Fatal("child exited before its parent", err)
	}
	if err = routedDeathKill(parentFD); err != nil {
		t.Fatal(err)
	}
	if exited, err := routedDeathExited(childFD, 3*time.Second); err != nil || !exited {
		t.Fatalf("builder child survived parent death: exited=%v err=%v", exited, err)
	}
}

func routedDeathParent(t *testing.T) {
	// Linux ties Pdeathsig to the creating thread, whose lifetime must encompass
	// the child. This matches the production kernel executor's thread guard.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	control := routedDeathUnix(t, os.NewFile(3, "parent-control"))
	defer control.Close()
	if err := control.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ready, signal, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer signal.Close()
	builder, err := routedKernelCommandV3(context.Background(), "apply", 0)
	if err != nil {
		t.Fatal(err)
	}
	child := routedDeathCommand(t, context.Background(), "child")
	if builder.SysProcAttr != nil {
		attributes := *builder.SysProcAttr
		child.SysProcAttr = &attributes
	}
	child.ExtraFiles = []*os.File{signal}
	child.Stdout, child.Stderr = io.Discard, os.Stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	_ = signal.Close()
	// Parent owns the unreaped child, so acquisition cannot target a reused PID.
	fd, err := unix.PidfdOpen(child.Process.Pid, 0)
	if err != nil {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal(err)
	}
	defer unix.Close(fd)
	defer func() {
		_ = routedDeathKill(fd)
		_ = child.Wait()
	}()
	if _, _, err = control.WriteMsgUnix([]byte{1}, unix.UnixRights(fd), nil); err != nil {
		t.Fatal(err)
	}
	if err = ready.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err = io.ReadFull(ready, data[:]); err != nil || data[0] != 1 {
		t.Fatal("child did not initialize", err)
	}
	if _, err = control.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	// Stay alive on the creating OS thread until the driver kills this process.
	_, _ = control.Read(data[:])
}
