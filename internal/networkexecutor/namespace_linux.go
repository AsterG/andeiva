package networkexecutor

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var owners = struct {
	sync.Mutex
	ids map[uint64]bool
}{ids: map[uint64]bool{}}

// New duplicates a trusted open namespace descriptor; no caller path is opened.
// The privileged supervisor must start in the host namespace, own this lab
// namespace exclusively and retain its recovery lifetime until Restore finishes.
// Neither HTTP handlers nor untrusted IPC may construct this capability.
func New(lifetime context.Context, namespace *os.File) (*Executor, error) {
	if lifetime == nil || namespace == nil || os.Geteuid() != 0 {
		return nil, ErrScope
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	host, err := os.Open("/proc/1/ns/net")
	if err != nil {
		return nil, ErrScope
	}
	defer host.Close()
	return NewWithHost(lifetime, namespace, host)
}

// NewWithHost accepts a host namespace capability opened by the trusted service
// manager before privilege restriction. That provenance cannot be inferred from
// an inode: callers must never accept this descriptor from HTTP or untrusted IPC.
// Both caller descriptors are duplicated; closing them does not revoke the pins.
// The host must equal this supervisor's current network namespace, and the target
// must be distinct. No additional privilege or caller-controlled path is needed.
func NewWithHost(lifetime context.Context, namespace, host *os.File) (*Executor, error) {
	if lifetime == nil || namespace == nil || host == nil || os.Geteuid() != 0 {
		return nil, ErrScope
	}
	if err := lifetime.Err(); err != nil {
		return nil, err
	}
	pin, id, err := pinNamespace(namespace)
	if err != nil {
		return nil, err
	}
	ok := false
	var hostPin *os.File
	defer func() {
		if !ok {
			_ = pin.Close()
			if hostPin != nil {
				_ = hostPin.Close()
			}
		}
	}()
	var hostID uint64
	hostPin, hostID, err = pinNamespace(host)
	if err != nil {
		return nil, err
	}
	self, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, ErrScope
	}
	selfID, err := namespaceID(int(self.Fd()))
	_ = self.Close()
	if err != nil || !validNamespaceBinding(id, hostID, selfID) {
		return nil, ErrScope
	}
	for _, path := range []string{"/usr/bin/nsenter", "/usr/bin/ip"} {
		if !trustedExecutable(path) {
			return nil, ErrScope
		}
	}
	owners.Lock()
	if owners.ids[id] {
		owners.Unlock()
		return nil, ErrBusy
	}
	owners.ids[id] = true
	owners.Unlock()
	e := &Executor{lifetime: lifetime}
	e.release = func() error {
		err := errors.Join(pin.Close(), hostPin.Close())
		owners.Lock()
		delete(owners.ids, id)
		owners.Unlock()
		return err
	}
	e.run = func(ctx context.Context, op operation) ([]byte, error) {
		current, err := namespaceID(int(pin.Fd()))
		if err != nil || current != id {
			return nil, ErrScope
		}
		anchor, err := namespaceID(int(hostPin.Fd()))
		if err != nil || anchor != hostID || current == anchor {
			return nil, ErrScope
		}
		if !trustedExecutable("/usr/bin/nsenter") || !trustedExecutable("/usr/bin/ip") {
			return nil, ErrScope
		}
		cmd, err := namespaceCommand(ctx, pin, op)
		if err != nil {
			return nil, err
		}
		output := &limitedBuffer{}
		stderr := &limitedBuffer{}
		cmd.Stdout = output
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, ErrCommand
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if output.exceeded || stderr.exceeded {
			return nil, ErrCommand
		}
		return output.data, nil
	}
	ok = true
	return e, nil
}

func validNamespaceBinding(target, host, self uint64) bool {
	return target != 0 && host != 0 && self == host && target != host
}

func pinNamespace(source *os.File) (*os.File, uint64, error) {
	if source == nil {
		return nil, 0, ErrScope
	}
	fd, err := unix.FcntlInt(source.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, 0, ErrScope
	}
	pin := os.NewFile(uintptr(fd), "andeiva-network-namespace")
	id, err := namespaceID(fd)
	if err != nil {
		_ = pin.Close()
		return nil, 0, err
	}
	return pin, id, nil
}

// namespaceCommand only constructs the allowlisted invocation. The owner checks
// the namespace pin and trusted binaries immediately before constructing it.
func namespaceCommand(ctx context.Context, pin *os.File, op operation) (*exec.Cmd, error) {
	args, err := arguments(op)
	if err != nil || pin == nil {
		return nil, ErrScope
	}
	argv := append([]string{"--net=/proc/self/fd/3", "--", "/usr/bin/ip"}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", argv...) // #nosec G204 -- Fixed executable, private typed operation, pinned non-host namespace FD.
	cmd.ExtraFiles = []*os.File{pin}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}
func namespaceID(fd int) (uint64, error) {
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || unix.Fstat(fd, &st) != nil {
		return 0, ErrScope
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return 0, ErrScope
	}
	return st.Ino, nil
}
func trustedExecutable(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		return false
	}
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		if dir == "/" {
			return true
		}
	}
}

type limitedBuffer struct {
	data     []byte
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > maxOutput-len(b.data) {
		b.exceeded = true
		return 0, io.ErrShortWrite
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
