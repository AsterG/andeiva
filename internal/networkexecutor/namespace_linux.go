package networkexecutor

import (
	"context"
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
	fd, err := unix.FcntlInt(namespace.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, ErrScope
	}
	pin := os.NewFile(uintptr(fd), "andeiva-isolated-network")
	ok := false
	defer func() {
		if !ok {
			_ = pin.Close()
		}
	}()
	id, err := namespaceID(fd)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{"/proc/self/ns/net", "/proc/1/ns/net"} {
		host, err := os.Open(path)
		if err != nil {
			return nil, ErrScope
		}
		hostID, err := namespaceID(int(host.Fd()))
		_ = host.Close()
		if err != nil || hostID == id {
			return nil, ErrScope
		}
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
	e.release = func() error { err := pin.Close(); owners.Lock(); delete(owners.ids, id); owners.Unlock(); return err }
	e.run = func(ctx context.Context, op operation) ([]byte, error) {
		current, err := namespaceID(int(pin.Fd()))
		if err != nil || current != id {
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
