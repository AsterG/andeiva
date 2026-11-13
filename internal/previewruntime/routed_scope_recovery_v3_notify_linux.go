//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// This protocol is restricted to the fixed root service's system-manager socket.
// Unknown/partial manager state is retained; notifications never imply receipt.
type scopeRecoveryNotifyV3 struct{ fd int }

func openScopeRecoveryNotifyV3() (*scopeRecoveryNotifyV3, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv("NOTIFY_SOCKET") != "/run/systemd/notify" || safeParents("/run/systemd/notify") != nil {
		return nil, ErrIdentity
	}
	var st unix.Stat_t
	if unix.Lstat("/run/systemd/notify", &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != 0 || st.Gid != 0 {
		return nil, ErrIdentity
	}
	group, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || string(group) != "0::"+routedSupervisorCgroupV3+"\n" {
		return nil, ErrIdentity
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err = unix.Connect(fd, &unix.SockaddrUnix{Name: "/run/systemd/notify"}); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &scopeRecoveryNotifyV3{fd: fd}, nil
}
func scopeNotifyWaitV3(ctx context.Context, fd int, events int16) error {
	if fd < 0 || uint64(fd) > uint64(1<<31-1) {
		return ErrIdentity
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		n, err := unix.Poll(poll, 20)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if poll[0].Revents&unix.POLLNVAL != 0 {
				return ErrIdentity
			}
			return nil
		}
	}
}
func (n *scopeRecoveryNotifyV3) send(ctx context.Context, text string, fd int) error {
	var rights []byte
	if fd >= 0 {
		rights = unix.UnixRights(fd)
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count, err := unix.SendmsgN(n.fd, []byte(text), rights, nil, unix.MSG_NOSIGNAL|unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			if err = scopeNotifyWaitV3(ctx, n.fd, unix.POLLOUT); err != nil {
				return err
			}
			continue
		}
		if err != nil || count != len(text) {
			return errors.Join(err, ErrUnavailable)
		}
		return nil
	}
}
func (n *scopeRecoveryNotifyV3) barrier(ctx context.Context) error {
	var pipes [2]int
	if err := unix.Pipe2(pipes[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return err
	}
	defer unix.Close(pipes[0])
	err := n.send(ctx, "BARRIER=1", pipes[1])
	closeErr := unix.Close(pipes[1])
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	var one [1]byte
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		count, err := unix.Read(pipes[0], one[:])
		if err == nil && count == 0 {
			return ctx.Err()
		}
		if err == nil {
			return ErrIdentity
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return err
		}
		if err = scopeNotifyWaitV3(ctx, pipes[0], unix.POLLIN|unix.POLLHUP); err != nil {
			return err
		}
	}
}

func (r *RoutedScopeRecoveryV3) Store(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revalidateLocked(ctx) != nil {
		return ErrIdentity
	}
	n, err := openScopeRecoveryNotifyV3()
	if err != nil {
		return err
	}
	defer unix.Close(n.fd)
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	want, err := r.storedFactsLocked()
	if err != nil {
		return err
	}
	fds := make([]int, len(r.files))
	for i, f := range r.files {
		fds[i] = int(f.Fd())
	}
	if err = exchangeScopeRecoveryStoreV3(call, n, readScopeRecoveryStoreV3, want, fds, false); err != nil {
		return err
	}
	if r.revalidateLocked(call) != nil {
		return ErrIdentity
	}
	return nil
}

// DropStored is called only after verified L2 teardown and cgroup drainage.
// It releases manager duplicates, not local pins, and never issues a receipt.
func (r *RoutedScopeRecoveryV3) DropStored(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || ctx.Err() != nil {
		return ErrIdentity
	}
	n, err := openScopeRecoveryNotifyV3()
	if err != nil {
		return err
	}
	defer unix.Close(n.fd)
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	want, err := r.storedFactsLocked()
	if err != nil {
		return err
	}
	return exchangeScopeRecoveryStoreV3(call, n, readScopeRecoveryStoreV3, want, nil, true)
}
func (r *RoutedScopeRecoveryV3) storedFactsLocked() (map[string]scopeRecoveryStoredV3, error) {
	want := make(map[string]scopeRecoveryStoredV3, len(r.files))
	for i, f := range r.files {
		_, st, err := scopeRecoveryIdentityV3(f)
		if err != nil {
			return nil, ErrIdentity
		}
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil || flags < 0 || uint64(flags) > uint64(^uint32(0)) {
			return nil, ErrIdentity
		}
		want[scopeRecoveryNamesV3[i]] = scopeRecoveryStoredV3{Mode: st.Mode, Major: unix.Major(uint64(st.Dev)), Minor: unix.Minor(uint64(st.Dev)), Inode: st.Ino, Rmajor: unix.Major(uint64(st.Rdev)), Rminor: unix.Minor(uint64(st.Rdev)), Flags: uint32(flags) &^ 0x8000}
	}
	return want, nil
}

// The exchange cannot infer success from a barrier: only exact manager readback
// grants completion. Partial publication/removal never retries or undoes evidence.
type scopeRecoveryNotifierV3 interface {
	send(context.Context, string, int) error
	barrier(context.Context) error
}

func exchangeScopeRecoveryStoreV3(ctx context.Context, n scopeRecoveryNotifierV3, read func(context.Context) ([]byte, error), want map[string]scopeRecoveryStoredV3, fds []int, remove bool) error {
	if ctx == nil || ctx.Err() != nil || len(want) != len(scopeRecoveryNamesV3) || (!remove && len(fds) != len(scopeRecoveryNamesV3)) {
		return ErrIdentity
	}
	before, after := map[string]scopeRecoveryStoredV3(nil), want
	if remove {
		before, after = want, nil
	}
	raw, err := read(ctx)
	if err != nil || !scopeRecoveryStoreMatchesV3(raw, before) {
		return ErrIdentity
	}
	for i, name := range scopeRecoveryNamesV3 {
		message, fd := "FDSTOREREMOVE=1\nFDNAME="+name, -1
		if !remove {
			message = "FDSTORE=1\nFDPOLL=0\nFDNAME=" + name
			fd = fds[i]
			if fd < 0 {
				return ErrIdentity
			}
		}
		if err = n.send(ctx, message, fd); err != nil {
			return err
		}
	}
	if err = n.barrier(ctx); err != nil {
		return err
	}
	raw, err = read(ctx)
	if err != nil || !scopeRecoveryStoreMatchesV3(raw, after) || ctx.Err() != nil {
		return ErrIdentity
	}
	return nil
}
