//go:build linux

package routedflow

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Collect sends only CT_GET|DUMP to the current namespace. The trusted launcher
// must prepare the conntrack netlink component; this collector never loads it.
// A complete netlink dump is not an atomic snapshot during concurrent traffic.
func Collect(parent context.Context) (Snapshot, error) {
	if parent == nil {
		return Snapshot{}, ErrObservation
	}
	ctx, cancel := context.WithTimeout(parent, DumpTimeout)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	socket, sequence, port, e := openConntrackSocket()
	if e != nil {
		return Snapshot{}, e
	}
	defer unix.Close(socket.fd)
	return collect(ctx, socket, sequence, port)
}

func openConntrackSocket() (_ *netlinkSocket, _ uint32, _ uint32, result error) {
	info, e := os.Stat("/sys/module/nf_conntrack_netlink")
	if e != nil || !info.IsDir() {
		return nil, 0, 0, ErrUnavailable
	}
	fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if e != nil {
		return nil, 0, 0, socketError(e)
	}
	defer func() {
		if result != nil {
			_ = unix.Close(fd)
		}
	}()
	if e = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return nil, 0, 0, socketError(e)
	}
	address, e := unix.Getsockname(fd)
	if e != nil {
		return nil, 0, 0, socketError(e)
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Family != unix.AF_NETLINK || local.Pid == 0 || local.Groups != 0 {
		return nil, 0, 0, ErrObservation
	}
	var nonce [4]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, 0, 0, ErrTransport
	}
	sequence := binary.NativeEndian.Uint32(nonce[:])
	if sequence == 0 || sequence > math.MaxUint32-MaxRetirements-1 {
		sequence = 1
	}
	return &netlinkSocket{fd: fd, buffer: make([]byte, MaxDatagram)}, sequence, local.Pid, nil
}

// Retire runs after the authenticated helper switches to the verified target
// rules in its exclusively owned network namespace. The same call owns the
// entire budget, including both bounded dumps and all point deletions.
func (p *Retirement) Retire(parent context.Context) (RetirementResult, error) {
	if p == nil || parent == nil || parent.Err() != nil || p.operation == "" || !p.used.CompareAndSwap(false, true) {
		return RetirementResult{}, ErrObservation
	}
	result := RetirementResult{Operation: p.operation}
	ctx, cancel := context.WithTimeout(parent, RetirementTimeout)
	defer cancel()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ns, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return result, ErrPermission
	}
	defer unix.Close(ns)
	var current unix.Stat_t
	var filesystem unix.Statfs_t
	kind, err := unix.IoctlRetInt(ns, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET ||
		unix.Fstatfs(ns, &filesystem) != nil || filesystem.Type != unix.NSFS_MAGIC ||
		unix.Fstat(ns, &current) != nil || current.Ino != p.gateway || current.Ino == p.host {
		return result, ErrPermission
	}
	socket, sequence, port, err := openConntrackSocket()
	if err != nil {
		return result, err
	}
	defer unix.Close(socket.fd)
	return p.run(ctx, socket, sequence, port)
}

type netlinkSocket struct {
	fd     int
	buffer []byte
}

func (s *netlinkSocket) wait(ctx context.Context, events int16) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		descriptor := s.fd
		if descriptor < 0 || descriptor > math.MaxInt32 {
			return ErrTransport
		}
		fds := []unix.PollFd{{Fd: int32(descriptor), Events: events}}
		_, e := unix.Poll(fds, 50) // cancellation/deadline checked at most every 50ms.
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return socketError(e)
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return ErrInterrupted
		}
		if fds[0].Revents&events != 0 {
			return nil
		}
	}
}
func (s *netlinkSocket) send(ctx context.Context, b []byte) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		e := unix.Sendto(s.fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EWOULDBLOCK) {
			if e = s.wait(ctx, unix.POLLOUT); e != nil {
				return e
			}
			continue
		}
		return socketError(e)
	}
}
func (s *netlinkSocket) receive(ctx context.Context) (datagram, error) {
	for {
		if e := s.wait(ctx, unix.POLLIN); e != nil {
			return datagram{}, e
		}
		n, oob, flags, from, e := unix.Recvmsg(s.fd, s.buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(e, unix.EINTR) || errors.Is(e, unix.EAGAIN) || errors.Is(e, unix.EWOULDBLOCK) {
			continue
		}
		if e != nil {
			return datagram{}, socketError(e)
		}
		peer, ok := from.(*unix.SockaddrNetlink)
		if !ok || peer.Family != unix.AF_NETLINK || n <= 0 || n > len(s.buffer) {
			return datagram{}, ErrObservation
		}
		return datagram{data: s.buffer[:n], peerPort: peer.Pid, peerGroups: peer.Groups, truncated: flags != 0 || oob != 0}, nil
	}
}
func socketError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, unix.EPERM), errors.Is(e, unix.EACCES):
		return ErrPermission
	case errors.Is(e, unix.ENOENT), errors.Is(e, unix.EOPNOTSUPP), errors.Is(e, unix.EPROTONOSUPPORT), errors.Is(e, unix.EAFNOSUPPORT):
		return ErrUnavailable
	case errors.Is(e, unix.ENOBUFS):
		return ErrInterrupted
	default:
		return ErrTransport
	}
}
