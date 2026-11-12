//go:build linux

package routedflow

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"os"

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
	info, e := os.Stat("/sys/module/nf_conntrack_netlink")
	if e != nil || !info.IsDir() {
		return Snapshot{}, ErrUnavailable
	}
	fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if e != nil {
		return Snapshot{}, socketError(e)
	}
	defer func() { _ = unix.Close(fd) }()
	if e = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return Snapshot{}, socketError(e)
	}
	address, e := unix.Getsockname(fd)
	if e != nil {
		return Snapshot{}, socketError(e)
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Family != unix.AF_NETLINK || local.Pid == 0 || local.Groups != 0 {
		return Snapshot{}, ErrObservation
	}
	var nonce [4]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return Snapshot{}, ErrTransport
	}
	sequence := binary.NativeEndian.Uint32(nonce[:])
	if sequence == 0 {
		sequence = 1
	}
	socket := &netlinkSocket{fd: fd, buffer: make([]byte, MaxDatagram)}
	return collect(ctx, socket, sequence, local.Pid)
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
