//go:build linux

package dhcpsockets

import (
	"context"
	"golang.org/x/sys/unix"
	"math"
	"time"
)

func observationDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return deadline
}

func captureDump[T any](ctx context.Context, deadline time.Time, request []byte, decode func([]byte, uint32, uint32) ([]T, bool, error), validate func([]T) error) ([]T, error) {
	fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if e != nil {
		return nil, ErrObservation
	}
	defer unix.Close(fd)
	if fd < 0 || fd > math.MaxInt32 {
		return nil, ErrObservation
	}
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, ErrObservation
	}
	sa, e := unix.Getsockname(fd)
	if e != nil {
		return nil, ErrObservation
	}
	local, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		return nil, ErrObservation
	}
	if unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, ErrObservation
	}
	buf := make([]byte, maxDatagram)
	var result []T
	for calls := 0; calls < 128; calls++ {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return nil, ErrObservation
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, e = unix.Poll(p, 10); e != nil && e != unix.EINTR {
			return nil, ErrObservation
		}
		if p[0].Revents == 0 {
			continue
		}
		n, _, flags, from, e := unix.Recvmsg(fd, buf, nil, unix.MSG_DONTWAIT)
		if e == unix.EAGAIN || e == unix.EINTR {
			continue
		}
		if e != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			return nil, ErrObservation
		}
		kernel, ok := from.(*unix.SockaddrNetlink)
		if !ok || kernel.Pid != 0 || kernel.Groups != 0 {
			return nil, ErrObservation
		}
		rows, done, e := decode(buf[:n], 1, local.Pid)
		if e != nil {
			return nil, e
		}
		result = append(result, rows...)
		if len(result) > maxRows {
			return nil, ErrObservation
		}
		if done {
			return finishDump(ctx, deadline, result, validate)
		}
	}
	return nil, ErrObservation
}

// Recheck the original budget after parsing and identity validation.
func finishDump[T any](ctx context.Context, deadline time.Time, rows []T, validate func([]T) error) ([]T, error) {
	if err := validate(rows); err != nil {
		return nil, err
	}
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil, ErrObservation
	}
	return rows, nil
}
