//go:build linux

package dhcpsockets

import (
	"context"
	"encoding/binary"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

// CaptureIPv4UDP reads unconnected IPv4 UDP socket creation metadata.
// A kernel sender, successful complete dump, bounds and context are mandatory.
func CaptureIPv4UDP(ctx context.Context) ([]Socket, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrObservation
	}
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
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
	q := make([]byte, 72)
	binary.NativeEndian.PutUint32(q[:4], 72)
	binary.NativeEndian.PutUint16(q[4:6], diagMessage)
	binary.NativeEndian.PutUint16(q[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(q[8:12], 1)
	q[16], q[17] = unix.AF_INET, unix.IPPROTO_UDP
	binary.NativeEndian.PutUint32(q[20:24], 1<<7) // TCP_CLOSE / unconnected UDP
	for i := 64; i < 72; i++ {
		q[i] = 255
	} // INET_DIAG_NOCOOKIE
	if unix.Sendto(fd, q, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return nil, ErrObservation
	}
	buf := make([]byte, maxDatagram)
	var result []Socket
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
		rows, done, e := consume(buf[:n], 1, local.Pid)
		if e != nil {
			return nil, e
		}
		result = append(result, rows...)
		if len(result) > maxRows {
			return nil, ErrObservation
		}
		if done {
			return finishCapture(ctx, deadline, result)
		}
	}
	return nil, ErrObservation
}

// Completion rechecks the original budget after decoding and identity validation.
func finishCapture(ctx context.Context, deadline time.Time, rows []Socket) ([]Socket, error) {
	if err := uniqueSockets(rows); err != nil {
		return nil, err
	}
	if ctx == nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil, ErrObservation
	}
	return rows, nil
}
