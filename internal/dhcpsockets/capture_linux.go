//go:build linux

package dhcpsockets

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"time"
)

// CaptureIPv4UDP reads unconnected IPv4 UDP socket creation metadata.
func CaptureIPv4UDP(ctx context.Context) ([]Socket, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrObservation
	}
	deadline := observationDeadline(ctx)
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
	return captureDump(ctx, deadline, q, consume, uniqueSockets)
}

func finishCapture(ctx context.Context, deadline time.Time, rows []Socket) ([]Socket, error) {
	return finishDump(ctx, deadline, rows, uniqueSockets)
}
