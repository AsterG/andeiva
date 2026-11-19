//go:build linux

package dhcpsockets

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/unix"
)

// CapturePacket reads AF_PACKET inventory in the caller's network namespace.
func CapturePacket(ctx context.Context) ([]PacketSocket, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrObservation
	}
	deadline := observationDeadline(ctx)
	q := make([]byte, 36)
	binary.NativeEndian.PutUint32(q[:4], 36)
	binary.NativeEndian.PutUint16(q[4:6], diagMessage)
	binary.NativeEndian.PutUint16(q[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(q[8:12], 1)
	q[16] = unix.AF_PACKET
	binary.NativeEndian.PutUint32(q[24:28], 1) // PACKET_SHOW_INFO also requests UID.
	for i := 28; i < 36; i++ {
		q[i] = 255
	}
	return captureDump(ctx, deadline, q, consumePackets, uniquePackets)
}
