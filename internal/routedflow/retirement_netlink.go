package routedflow

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
)

const ctDelete = 0x102
const retirementRequestSize = 88

func appendAttribute(dst []byte, kind uint16, value []byte) []byte {
	size := len(value) + 4
	if size < 4 || size > math.MaxUint16 {
		return nil
	}
	start := len(dst)
	dst = append(dst, make([]byte, aligned(size))...)
	binary.NativeEndian.PutUint16(dst[start:], uint16(size))
	binary.NativeEndian.PutUint16(dst[start+2:], kind)
	copy(dst[start+4:], value)
	return dst
}

func retireRequest(sequence, port uint32, e retirementEntry) ([]byte, error) {
	original := e.original
	if sequence == 0 || port == 0 || e.id == 0 || !original.Source.Address.Is4() ||
		!original.Destination.Address.Is4() || original.Source.Port == 0 || original.Destination.Port == 0 {
		return nil, ErrObservation
	}
	var number byte
	switch original.Protocol {
	case "tcp":
		number = 6
	case "udp":
		number = 17
	default:
		return nil, ErrObservation
	}
	src, dst := original.Source.Address.As4(), original.Destination.Address.As4()
	ip := appendAttribute(nil, 1, src[:])
	ip = appendAttribute(ip, 2, dst[:])
	proto := appendAttribute(nil, 1, []byte{number})
	proto = appendAttribute(proto, 2, binary.BigEndian.AppendUint16(nil, original.Source.Port))
	proto = appendAttribute(proto, 3, binary.BigEndian.AppendUint16(nil, original.Destination.Port))
	tuple := appendAttribute(nil, nestedFlag|1, ip)
	tuple = appendAttribute(tuple, nestedFlag|2, proto)

	req := make([]byte, 20)
	req[16] = 2                                     // AF_INET, nfnetlink v0.
	req = appendAttribute(req, nestedFlag|1, tuple) // CTA_TUPLE_ORIG, required for point deletion.
	req = appendAttribute(req, 12, binary.BigEndian.AppendUint32(nil, e.id))
	req = appendAttribute(req, 18, binary.BigEndian.AppendUint16(nil, e.zone))
	if len(req) != retirementRequestSize {
		return nil, ErrObservation
	}
	binary.NativeEndian.PutUint32(req, retirementRequestSize)
	binary.NativeEndian.PutUint16(req[4:], ctDelete)
	binary.NativeEndian.PutUint16(req[6:], 0x5) // Request and ACK. No dump, filter or flush.
	binary.NativeEndian.PutUint32(req[8:], sequence)
	binary.NativeEndian.PutUint32(req[12:], port)
	return req, nil
}

func retireEntry(ctx context.Context, t transport, sequence, port uint32, e retirementEntry) error {
	req, err := retireRequest(sequence, port, e)
	if err != nil {
		return err
	}
	if err = t.send(ctx, req); err != nil {
		return err
	}
	reply, err := t.receive(ctx)
	if err != nil {
		return err
	}
	data := reply.data
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if reply.peerPort != 0 || reply.peerGroups != 0 || reply.truncated || len(data) < 36 ||
		int64(binary.NativeEndian.Uint32(data)) != int64(len(data)) || binary.NativeEndian.Uint16(data[4:]) != 2 ||
		binary.NativeEndian.Uint16(data[6:])&^uint16(0x100) != 0 ||
		binary.NativeEndian.Uint32(data[8:]) != sequence || binary.NativeEndian.Uint32(data[12:]) != port ||
		!bytes.Equal(data[20:36], req[:16]) {
		return ErrObservation
	}
	code := binary.NativeEndian.Uint32(data[16:])
	if code != 0 {
		return kernelError(code)
	}
	if len(data) != 36 {
		return ErrObservation
	}
	return nil
}
