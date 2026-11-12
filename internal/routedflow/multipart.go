package routedflow

import (
	"bytes"
	"encoding/binary"
)

const (
	headerSize          = 16
	ctNew               = 0x100
	ctGet               = 0x101
	flagMulti           = 2
	flagDumpInterrupted = 0x10
	flagFiltered        = 0x20
)

func dumpRequest(sequence, port uint32) []byte {
	request := make([]byte, 20)
	binary.NativeEndian.PutUint32(request, 20)
	binary.NativeEndian.PutUint16(request[4:], ctGet)
	binary.NativeEndian.PutUint16(request[6:], 0x301) // request | root | match; never CTRZERO, NEW or DELETE.
	binary.NativeEndian.PutUint32(request[8:], sequence)
	binary.NativeEndian.PutUint32(request[12:], port)
	request[16] = 2 // AF_INET; nfnetlink version and resource ID remain zero.
	return request
}

type flowKey struct {
	source, destination Endpoint
	protocol            string
	zone                uint16
}

func zoneValue(v *uint16) uint16 {
	if v == nil {
		return 0
	}
	return *v
}

type multipart struct {
	sequence, port                uint32
	totalBytes, messages, skipped int
	done                          bool
	failed                        error
	flows                         []Flow
	seen                          map[flowKey]bool
}

func newMultipart(sequence, port uint32) *multipart {
	return &multipart{sequence: sequence, port: port, flows: []Flow{}, seen: map[flowKey]bool{}}
}
func (d *multipart) consume(data []byte, peerPort, peerGroups uint32, truncated bool) error {
	if d.failed != nil {
		return d.failed
	}
	e := d.consumeDatagram(data, peerPort, peerGroups, truncated)
	if e != nil {
		d.failed = e
	}
	return e
}
func (d *multipart) consumeDatagram(data []byte, peerPort, peerGroups uint32, truncated bool) error {
	if truncated || d.done || d.sequence == 0 || d.port == 0 || peerPort != 0 || peerGroups != 0 || len(data) == 0 || len(data) > MaxDatagram {
		return ErrObservation
	}
	d.totalBytes += len(data)
	if d.totalBytes > MaxDumpBytes {
		return ErrLimit
	}
	for len(data) > 0 {
		if len(data) < headerSize {
			return ErrObservation
		}
		size := binary.NativeEndian.Uint32(data)
		if size < headerSize || size > MaxDatagram {
			return ErrObservation
		}
		n := int(size)
		if n > len(data) || aligned(n) > len(data) {
			return ErrObservation
		}
		kind := binary.NativeEndian.Uint16(data[4:])
		flags := binary.NativeEndian.Uint16(data[6:])
		if binary.NativeEndian.Uint32(data[8:]) != d.sequence || binary.NativeEndian.Uint32(data[12:]) != d.port {
			return ErrObservation
		}
		d.messages++
		if d.messages > MaxMessages {
			return ErrLimit
		}
		if flags&flagDumpInterrupted != 0 {
			return ErrInterrupted
		}
		payload := data[headerSize:n]
		data = data[aligned(n):]
		switch kind {
		case ctNew:
			if flags&flagMulti == 0 || flags&^uint16(flagMulti|flagFiltered) != 0 {
				return ErrObservation
			}
			f, inScope, e := decodeFlow(payload)
			if e != nil {
				return e
			}
			if !inScope {
				d.skipped++
				continue
			}
			zone := zoneValue(f.Zone)
			if f.Original.Zone != nil {
				zone = *f.Original.Zone
			}
			key := flowKey{source: f.Original.Source, destination: f.Original.Destination, protocol: f.Original.Protocol, zone: zone}
			if d.seen[key] {
				return ErrObservation
			}
			if len(d.flows) >= MaxFlows {
				return ErrLimit
			}
			d.seen[key] = true
			d.flows = append(d.flows, f)
		case 3: // NLMSG_DONE; no partial snapshot is returned before this terminator.
			if flags&flagMulti == 0 || flags&^uint16(flagMulti|flagFiltered) != 0 || len(data) != 0 || (len(payload) != 0 && len(payload) != 4) {
				return ErrObservation
			}
			if len(payload) == 4 {
				if code := binary.NativeEndian.Uint32(payload); code != 0 {
					return kernelError(code)
				}
			}
			d.done = true
		case 2: // NLMSG_ERROR must quote this exact read-only request.
			if flags != 0 || len(payload) != 24 || !bytes.Equal(payload[4:], dumpRequest(d.sequence, d.port)) {
				return ErrObservation
			}
			return kernelError(binary.NativeEndian.Uint32(payload))
		case 4:
			return ErrInterrupted // NLMSG_OVERRUN
		default:
			return ErrObservation
		}
	}
	return nil
}
func kernelError(code uint32) error {
	if code == 0 || code&0x80000000 == 0 {
		return ErrObservation
	} // unsolicited ACK or malformed positive errno.
	switch ^code + 1 {
	case 1, 13:
		return ErrPermission
	case 2, 95:
		return ErrUnavailable
	case 4, 105:
		return ErrInterrupted
	default:
		return ErrTransport
	}
}
