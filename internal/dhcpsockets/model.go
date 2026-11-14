package dhcpsockets

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrObservation = errors.New("ANDEIVA_DHCP_SOCKET_OBSERVATION_FAILED")

const (
	maxDatagram     = 64 << 10
	maxRows         = 64
	diagMessage     = 20
	cgroupAttribute = 21
)

// Socket records creation provenance, not the current descriptor holder.
type Socket struct {
	Address        netip.Addr `json:"address"`
	Port           uint16     `json:"port"`
	Interface      uint32     `json:"interface"`
	Cookie         uint64     `json:"cookie"`
	Inode          uint32     `json:"inode"`
	UID            uint32     `json:"uid"`
	CreationCgroup uint64     `json:"creation_cgroup"`
}

func decodeSocket(raw []byte) (Socket, error) {
	var s Socket
	if len(raw) < 72 || len(raw) > maxDatagram || raw[0] != 2 || raw[1] != 7 {
		return s, ErrObservation
	}
	// The capture requests unconnected, bound IPv4 UDP sockets only.
	if binary.BigEndian.Uint16(raw[6:8]) != 0 {
		return s, ErrObservation
	}
	for _, v := range raw[12:40] {
		if v != 0 {
			return s, ErrObservation
		}
	}
	s.Address = netip.AddrFrom4([4]byte(raw[8:12]))
	s.Port = binary.BigEndian.Uint16(raw[4:6])
	s.Interface = binary.NativeEndian.Uint32(raw[40:44])
	s.Cookie = uint64(binary.NativeEndian.Uint32(raw[44:48])) | uint64(binary.NativeEndian.Uint32(raw[48:52]))<<32
	s.UID = binary.NativeEndian.Uint32(raw[64:68])
	s.Inode = binary.NativeEndian.Uint32(raw[68:72])
	seen := false
	for p := 72; p < len(raw); {
		if len(raw)-p < 4 {
			return Socket{}, ErrObservation
		}
		n := int(binary.NativeEndian.Uint16(raw[p : p+2]))
		typ := binary.NativeEndian.Uint16(raw[p+2 : p+4])
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(raw)-p {
			return Socket{}, ErrObservation
		}
		if typ == cgroupAttribute {
			if seen || n != 12 {
				return Socket{}, ErrObservation
			}
			seen = true
			s.CreationCgroup = binary.NativeEndian.Uint64(raw[p+4 : p+12])
		}
		// Unknown kernel attributes are skipped structurally; they confer no proof.
		p += aligned
	}
	if !seen || s.CreationCgroup == 0 || s.Inode == 0 || s.Cookie == 0 || s.Cookie == ^uint64(0) {
		return Socket{}, ErrObservation
	}
	return s, nil
}

// consume validates each netlink envelope before decoding a bounded dump.
func consume(raw []byte, seq, port uint32) ([]Socket, bool, error) {
	return consumeRecords(raw, seq, port, decodeSocket)
}

func consumeRecords[T any](raw []byte, seq, port uint32, decode func([]byte) (T, error)) ([]T, bool, error) {
	if len(raw) == 0 || len(raw) > maxDatagram {
		return nil, false, ErrObservation
	}
	var result []T
	done := false
	for len(raw) > 0 {
		if len(raw) < 16 || done {
			return nil, false, ErrObservation
		}
		n := int(binary.NativeEndian.Uint32(raw[:4]))
		aligned := (n + 3) &^ 3
		if n < 16 || aligned > len(raw) || binary.NativeEndian.Uint32(raw[8:12]) != seq || binary.NativeEndian.Uint32(raw[12:16]) != port {
			return nil, false, ErrObservation
		}
		flags := binary.NativeEndian.Uint16(raw[6:8])
		if flags&0x10 != 0 {
			return nil, false, ErrObservation
		} // NLM_F_DUMP_INTR
		switch binary.NativeEndian.Uint16(raw[4:6]) {
		case 3: // NLMSG_DONE; require a successful dump status.
			if n != 20 || binary.NativeEndian.Uint32(raw[16:20]) != 0 {
				return nil, false, ErrObservation
			}
			done = true
		case diagMessage:
			if flags&2 == 0 {
				return nil, false, ErrObservation
			}
			s, err := decode(raw[16:n])
			if err != nil {
				return nil, false, err
			}
			result = append(result, s)
			if len(result) > maxRows {
				return nil, false, ErrObservation
			}
		default:
			return nil, false, ErrObservation
		}
		raw = raw[aligned:]
	}
	return result, done, nil
}

func uniqueSockets(rows []Socket) error {
	inodes := make(map[uint32]bool, len(rows))
	cookies := make(map[uint64]bool, len(rows))
	for _, row := range rows {
		if row.Inode == 0 || row.Cookie == 0 || row.Cookie == ^uint64(0) || row.CreationCgroup == 0 || inodes[row.Inode] || cookies[row.Cookie] {
			return ErrObservation
		}
		inodes[row.Inode], cookies[row.Cookie] = true, true
	}
	return nil
}
