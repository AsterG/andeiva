package dhcpsockets

import "encoding/binary"

// PacketSocket is AF_PACKET inventory; packet_diag supplies no creation-cgroup.
// UID, cookie and inode do not prove a current descriptor holder or service.
type PacketSocket struct {
	Interface uint32
	Type      uint8
	Protocol  uint16
	Cookie    uint64
	Inode     uint32
	UID       uint32
	Flags     uint32
}

func decodePacket(raw []byte) (PacketSocket, error) {
	var s PacketSocket
	if len(raw) < 16 || len(raw) > maxDatagram || raw[0] != 17 || raw[1] == 0 {
		return s, ErrObservation
	}
	s.Type = raw[1]
	s.Protocol = binary.NativeEndian.Uint16(raw[2:4])
	s.Inode = binary.NativeEndian.Uint32(raw[4:8])
	s.Cookie = uint64(binary.NativeEndian.Uint32(raw[8:12])) | uint64(binary.NativeEndian.Uint32(raw[12:16]))<<32
	info, uid := false, false
	for p := 16; p < len(raw); {
		if len(raw)-p < 4 {
			return PacketSocket{}, ErrObservation
		}
		n := int(binary.NativeEndian.Uint16(raw[p : p+2]))
		kind := binary.NativeEndian.Uint16(raw[p+2 : p+4])
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(raw)-p {
			return PacketSocket{}, ErrObservation
		}
		switch kind {
		case 0:
			if info || n != 28 {
				return PacketSocket{}, ErrObservation
			}
			info = true
			s.Interface = binary.NativeEndian.Uint32(raw[p+4 : p+8])
			s.Flags = binary.NativeEndian.Uint32(raw[p+24 : p+28])
		case 5:
			if uid || n != 8 {
				return PacketSocket{}, ErrObservation
			}
			uid = true
			s.UID = binary.NativeEndian.Uint32(raw[p+4 : p+8])
		}
		p += aligned
	}
	if !info || !uid || s.Inode == 0 || s.Cookie == 0 || s.Cookie == ^uint64(0) {
		return PacketSocket{}, ErrObservation
	}
	return s, nil
}

func consumePackets(raw []byte, seq, port uint32) ([]PacketSocket, bool, error) {
	return consumeRecords(raw, seq, port, decodePacket)
}
func uniquePackets(rows []PacketSocket) error {
	inodes := map[uint32]bool{}
	cookies := map[uint64]bool{}
	for _, s := range rows {
		if s.Inode == 0 || s.Cookie == 0 || inodes[s.Inode] || cookies[s.Cookie] {
			return ErrObservation
		}
		inodes[s.Inode], cookies[s.Cookie] = true, true
	}
	return nil
}
