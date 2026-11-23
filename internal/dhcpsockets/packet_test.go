package dhcpsockets

import (
	"encoding/binary"
	"testing"
)

func packetMessage() []byte {
	b := make([]byte, 52)
	b[0] = 17
	b[1] = 2
	binary.NativeEndian.PutUint16(b[2:4], 0x0800)
	binary.NativeEndian.PutUint32(b[4:8], 88)
	binary.NativeEndian.PutUint32(b[8:12], 77)
	binary.NativeEndian.PutUint16(b[16:18], 28)
	binary.NativeEndian.PutUint16(b[18:20], 0)
	binary.NativeEndian.PutUint32(b[20:24], 3)
	binary.NativeEndian.PutUint32(b[40:44], 1)
	binary.NativeEndian.PutUint16(b[44:46], 8)
	binary.NativeEndian.PutUint16(b[46:48], 5)
	binary.NativeEndian.PutUint32(b[48:52], 1000)
	return b
}
func TestPacketIdentityAndMissingAttribution(t *testing.T) {
	s, err := decodePacket(packetMessage())
	if err != nil || s.Interface != 3 || s.Type != 2 || s.Protocol != 0x0800 || s.Cookie != 77 || s.Inode != 88 || s.UID != 1000 || s.Flags != 1 {
		t.Fatal(s, err)
	}
	for name, change := range map[string]func([]byte) []byte{
		"short":               func(b []byte) []byte { return b[:15] },
		"missing_uid":         func(b []byte) []byte { return b[:44] },
		"duplicate_uid":       func(b []byte) []byte { return append(b, b[44:]...) },
		"duplicate_info":      func(b []byte) []byte { return append(b, b[16:44]...) },
		"malformed_attribute": func(b []byte) []byte { b[16] = 255; return b },
		"wrong_family":        func(b []byte) []byte { b[0] = 2; return b },
		"missing_info":        func(b []byte) []byte { return append(b[:16], b[44:]...) },
		"zero_inode":          func(b []byte) []byte { clear(b[4:8]); return b },
		"zero_cookie":         func(b []byte) []byte { clear(b[8:16]); return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePacket(change(packetMessage())); err == nil {
				t.Fatal("invalid packet identity accepted")
			}
		})
	}
}
func TestPacketUnboundAndAllProtocolEndpointsStayVisible(t *testing.T) {
	b := packetMessage()
	clear(b[20:24])
	binary.NativeEndian.PutUint16(b[2:4], 3)
	s, err := decodePacket(b)
	if err != nil || s.Interface != 0 || s.Protocol != 3 {
		t.Fatal("unbound/all-protocol resource was hidden", s, err)
	}
}
func TestPacketDumpValidatesEnvelopeAndDuplicates(t *testing.T) {
	body := packetMessage()
	b := make([]byte, 16+len(body))
	copy(b[16:], body)
	binary.NativeEndian.PutUint32(b[:4], 68)
	binary.NativeEndian.PutUint16(b[4:6], 20)
	binary.NativeEndian.PutUint16(b[6:8], 2)
	binary.NativeEndian.PutUint32(b[8:12], 1)
	binary.NativeEndian.PutUint32(b[12:16], 10)
	rows, done, err := consumePackets(b, 1, 10)
	if err != nil || done || len(rows) != 1 {
		t.Fatal(rows, done, err)
	}
	b[6] |= 16
	if _, _, err := consumePackets(b, 1, 10); err == nil {
		t.Fatal("interrupted packet dump accepted")
	}
	if uniquePackets([]PacketSocket{rows[0], rows[0]}) == nil {
		t.Fatal("duplicate packet identity accepted")
	}
}

func TestPacketRawAllProtocolProfileRemainsVisible(t *testing.T) {
	b := packetMessage()
	b[1] = 3
	binary.NativeEndian.PutUint16(b[2:4], 3)
	s, err := decodePacket(b)
	if err != nil || s.Type != 3 || s.Protocol != 3 || s.Interface != 3 {
		t.Fatal("RAW/ETH_P_ALL observation changed", s, err)
	}
}
