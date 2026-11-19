package dhcpsockets

import (
	"encoding/binary"
	"testing"
)

func socketMessage() []byte {
	b := make([]byte, 84)
	b[0], b[1] = 2, 7
	b[8], b[11] = 127, 1
	binary.BigEndian.PutUint16(b[4:6], 68)
	binary.NativeEndian.PutUint32(b[44:48], 77)
	binary.NativeEndian.PutUint32(b[68:72], 88)
	binary.NativeEndian.PutUint16(b[72:74], 12)
	binary.NativeEndian.PutUint16(b[74:76], 21)
	binary.NativeEndian.PutUint64(b[76:84], 99)
	return b
}

func TestValidatedCaptureAttributes(t *testing.T) {
	s, e := decodeSocket(socketMessage())
	if e != nil || s.Cookie != 77 || s.Inode != 88 || s.CreationCgroup != 99 || s.Port != 68 || s.Address.String() != "127.0.0.1" {
		t.Fatal("valid capture rejected")
	}
	for name, change := range map[string]func([]byte) []byte{
		"short": func(b []byte) []byte { return b[:71] }, "missing": func(b []byte) []byte { return b[:72] },
		"duplicate":   func(b []byte) []byte { return append(b, b[72:]...) },
		"bad length":  func(b []byte) []byte { b[72] = 255; return b },
		"cgroup zero": func(b []byte) []byte { clear(b[76:84]); return b },
		"cookie zero": func(b []byte) []byte { clear(b[44:52]); return b },
		"inode zero":  func(b []byte) []byte { clear(b[68:72]); return b },
		"family":      func(b []byte) []byte { b[0] = 10; return b },
		"connected":   func(b []byte) []byte { b[1] = 1; return b },
		"peer":        func(b []byte) []byte { b[24] = 1; return b },
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeSocket(change(socketMessage())); e == nil {
				t.Fatal("invalid capture accepted")
			}
		})
	}
}

func TestEnvelopeRejectsForgeryAndIncompleteDump(t *testing.T) {
	body := socketMessage()
	raw := make([]byte, 16+len(body))
	copy(raw[16:], body)
	binary.NativeEndian.PutUint32(raw[:4], uint32(len(raw)))
	binary.NativeEndian.PutUint16(raw[4:6], 20)
	binary.NativeEndian.PutUint16(raw[6:8], 2)
	binary.NativeEndian.PutUint32(raw[8:12], 1)
	binary.NativeEndian.PutUint32(raw[12:16], 10)
	rows, done, e := consume(raw, 1, 10)
	if e != nil || done || len(rows) != 1 {
		t.Fatal("row envelope")
	}
	for _, offset := range []int{0, 4, 6, 8, 12} {
		b := append([]byte(nil), raw...)
		b[offset] = 255
		if _, _, e := consume(b, 1, 10); e == nil {
			t.Fatalf("accepted malformed field %d", offset)
		}
	}
	end := make([]byte, 20)
	binary.NativeEndian.PutUint32(end[:4], 20)
	binary.NativeEndian.PutUint16(end[4:6], 3)
	binary.NativeEndian.PutUint32(end[8:12], 1)
	binary.NativeEndian.PutUint32(end[12:16], 10)
	if _, done, e = consume(end, 1, 10); e != nil || !done {
		t.Fatal("done")
	}
	end[16] = 1
	if _, _, e = consume(end, 1, 10); e == nil {
		t.Fatal("failed dump")
	}
}

func TestUnknownEndpointsArePreserved(t *testing.T) {
	b := socketMessage()
	clear(b[4:6])
	clear(b[8:12])
	s, err := decodeSocket(b)
	if err != nil || s.Port != 0 || !s.Address.IsUnspecified() {
		t.Fatal("inventory must not hide unbound or wildcard sockets", s, err)
	}
}
func TestDuplicateKernelIdentityIsRejected(t *testing.T) {
	s, _ := decodeSocket(socketMessage())
	other := s
	other.Inode++
	other.Cookie++
	if uniqueSockets([]Socket{s, other}) != nil {
		t.Fatal("different sockets rejected")
	}
	for _, rows := range [][]Socket{{s, s}, {s, {Inode: other.Inode, Cookie: s.Cookie, CreationCgroup: 99}}, {s, {Inode: s.Inode, Cookie: other.Cookie, CreationCgroup: 99}}} {
		if uniqueSockets(rows) == nil {
			t.Fatal("ambiguous kernel identities accepted")
		}
	}
}
