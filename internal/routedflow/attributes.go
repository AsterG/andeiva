package routedflow

import (
	"encoding/binary"
	"net/netip"
)

const nestedFlag uint16 = 1 << 15
const netOrderFlag uint16 = 1 << 14

type attribute struct {
	flags uint16
	value []byte
}
type attributes map[uint16]attribute
type attributeBudget struct{ count int }

func aligned(n int) int { return (n + 3) &^ 3 }

// Header lengths/types are native-endian; IPv4 addresses, ports, IDs, flags and
// counters follow nfnetlink's network byte order regardless of optional NLA flags.
func parseAttributes(data []byte, pad uint16, budget *attributeBudget) (attributes, error) {
	result := attributes{}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, ErrObservation
		}
		size := int(binary.NativeEndian.Uint16(data))
		kind := binary.NativeEndian.Uint16(data[2:])
		id := kind & 0x3fff
		flags := kind & 0xc000
		if size < 4 || aligned(size) > len(data) || flags == nestedFlag|netOrderFlag {
			return nil, ErrObservation
		}
		budget.count++
		if budget.count > MaxAttributes {
			return nil, ErrLimit
		}
		if id == pad && pad != 0 {
			if size != 4 || flags != 0 {
				return nil, ErrObservation
			}
		} else {
			if id == 0 {
				return nil, ErrObservation
			}
			if _, exists := result[id]; exists {
				return nil, ErrObservation
			}
			result[id] = attribute{flags: flags, value: data[4:size]}
		}
		data = data[aligned(size):]
	}
	return result, nil
}

func validateTree(data []byte, pad uint16, depth int, b *attributeBudget) error {
	if depth > 6 {
		return ErrLimit
	}
	a, e := parseAttributes(data, pad, b)
	if e != nil {
		return e
	}
	for id, value := range a {
		if value.flags != nestedFlag {
			continue
		}
		childPad := uint16(0)
		if depth == 0 {
			if id == 9 || id == 10 {
				childPad = 6
			}
			if id == 20 {
				childPad = 3
			}
		}
		if e := validateTree(value.value, childPad, depth+1, b); e != nil {
			return e
		}
	}
	return nil
}
func (a attributes) group(id uint16, pad uint16, b *attributeBudget) (attributes, error) {
	v, ok := a[id]
	if !ok || v.flags != nestedFlag {
		return nil, ErrObservation
	}
	return parseAttributes(v.value, pad, b)
}
func (a attributes) scalar(id uint16, size int) ([]byte, error) {
	v, ok := a[id]
	if !ok || v.flags == nestedFlag || len(v.value) != size {
		return nil, ErrObservation
	}
	return v.value, nil
}
func (a attributes) optional32(id uint16) (*uint32, error) {
	if _, ok := a[id]; !ok {
		return nil, nil
	}
	v, e := a.scalar(id, 4)
	if e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(v)
	return &n, nil
}
func (a attributes) optional16(id uint16) (*uint16, error) {
	if _, ok := a[id]; !ok {
		return nil, nil
	}
	v, e := a.scalar(id, 2)
	if e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint16(v)
	return &n, nil
}
func parseTuple(a attributes, id uint16, b *attributeBudget) (Tuple, error) {
	fields, e := a.group(id, 0, b)
	if e != nil {
		return Tuple{}, e
	}
	ip, e := fields.group(1, 0, b)
	if e != nil {
		return Tuple{}, e
	}
	src, e := ip.scalar(1, 4)
	if e != nil {
		return Tuple{}, e
	}
	dst, e := ip.scalar(2, 4)
	if e != nil {
		return Tuple{}, e
	}
	if _, ok := ip[3]; ok {
		return Tuple{}, ErrObservation
	}
	if _, ok := ip[4]; ok {
		return Tuple{}, ErrObservation
	}
	protocol, e := fields.group(2, 0, b)
	if e != nil {
		return Tuple{}, e
	}
	num, e := protocol.scalar(1, 1)
	if e != nil {
		return Tuple{}, e
	}
	name := "other"
	if num[0] == 6 {
		name = "tcp"
	}
	if num[0] == 17 {
		name = "udp"
	}
	var sp, dp uint16
	if name != "other" {
		p, e := protocol.scalar(2, 2)
		if e != nil {
			return Tuple{}, e
		}
		sp = binary.BigEndian.Uint16(p)
		p, e = protocol.scalar(3, 2)
		if e != nil {
			return Tuple{}, e
		}
		dp = binary.BigEndian.Uint16(p)
		for id := uint16(4); id <= 9; id++ {
			if _, ok := protocol[id]; ok {
				return Tuple{}, ErrObservation
			}
		}
	}
	zone, e := fields.optional16(3)
	if e != nil {
		return Tuple{}, e
	}
	return Tuple{Source: Endpoint{Address: netip.AddrFrom4([4]byte(src)), Port: sp}, Destination: Endpoint{Address: netip.AddrFrom4([4]byte(dst)), Port: dp}, Protocol: name, Zone: zone, protocolNumber: num[0]}, nil
}
func parseCounters(a attributes, id uint16, b *attributeBudget) (*Counters, error) {
	if _, ok := a[id]; !ok {
		return nil, nil
	}
	values, e := a.group(id, 6, b)
	if e != nil {
		return nil, e
	}
	c := &Counters{}
	for _, spec := range []struct {
		id     uint16
		target **uint64
	}{{1, &c.Packets}, {2, &c.Bytes}} {
		if _, ok := values[spec.id]; !ok {
			continue
		}
		raw, e := values.scalar(spec.id, 8)
		if e != nil {
			return nil, e
		}
		v := binary.BigEndian.Uint64(raw)
		*spec.target = &v
		c.WidthBits = 64
	}
	// Do not silently prefer one counter width over another conflicting report.
	for _, spec := range []struct {
		id     uint16
		target **uint64
	}{{3, &c.Packets}, {4, &c.Bytes}} {
		if _, ok := values[spec.id]; !ok {
			continue
		}
		if c.WidthBits == 64 {
			return nil, ErrObservation
		}
		raw, e := values.scalar(spec.id, 4)
		if e != nil {
			return nil, e
		}
		v := uint64(binary.BigEndian.Uint32(raw))
		*spec.target = &v
		c.WidthBits = 32
	}
	if c.Packets == nil && c.Bytes == nil {
		return nil, ErrObservation
	}
	return c, nil
}
func decodeFlow(data []byte) (Flow, bool, error) {
	if len(data) < 4 || data[0] != 2 || data[1] != 0 || binary.BigEndian.Uint16(data[2:4]) != 0 {
		return Flow{}, false, ErrObservation
	}
	if e := validateTree(data[4:], 0, 0, &attributeBudget{}); e != nil {
		return Flow{}, false, e
	}
	b := &attributeBudget{}
	a, e := parseAttributes(data[4:], 0, b)
	if e != nil {
		return Flow{}, false, e
	}
	orig, e := parseTuple(a, 1, b)
	if e != nil {
		return Flow{}, false, e
	}
	reply, e := parseTuple(a, 2, b)
	if e != nil {
		return Flow{}, false, e
	}
	if orig.protocolNumber != reply.protocolNumber {
		return Flow{}, false, ErrObservation
	}
	f := Flow{Original: orig, Reply: reply, ForwardTranslated: reverse(reply), ReplyTranslated: reverse(orig)}
	f.SourceChanged = f.Original.Source != f.ForwardTranslated.Source
	f.DestinationChanged = f.Original.Destination != f.ForwardTranslated.Destination
	for _, spec := range []struct {
		id     uint16
		target **uint32
	}{{3, &f.Status}, {7, &f.TimeoutSeconds}, {8, &f.Mark}, {12, &f.ID}} {
		v, e := a.optional32(spec.id)
		if e != nil {
			return Flow{}, false, e
		}
		*spec.target = v
	}
	f.Zone, e = a.optional16(18)
	if e != nil {
		return Flow{}, false, e
	}
	f.OriginalCounters, e = parseCounters(a, 9, b)
	if e != nil {
		return Flow{}, false, e
	}
	f.ReplyCounters, e = parseCounters(a, 10, b)
	if e != nil {
		return Flow{}, false, e
	}
	if orig.Protocol == "other" {
		return Flow{}, false, nil
	}
	if _, ok := a[4]; ok {
		info, e := a.group(4, 0, b)
		if e != nil {
			return Flow{}, false, e
		}
		if orig.Protocol != "tcp" {
			return Flow{}, false, ErrObservation
		}
		tcp, e := info.group(1, 0, b)
		if e != nil {
			return Flow{}, false, e
		}
		state, e := tcp.scalar(1, 1)
		if e != nil {
			return Flow{}, false, e
		}
		f.TCPState = tcpState(state[0])
	}
	return f, true, nil
}
