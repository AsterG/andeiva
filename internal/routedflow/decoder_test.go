package routedflow

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSeq uint32 = 0x12345678
const testPort uint32 = 2468

func attr(id uint16, value []byte) []byte {
	b := make([]byte, aligned(4+len(value)))
	binary.NativeEndian.PutUint16(b, uint16(4+len(value)))
	binary.NativeEndian.PutUint16(b[2:], id)
	copy(b[4:], value)
	return b
}
func join(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func be64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func tuple(id uint16, src, dst string, sp, dp uint16, proto byte) []byte {
	sa := netip.MustParseAddr(src).As4()
	da := netip.MustParseAddr(dst).As4()
	ip := attr(nestedFlag|1, join(attr(1, sa[:]), attr(2, da[:])))
	protocol := attr(nestedFlag|2, join(attr(1, []byte{proto}), attr(2, be16(sp)), attr(3, be16(dp))))
	return attr(nestedFlag|id, join(ip, protocol))
}
func flowPayload(proto byte, withOptions bool) []byte {
	attrs := join(tuple(1, "198.18.0.2", "198.19.0.2", 45678, 18080, proto), tuple(2, "198.19.0.2", "198.19.0.1", 18080, 51000, proto))
	if withOptions {
		attrs = join(attrs, attr(3, be32(0x19e)), attr(7, be32(119)), attr(8, be32(0xad123456)), attr(12, be32(83)), attr(18, be16(9)),
			attr(nestedFlag|9, join(attr(1, be64(12)), attr(6, nil), attr(2, be64(2048)), attr(6, nil))),
			attr(nestedFlag|10, join(attr(1, be64(8)), attr(2, be64(1024)))))
		if proto == 6 {
			attrs = join(attrs, attr(nestedFlag|4, attr(nestedFlag|1, attr(1, []byte{3}))))
		}
	}
	return join([]byte{2, 0, 0, 0}, attrs)
}
func message(kind, flags uint16, payload []byte) []byte {
	b := make([]byte, aligned(headerSize+len(payload)))
	binary.NativeEndian.PutUint32(b, uint32(headerSize+len(payload)))
	binary.NativeEndian.PutUint16(b[4:], kind)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], testSeq)
	binary.NativeEndian.PutUint32(b[12:], testPort)
	copy(b[16:], payload)
	return b
}
func done() []byte { return message(3, flagMulti, []byte{0, 0, 0, 0}) }

func TestTupleTranslationAndOptionalKernelEvidence(t *testing.T) {
	f, ok, e := decodeFlow(flowPayload(6, true))
	if e != nil || !ok {
		t.Fatal(e)
	}
	if f.Original.Source.Address.String() != "198.18.0.2" || f.Original.Source.Port != 45678 || f.ForwardTranslated.Source.Address.String() != "198.19.0.1" || f.ForwardTranslated.Source.Port != 51000 || !f.SourceChanged || f.DestinationChanged {
		t.Fatalf("incorrect SNAT view: %+v", f)
	}
	if f.ReplyTranslated.Destination != f.Original.Source || f.ReplyTranslated.Source != f.Original.Destination || f.ForwardTranslated.Destination != f.Reply.Source {
		t.Fatal("inverse translation")
	}
	if f.TCPState == nil || f.TCPState.Name != "established" || f.TCPState.Value != 3 || f.Status == nil || *f.Status != 0x19e || f.Mark == nil || *f.Mark != 0xad123456 || *f.Zone != 9 || *f.TimeoutSeconds != 119 || *f.ID != 83 {
		t.Fatal("kernel fields lost")
	}
	if f.OriginalCounters == nil || f.OriginalCounters.WidthBits != 64 || *f.OriginalCounters.Packets != 12 || *f.OriginalCounters.Bytes != 2048 || *f.ReplyCounters.Packets != 8 {
		t.Fatal("counter endian/width")
	}
	f, ok, e = decodeFlow(flowPayload(17, false))
	if e != nil || !ok || f.Original.Protocol != "udp" {
		t.Fatal(e)
	}
	if f.Status != nil || f.TCPState != nil || f.OriginalCounters != nil || f.ReplyCounters != nil || f.Mark != nil || f.TimeoutSeconds != nil {
		t.Fatal("invented optional evidence")
	}
	encoded, _ := json.Marshal(f)
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	if _, ok := fields["tcp_state"]; ok {
		t.Fatal("UDP TCP state invented")
	}
	if _, ok := fields["original_counters"]; ok {
		t.Fatal("missing counters reported as zero")
	}
}
func TestNoTranslationAndDestinationTranslation(t *testing.T) {
	payload := join([]byte{2, 0, 0, 0}, tuple(1, "198.18.0.2", "203.0.113.5", 44000, 443, 6), tuple(2, "203.0.113.5", "198.18.0.2", 443, 44000, 6))
	f, _, e := decodeFlow(payload)
	if e != nil || f.SourceChanged || f.DestinationChanged {
		t.Fatal("non-NAT route changed", e)
	}
	payload = join([]byte{2, 0, 0, 0}, tuple(1, "198.18.0.2", "203.0.113.5", 44000, 443, 6), tuple(2, "198.19.0.20", "198.19.0.1", 8443, 51000, 6))
	f, _, e = decodeFlow(payload)
	if e != nil || !f.SourceChanged || !f.DestinationChanged || f.ForwardTranslated.Destination.Port != 8443 {
		t.Fatal("twice-NAT view", e)
	}
}
func TestCounterPresenceWidthAndDuplicates(t *testing.T) {
	cases := []struct {
		value          []byte
		bits           uint8
		packets, bytes bool
		bad            bool
	}{
		{join(attr(1, be64(0)), attr(2, be64(0))), 64, true, true, false},
		{attr(1, be64(1)), 64, true, false, false},
		{join(attr(3, be32(12)), attr(4, be32(24))), 32, true, true, false},
		{nil, 0, false, false, true}, {join(attr(1, be64(1)), attr(1, be64(2))), 0, false, false, true},
		{join(attr(1, be64(1)), attr(3, be32(1))), 0, false, false, true},
		{join(attr(1, be64(1)), attr(4, be32(1))), 0, false, false, true},
		{attr(1, be32(3)), 0, false, false, true},
	}
	for _, tc := range cases {
		a, e := parseAttributes(attr(nestedFlag|9, tc.value), 0, &attributeBudget{})
		if e != nil {
			t.Fatal(e)
		}
		c, e := parseCounters(a, 9, &attributeBudget{})
		if tc.bad {
			if e == nil {
				t.Fatal("invalid counter accepted")
			}
			continue
		}
		if e != nil || c.WidthBits != tc.bits || (c.Packets != nil) != tc.packets || (c.Bytes != nil) != tc.bytes {
			t.Fatal("counter presence/width", e)
		}
	}
}

func TestCounterJSONPreservesFullUint64Precision(t *testing.T) {
	packets := uint64(1<<53) + 1
	octets := ^uint64(0)
	data, e := json.Marshal(Counters{Packets: &packets, Bytes: &octets, WidthBits: 64})
	if e != nil || !strings.Contains(string(data), `"packets":"9007199254740993"`) || !strings.Contains(string(data), `"bytes":"18446744073709551615"`) {
		t.Fatal("counter JSON lost precision", string(data), e)
	}
	var decoded Counters
	if e = json.Unmarshal(data, &decoded); e != nil || decoded.Packets == nil || *decoded.Packets != packets || decoded.Bytes == nil || *decoded.Bytes != octets {
		t.Fatal("counter roundtrip", e)
	}
	zero := uint64(0)
	data, e = json.Marshal(Counters{Packets: &zero, WidthBits: 64})
	if e != nil || !strings.Contains(string(data), `"packets":"0"`) || strings.Contains(string(data), `"bytes"`) {
		t.Fatal("nil/zero counter distinction", string(data), e)
	}
	decoded = Counters{}
	if e = json.Unmarshal(data, &decoded); e != nil || decoded.Packets == nil || *decoded.Packets != 0 || decoded.Bytes != nil {
		t.Fatal("nil omission roundtrip", e)
	}
	for _, bad := range []string{`{"packets":9007199254740993,"width_bits":64}`, `{"bytes":"18446744073709551616","width_bits":64}`} {
		if json.Unmarshal([]byte(bad), new(Counters)) == nil {
			t.Fatal("unsafe counter wire value accepted")
		}
	}
}
func TestMalformedAttributesAndScope(t *testing.T) {
	original := tuple(1, "198.18.0.2", "198.19.0.2", 45678, 18080, 6)
	reply := tuple(2, "198.19.0.2", "198.19.0.1", 18080, 51000, 6)
	for _, payload := range [][]byte{
		nil, {2, 1, 0, 0}, {10, 0, 0, 0}, {2, 0, 0, 1},
		join([]byte{2, 0, 0, 0}, original), join([]byte{2, 0, 0, 0}, original, reply, original),
		join([]byte{2, 0, 0, 0}, attr(1, original[4:]), reply),
		join([]byte{2, 0, 0, 0}, original, tuple(2, "198.19.0.2", "198.19.0.1", 18080, 51000, 17)),
		join([]byte{2, 0, 0, 0}, original, reply, attr(nestedFlag|7, be32(30))),
		join([]byte{2, 0, 0, 0}, original, reply, attr(8, []byte{1, 2, 3})),
		join([]byte{2, 0, 0, 0}, original, reply, attr(nestedFlag|netOrderFlag|60, nil)),
		join([]byte{2, 0, 0, 0}, original, reply, attr(nestedFlag|60, join(attr(1, nil), attr(1, nil)))),
	} {
		if _, _, e := decodeFlow(payload); e == nil {
			t.Fatal("malformed attributes accepted")
		}
	}
	if _, ok, e := decodeFlow(flowPayload(1, false)); e != nil || ok {
		t.Fatal("non-TCP/UDP scope", e)
	}
	payload := flowPayload(6, false)
	extra := attr(55, []byte{1, 2, 3})
	payload = append(payload, extra...)
	if _, ok, e := decodeFlow(payload); e != nil || !ok {
		t.Fatal("bounded unused kernel attr rejected", e)
	}
	deep := attr(1, nil)
	for i := 0; i < 8; i++ {
		deep = attr(nestedFlag|60, deep)
	}
	if e := validateTree(deep, 0, 0, &attributeBudget{}); !errors.Is(e, ErrLimit) {
		t.Fatal("nested bound", e)
	}
	var many []byte
	for i := 1; i <= MaxAttributes+1; i++ {
		many = append(many, attr(uint16(i), nil)...)
	}
	if e := validateTree(many, 0, 0, &attributeBudget{}); !errors.Is(e, ErrLimit) {
		t.Fatal("attribute count bound", e)
	}
}

func TestMultipartCompletionAndStrictBoundaries(t *testing.T) {
	entry := message(ctNew, flagMulti, flowPayload(6, true))
	d := newMultipart(testSeq, testPort)
	if e := d.consume(entry, 0, 0, false); e != nil || d.done {
		t.Fatal(e)
	}
	if e := d.consume(done(), 0, 0, false); e != nil || !d.done || len(d.flows) != 1 {
		t.Fatal(e)
	}
	if e := d.consume(done(), 0, 0, false); e == nil {
		t.Fatal("duplicate terminator")
	}
	for _, change := range []func([]byte){
		func(b []byte) { binary.NativeEndian.PutUint32(b, 15) },
		func(b []byte) { binary.NativeEndian.PutUint32(b, uint32(len(b)+4)) },
		func(b []byte) { binary.NativeEndian.PutUint32(b[8:], testSeq+1) },
		func(b []byte) { binary.NativeEndian.PutUint32(b[12:], 0) },
		func(b []byte) { binary.NativeEndian.PutUint16(b[6:], 0) },
		func(b []byte) { binary.NativeEndian.PutUint16(b[4:], ctGet) },
	} {
		bad := append([]byte{}, entry...)
		change(bad)
		if e := newMultipart(testSeq, testPort).consume(bad, 0, 0, false); e == nil {
			t.Fatal("invalid header accepted")
		}
	}
	for _, tc := range []struct {
		data         []byte
		peer, groups uint32
		trunc        bool
	}{
		{entry, 7, 0, false}, {entry, 0, 1, false}, {entry, 0, 0, true}, {entry[:15], 0, 0, false},
		{join(done(), entry), 0, 0, false}, {join(entry, entry), 0, 0, false},
		{message(ctNew, flagMulti|flagDumpInterrupted, flowPayload(6, false)), 0, 0, false},
		{message(4, 0, nil), 0, 0, false}, {message(1, flagMulti, nil), 0, 0, false},
		{make([]byte, MaxDatagram+1), 0, 0, false},
	} {
		if e := newMultipart(testSeq, testPort).consume(tc.data, tc.peer, tc.groups, tc.trunc); e == nil {
			t.Fatal("invalid multipart accepted")
		}
	}
	d = newMultipart(testSeq, testPort)
	d.totalBytes = MaxDumpBytes
	if e := d.consume(done(), 0, 0, false); !errors.Is(e, ErrLimit) {
		t.Fatal("byte bound", e)
	}
	d = newMultipart(testSeq, testPort)
	d.messages = MaxMessages
	if e := d.consume(done(), 0, 0, false); !errors.Is(e, ErrLimit) {
		t.Fatal("message bound", e)
	}
	d = newMultipart(testSeq, testPort)
	d.flows = make([]Flow, MaxFlows)
	if e := d.consume(entry, 0, 0, false); !errors.Is(e, ErrLimit) {
		t.Fatal("flow bound", e)
	}
}

func TestDuplicateOriginalUsesEffectiveConntrackZone(t *testing.T) {
	original := tuple(1, "198.18.0.2", "198.19.0.2", 45678, 18080, 6)
	reply := tuple(2, "198.19.0.2", "198.19.0.1", 18080, 51000, 6)
	base := message(ctNew, flagMulti, join([]byte{2, 0, 0, 0}, original, reply, attr(18, be16(9))))
	directionalOriginal := attr(nestedFlag|1, join(original[4:], attr(3, be16(9))))
	directional := message(ctNew, flagMulti, join([]byte{2, 0, 0, 0}, directionalOriginal, reply))
	if e := newMultipart(testSeq, testPort).consume(join(base, directional), 0, 0, false); !errors.Is(e, ErrObservation) {
		t.Fatal("equivalent original zone duplicated", e)
	}
	otherZone := message(ctNew, flagMulti, join([]byte{2, 0, 0, 0}, original, reply, attr(18, be16(10))))
	d := newMultipart(testSeq, testPort)
	if e := d.consume(join(base, otherZone, done()), 0, 0, false); e != nil || len(d.flows) != 2 {
		t.Fatal("distinct conntrack zones collapsed", e)
	}
}
func TestKernelErrorsNeverBecomeEmptySuccess(t *testing.T) {
	for _, tc := range []struct {
		errno uint32
		want  error
	}{{2, ErrUnavailable}, {1, ErrPermission}, {13, ErrPermission}, {105, ErrInterrupted}, {22, ErrTransport}} {
		payload := make([]byte, 4)
		binary.NativeEndian.PutUint32(payload, ^tc.errno+1)
		payload = append(payload, dumpRequest(testSeq, testPort)...)
		e := newMultipart(testSeq, testPort).consume(message(2, 0, payload), 0, 0, false)
		if !errors.Is(e, tc.want) {
			t.Fatal(tc, e)
		}
	}
	ack := join([]byte{0, 0, 0, 0}, dumpRequest(testSeq, testPort))
	if e := newMultipart(testSeq, testPort).consume(message(2, 0, ack), 0, 0, false); e == nil {
		t.Fatal("unsolicited ACK")
	}
	req := dumpRequest(testSeq, testPort)
	if len(req) != 20 || binary.NativeEndian.Uint16(req[4:]) != ctGet || binary.NativeEndian.Uint16(req[6:]) != 0x301 || req[16] != 2 {
		t.Fatal("not strictly read-only IPv4 request")
	}
}

type fakeTransport struct {
	packets []datagram
	sent    [][]byte
	block   bool
}

func (f *fakeTransport) send(_ context.Context, b []byte) error {
	f.sent = append(f.sent, append([]byte{}, b...))
	return nil
}
func (f *fakeTransport) receive(ctx context.Context) (datagram, error) {
	if f.block {
		<-ctx.Done()
		return datagram{}, ctx.Err()
	}
	if len(f.packets) == 0 {
		return datagram{}, ErrTransport
	}
	p := f.packets[0]
	f.packets = f.packets[1:]
	return p, nil
}
func TestCollectCancellationAndNoPartialSuccess(t *testing.T) {
	tport := &fakeTransport{packets: []datagram{{data: message(ctNew, flagMulti, flowPayload(6, false))}, {data: done()}}}
	snapshot, e := collect(context.Background(), tport, testSeq, testPort)
	if e != nil || len(snapshot.Flows) != 1 || len(tport.sent) != 1 || snapshot.FinishedAt.Before(snapshot.StartedAt) {
		t.Fatal(e)
	}
	tport = &fakeTransport{packets: []datagram{{data: message(ctNew, flagMulti, flowPayload(6, false))}}}
	snapshot, e = collect(context.Background(), tport, testSeq, testPort)
	if e == nil || snapshot.Flows != nil {
		t.Fatal("partial dump released")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tport = &fakeTransport{}
	if _, e = collect(ctx, tport, testSeq, testPort); !errors.Is(e, context.Canceled) || len(tport.sent) != 0 {
		t.Fatal("cancelled send", e)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, e = collect(ctx, &fakeTransport{block: true}, testSeq, testPort); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("deadline", e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tport := &fakeTransport{packets: []datagram{{data: done()}}}
			if s, e := collect(context.Background(), tport, testSeq, testPort); e != nil || s.Flows == nil || len(s.Flows) != 0 {
				t.Error("empty complete dump", e)
			}
		}()
	}
	wg.Wait()
}
func FuzzMultipart(f *testing.F) {
	f.Add(join(message(ctNew, flagMulti, flowPayload(6, true)), done()))
	f.Add(flowPayload(17, false))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxDatagram {
			t.Skip()
		}
		d := newMultipart(testSeq, testPort)
		_ = d.consume(data, 0, 0, false)
	})
}
func FuzzFlowAttributes(f *testing.F) {
	f.Add(flowPayload(6, true))
	f.Add(flowPayload(17, false))
	f.Add([]byte{2, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxDatagram {
			t.Skip()
		}
		_, _, _ = decodeFlow(data)
	})
}
func BenchmarkDecodeFlow(b *testing.B) {
	data := flowPayload(6, true)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, e := decodeFlow(data); e != nil {
			b.Fatal(e)
		}
	}
}
