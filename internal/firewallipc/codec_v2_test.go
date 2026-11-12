package firewallipc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewalladmin"
)

func requestFixtureV2(verb string, p any) RequestV2 {
	b, _ := json.Marshal(p)
	return RequestV2{ProtocolVersion: 2, Run: strings.Repeat("a", 32), Sequence: 1<<32 | 1, Namespace: 42, Domain: "firewall", Verb: verb, Payload: b}
}
func TestCodecV2StrictScopes(t *testing.T) {
	scope := RecoveryScope{"lease", strings.Repeat("b", 64), strings.Repeat("c", 64), time.Date(2026, 11, 12, 1, 2, 3, 123456789, time.UTC)}
	m := requestFixtureV2("recover_scoped", scope)
	valid, _ := json.Marshal(m)
	if _, _, e := DecodeRequestV2(valid); e != nil {
		t.Fatal(e)
	}
	for name, bad := range map[string][]byte{
		"unknown":   []byte(strings.Replace(string(valid), `"id":"lease"`, `"id":"lease","ttl_ns":1`, 1)),
		"duplicate": []byte(strings.Replace(string(valid), `"id":"lease"`, `"id":"lease","ID":"other"`, 1)),
		"case":      []byte(strings.Replace(string(valid), `"protocol_version"`, `"Protocol_version"`, 1)),
		"offset":    []byte(strings.Replace(string(valid), "01:02:03.123456789Z", "01:02:03.123456789+00:00", 1)),
		"precision": []byte(strings.Replace(string(valid), ".123456789Z", ".1234567890Z", 1)),
		"zero":      []byte(strings.Replace(string(valid), "2026-11-12T01:02:03.123456789Z", "0001-01-01T00:00:00Z", 1)),
		"version":   []byte(strings.Replace(string(valid), `"protocol_version":2`, `"protocol_version":1`, 1)),
		"legacy":    []byte(strings.Replace(string(valid), "recover_scoped", "recovered", 1)),
		"extra":     append(append([]byte{}, valid...), []byte(` {}`)...),
		"oversize":  []byte(strings.Repeat("x", MaxFrame+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, e := DecodeRequestV2(bad); e == nil {
				t.Fatal("accepted malformed frame")
			}
		})
	}
	for _, payload := range []json.RawMessage{nil, json.RawMessage(`null`), json.RawMessage(`[]`), json.RawMessage(`{"x":1}`)} {
		m = requestFixtureV2("state", struct{}{})
		m.Payload = payload
		b, _ := json.Marshal(m)
		if _, _, e := DecodeRequestV2(b); e == nil {
			t.Fatal("state payload accepted", string(payload))
		}
	}
}
func TestCodecV2HelloAndReplyCorrelation(t *testing.T) {
	h := NewHelloV2(strings.Repeat("a", 32), 42, "firewall")
	b, _ := json.Marshal(h)
	if _, e := DecodeHelloV2(b, false); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{strings.Replace(string(b), `"attach_observed.v1","recover_scoped.v1"`, `"recover_scoped.v1","attach_observed.v1"`, 1), strings.Replace(string(b), `"protocol_version":2`, `"protocol_version":1`, 1), strings.Replace(string(b), `"domain":"firewall"`, `"domain":"arbitrary"`, 1)} {
		if _, e := DecodeHelloV2([]byte(bad), false); e == nil {
			t.Fatal("bad hello")
		}
	}
	m := requestFixtureV2("state", struct{}{})
	p, _ := json.Marshal(ResultV2{State: firewalladmin.LeaseState{Phase: "idle"}, Hash: strings.Repeat("b", 64)})
	r := ReplyV2{ProtocolVersion: 2, Run: m.Run, Sequence: m.Sequence, Namespace: m.Namespace, Domain: m.Domain, Verb: m.Verb, Payload: p}
	b, _ = json.Marshal(r)
	if _, e := DecodeReplyV2(b, m); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*ReplyV2){func(r *ReplyV2) { r.Sequence++ }, func(r *ReplyV2) { r.Domain = "local_services" }, func(r *ReplyV2) { r.Namespace++ }, func(r *ReplyV2) { r.ProtocolVersion = 1 }, func(r *ReplyV2) { r.Run = strings.Repeat("b", 32) }, func(r *ReplyV2) { r.Verb = "observe" }, func(r *ReplyV2) { r.Error = ErrChannel.Error() }} {
		bad := r
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if _, e := DecodeReplyV2(b, m); e == nil {
			t.Fatal("uncorrelated reply accepted")
		}
	}
}
func FuzzDecodeRequestV2(f *testing.F) {
	m := requestFixtureV2("state", struct{}{})
	b, _ := json.Marshal(m)
	f.Add(b)
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _, _ = DecodeRequestV2(data) })
}
