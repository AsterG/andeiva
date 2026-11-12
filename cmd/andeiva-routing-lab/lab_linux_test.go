//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/routedflow"
)

func TestExecutableAllowlist(t *testing.T) {
	self := "/trusted/andeiva-routing-lab"
	for _, path := range []string{ipPath, nftPath, "/usr/sbin/sysctl", self} {
		if !allowedExecutable(path, self) {
			t.Fatalf("fixed executable rejected: %s", path)
		}
	}
	for _, path := range []string{"", "/bin/sh", "/usr/bin/nft", "/trusted/../trusted/andeiva-routing-lab", "nft", "/usr/sbin/nft;sh", "/trusted/andeiva-routing-lab-extra"} {
		if allowedExecutable(path, self) {
			t.Fatalf("unexpected executable allowed: %s", path)
		}
	}
	if allowedExecutable("", "") {
		t.Fatal("empty self authorizes an executable")
	}
}

func flowSnapshotFixture() routedflow.Snapshot {
	endpoint := func(ip string, port uint16) routedflow.Endpoint {
		return routedflow.Endpoint{Address: netip.MustParseAddr(ip), Port: port}
	}
	s := routedflow.Snapshot{SchemaVersion: 1, StartedAt: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), Flows: []routedflow.Flow{}}
	s.FinishedAt = s.StartedAt.Add(time.Millisecond)
	for i, protocol := range []string{"tcp", "udp"} {
		port := uint16(18080 + i)
		original := routedflow.Tuple{Protocol: protocol, Source: endpoint("198.18.0.2", uint16(40000+i)), Destination: endpoint("198.19.0.2", port)}
		reply := routedflow.Tuple{Protocol: protocol, Source: endpoint("198.19.0.2", port), Destination: endpoint("198.19.0.1", uint16(50000+i))}
		s.Flows = append(s.Flows, routedflow.Flow{Original: original, Reply: reply, ForwardTranslated: routedflow.Tuple{Protocol: protocol, Source: reply.Destination, Destination: reply.Source}, ReplyTranslated: routedflow.Tuple{Protocol: protocol, Source: original.Destination, Destination: original.Source}, SourceChanged: true})
	}
	return s
}

func TestFlowSnapshotRequiresBothRealSNATTuples(t *testing.T) {
	data, _ := json.Marshal(flowSnapshotFixture())
	s, e := decodeSNATFlowSnapshot(data)
	if e != nil || len(s.Flows) != 2 {
		t.Fatal("valid real-flow shape rejected", e)
	}
	for _, flow := range s.Flows {
		if flow.OriginalCounters != nil || flow.ReplyCounters != nil || flow.TCPState != nil {
			t.Fatal("nil metrics invented")
		}
	}
	for _, change := range []func(*routedflow.Snapshot){
		func(s *routedflow.Snapshot) { s.Flows = s.Flows[:1] },
		func(s *routedflow.Snapshot) { s.Flows = nil },
		func(s *routedflow.Snapshot) {
			s.Flows[0].Original.Source.Address = netip.MustParseAddr("198.18.0.99")
			s.Flows[0].ReplyTranslated.Destination = s.Flows[0].Original.Source
		},
		func(s *routedflow.Snapshot) {
			s.Flows[0].Reply.Destination.Address = netip.MustParseAddr("198.19.0.99")
			s.Flows[0].ForwardTranslated.Source = s.Flows[0].Reply.Destination
		},
		func(s *routedflow.Snapshot) {
			s.Flows[0].ForwardTranslated.Source.Address = netip.MustParseAddr("198.19.0.99")
		},
		func(s *routedflow.Snapshot) { s.Flows[0].Original.Protocol = "icmp" },
		func(s *routedflow.Snapshot) { s.Flows[0].Reply.Protocol = "udp" },
		func(s *routedflow.Snapshot) {
			s.Flows[1].Original.Destination.Port = 18082
			s.Flows[1].ReplyTranslated.Source = s.Flows[1].Original.Destination
		},
		func(s *routedflow.Snapshot) {
			s.Flows[1].Reply.Source.Port = 18082
			s.Flows[1].ForwardTranslated.Destination = s.Flows[1].Reply.Source
		},
		func(s *routedflow.Snapshot) { s.Flows[0].SourceChanged = false },
		func(s *routedflow.Snapshot) {
			s.Flows[0].Original.Source.Port = 0
			s.Flows[0].ReplyTranslated.Destination = s.Flows[0].Original.Source
		},
		func(s *routedflow.Snapshot) { s.SchemaVersion = 2 },
		func(s *routedflow.Snapshot) { s.FinishedAt = s.StartedAt.Add(-time.Second) },
	} {
		bad := flowSnapshotFixture()
		change(&bad)
		data, _ := json.Marshal(bad)
		if _, e := decodeSNATFlowSnapshot(data); e == nil {
			t.Fatal("invalid tuple/snapshot accepted")
		}
	}
}

func TestFlowSnapshotStrictJSONBounds(t *testing.T) {
	data, _ := json.Marshal(flowSnapshotFixture())
	for _, bad := range [][]byte{
		nil, append(append([]byte{}, data...), []byte(` {}`)...), bytes.Repeat([]byte{' '}, (1<<20)+1),
		[]byte(strings.Replace(string(data), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		[]byte(strings.Replace(string(data), `"schema_version":1`, `"Schema_version":1`, 1)),
		[]byte(strings.Replace(string(data), `"schema_version":1`, `"schema_version":1,"unexpected":true`, 1)),
	} {
		if _, e := decodeSNATFlowSnapshot(bad); e == nil {
			t.Fatal("invalid JSON snapshot accepted")
		}
	}
}

func TestFlowSnapshotExactCounterStrings(t *testing.T) {
	fixture := flowSnapshotFixture()
	packets := uint64(1<<53) + 1
	octets := ^uint64(0)
	fixture.Flows[0].OriginalCounters = &routedflow.Counters{Packets: &packets, Bytes: &octets, WidthBits: 64}
	data, e := json.Marshal(fixture)
	if e != nil {
		t.Fatal(e)
	}
	snapshot, e := decodeSNATFlowSnapshot(data)
	if e != nil || *snapshot.Flows[0].OriginalCounters.Packets != packets || *snapshot.Flows[0].OriginalCounters.Bytes != octets || snapshot.Flows[0].ReplyCounters != nil {
		t.Fatal("counter string snapshot precision/presence", e)
	}
	unsafe := strings.Replace(string(data), `"packets":"9007199254740993"`, `"packets":9007199254740993`, 1)
	if _, e = decodeSNATFlowSnapshot([]byte(unsafe)); e == nil {
		t.Fatal("numeric counter accepted by strict helper")
	}
}
