//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedflow"
	"github.com/AsterG/andeiva/internal/routednft"
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

type fakeNetworkExecutor struct {
	calls                                     []string
	applyErr, verifyErr, restoreErr, closeErr error
	plan                                      networkplan.Revision
}

func (e *fakeNetworkExecutor) Apply(_ context.Context, plan networkplan.Revision) error {
	e.calls = append(e.calls, "apply")
	e.plan = plan
	return e.applyErr
}
func (e *fakeNetworkExecutor) Verify(context.Context) error {
	e.calls = append(e.calls, "verify")
	return e.verifyErr
}
func (e *fakeNetworkExecutor) Restore() error {
	e.calls = append(e.calls, "restore")
	return e.restoreErr
}
func (e *fakeNetworkExecutor) Close() error { e.calls = append(e.calls, "close"); return e.closeErr }

func TestTypedNetworkPlanUsesCanonicalLabPolicyAndReadback(t *testing.T) {
	f := &fakeNetworkExecutor{}
	if err := applyTypedNetworkPlan(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.calls, []string{"apply", "verify"}) || !reflect.DeepEqual(f.plan, routednft.LabPolicy().Network) {
		t.Fatal("typed plan or readback missing")
	}
	applyFailure := errors.New("apply failure")
	verifyFailure := errors.New("verify failure")
	f = &fakeNetworkExecutor{applyErr: applyFailure}
	if err := applyTypedNetworkPlan(context.Background(), f); !errors.Is(err, applyFailure) || !reflect.DeepEqual(f.calls, []string{"apply"}) {
		t.Fatal("failed apply passed to verification", err)
	}
	f = &fakeNetworkExecutor{verifyErr: verifyFailure}
	if err := applyTypedNetworkPlan(context.Background(), f); !errors.Is(err, verifyFailure) {
		t.Fatal("failed readback hidden", err)
	}
}

func TestHostAnchorOverrideAcceptsNoArbitraryDescriptorOrPath(t *testing.T) {
	for _, input := range []string{"1", "3", "00", " 0", "/proc/1/ns/net", "/proc/self/fd/0", "-1"} {
		if executor, err := newLabNetworkExecutor(context.Background(), nil, input); err == nil || executor != nil {
			t.Fatal("nonliteral host override accepted", input)
		}
	}
}

func TestTypedNetworkCleanupRestoresBeforeClosingAndRetainsBothErrors(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f := &fakeNetworkExecutor{}
		if fail {
			f.restoreErr = errors.New("uncertain restoration")
			f.closeErr = errors.New("close failure")
		}
		err := closeTypedNetworkPlan(f)
		if !reflect.DeepEqual(f.calls, []string{"restore", "close"}) {
			t.Fatal("cleanup order changed", f.calls)
		}
		if fail {
			if !errors.Is(err, f.restoreErr) || !errors.Is(err, f.closeErr) {
				t.Fatal("cleanup failure hidden", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNamespacePinIdentityRejectsReplacementAndSymlink(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	for _, path := range []string{first, second} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	a, err := os.Lstat(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Lstat(second)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.Open(first)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	opened, err := pin.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !sameNamespacePin(a, opened) || sameNamespacePin(a, b) || sameNamespacePin(nil, a) || sameNamespacePin(a, nil) {
		t.Fatal("pin inode guard failed")
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(first, alias); err != nil {
		t.Fatal(err)
	}
	symlink, err := os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if sameNamespacePin(a, symlink) {
		t.Fatal("symlink accepted as namespace pin")
	}
	n := &namespace{name: "andeiva-uncreated-test-pin"}
	if f, err := n.open(); err == nil || f != nil {
		if f != nil {
			_ = f.Close()
		}
		t.Fatal("uncreated namespace opened")
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
