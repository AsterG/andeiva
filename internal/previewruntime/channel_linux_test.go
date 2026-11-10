//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func testDial(path string, m Metadata) (*firewallipc.Client, uint64, error) {
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, 0, e
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if e = json.NewEncoder(c).Encode(hello{Version: 1, RuntimeRun: m.RunID, Namespace: m.GatewayNamespace}); e != nil {
		c.Close()
		return nil, 0, e
	}
	b, e := bufio.NewReaderSize(c, 4096).ReadSlice('\n')
	var h hello
	if e != nil || firewallipc.Decode(b, &h) != nil {
		c.Close()
		return nil, 0, ErrUnavailable
	}
	_ = c.SetDeadline(time.Time{})
	client, e := firewallipc.New(c, c, h.Run, h.Epoch<<32, h.Namespace, artifactDigest)
	return client, h.Epoch, e
}
func TestUnixReconnectRecoveryAndIndependentExpiry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := privateDir(t)
	path := filepath.Join(p, "helper.sock")
	ids := Identities{APIUID: uint32(os.Getuid()), APIGID: uint32(os.Getgid())}
	l, e := listenPrivate(path, ids.APIUID, ids.APIGID)
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(path)
	m := Metadata{RunID: strings.Repeat("a", 32), GatewayNamespace: 42}
	backend := configpoc.NewSimEngine("unix-test")
	engine := NewCounterEngine(strings.Repeat("b", 32), backend, func(context.Context) (string, []firewallipc.Counter, error) { return backend.Current(), nil, nil })
	guardian := nftguardian.NewRestricted(engine)
	defer guardian.Close()
	s := NewSession(strings.Repeat("b", 32), 42, engine, guardian, engine.Observe)
	done := make(chan error, 1)
	go func() { done <- serveController(ctx, l, m, ids, s) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	}()
	client, epoch, e := testDial(path, m)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if epoch != 1 {
		t.Fatal("first epoch")
	}
	second, _, e := testDial(path, m)
	if e == nil {
		second.Close()
		t.Fatal("second controller accepted")
	}
	initial, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	target, _ := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "web", Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}})
	if client.Apply(ctx, initial) != nil || client.Recovered(ctx) != nil || client.Arm(ctx, "expire", initial, target, 500*time.Millisecond) != nil || client.Apply(ctx, target) != nil {
		t.Fatal("lease activation failed")
	}
	client.Close()
	deadline := time.Now().Add(2 * time.Second)
	for guardian.Status().Phase != "expired" {
		if time.Now().After(deadline) {
			t.Fatal("API loss disabled expiry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if engine.Current() != initial.Hash {
		t.Fatal("expiry failed readback")
	}
	client, epoch, e = testDial(path, m)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if epoch <= 1 {
		t.Fatal("epoch reused")
	}
	if client.Recovered(ctx) == nil {
		t.Fatal("reconnection bypassed recovery")
	}
	if client.Apply(ctx, initial) != nil || client.Recovered(ctx) != nil {
		t.Fatal("recovery rejected")
	}
}
func TestHandshakeRejectsWrongNamespaceAndOversize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(privateDir(t), "helper.sock")
	ids := Identities{APIUID: uint32(os.Getuid()), APIGID: uint32(os.Getgid())}
	l, e := listenPrivate(path, ids.APIUID, ids.APIGID)
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(path)
	engine := configpoc.NewSimEngine("invalid")
	guardian := nftguardian.NewRestricted(engine)
	defer guardian.Close()
	m := Metadata{RunID: strings.Repeat("a", 32), GatewayNamespace: 42}
	s := NewSession(strings.Repeat("b", 32), 42, engine, guardian, nil)
	done := make(chan error, 1)
	go func() { done <- serveController(ctx, l, m, ids, s) }()
	defer func() { cancel(); <-done }()
	for _, payload := range []string{`{"version":1,"runtime_run":"` + m.RunID + `","namespace":1}` + "\n", strings.Repeat("x", firewallipc.MaxFrame) + "\n"} {
		c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = c.Write([]byte(payload))
		var b [1]byte
		if n, _ := c.Read(b[:]); n != 0 {
			t.Fatal("bad handshake replied")
		}
		c.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if engine.Current() != "" {
		t.Fatal("invalid message changed engine")
	}
}
