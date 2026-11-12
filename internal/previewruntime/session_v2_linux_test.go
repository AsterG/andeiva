//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/nftguardian"
)

func socketpairV2(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	open := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "test-owned-ipc")
		c, e := net.FileConn(f)
		_ = f.Close()
		if e != nil {
			t.Fatal(e)
		}
		return c.(*net.UnixConn)
	}
	return open(fds[0]), open(fds[1])
}

func TestScopedIPCV2ExpiredAndStaleAttachment(t *testing.T) {
	s, g, engine, a, b := fixtureSessionV2(t)
	ctx := context.Background()
	c := initializeV2(t, s, a)
	if c.client.Arm(ctx, "lease", a, b, 500*time.Millisecond) != nil {
		t.Fatal("arm")
	}
	armed, _ := c.client.Snapshot(ctx)
	if g.Apply(ctx, b) != nil {
		t.Fatal("test-controlled transition")
	}
	if c.client.AttachObserved(ctx, armed) == nil || g.Status().Phase != "pending" || engine.Current() != b.Hash {
		t.Fatal("stale attach accepted or mutated")
	}
	c.stop()
	time.Sleep(550 * time.Millisecond)
	c = dialSessionV2(t, s, nil)
	defer c.stop()
	o := attachV2(t, c.client)
	if o.State.Phase != "expired" || o.Hash != a.Hash || c.client.RecoverScoped(ctx, o.State) != nil || g.Status().Phase != "idle" {
		t.Fatal("expired exact recovery", o)
	}
}

func TestScopedIPCV2SingleControllerAndEnvelope(t *testing.T) {
	s, _, engine, a, _ := fixtureSessionV2(t)
	c := initializeV2(t, s, a)
	x, y := socketpairV2(t)
	done := make(chan error, 1)
	go func() { done <- s.ServeV2(context.Background(), y, strings.Repeat("a", 32)) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if extra, e := firewallipc.ConnectV2(ctx, x, strings.Repeat("a", 32), 42, "firewall", artifactDigest); e == nil {
		_ = extra.Close()
		t.Fatal("second controller accepted")
	}
	<-done
	c.stop()
	for _, field := range []string{"run", "namespace", "domain", "sequence", "epoch", "version"} {
		t.Run(field, func(t *testing.T) {
			x, y := socketpairV2(t)
			done := make(chan error, 1)
			go func() { done <- s.ServeV2(context.Background(), y, strings.Repeat("a", 32)) }()
			h := firewallipc.NewHelloV2(strings.Repeat("a", 32), 42, "firewall")
			_ = json.NewEncoder(x).Encode(h)
			reader := bufio.NewReader(x)
			data, e := reader.ReadBytes('\n')
			if e != nil {
				t.Fatal(e)
			}
			got, e := firewallipc.DecodeHelloV2(data, true)
			if e != nil {
				t.Fatal(e)
			}
			m := firewallipc.RequestV2{ProtocolVersion: 2, Run: got.Run, Sequence: got.Epoch<<32 | 1, Namespace: 42, Domain: "firewall", Verb: "state", Payload: json.RawMessage(`{}`)}
			switch field {
			case "run":
				m.Run = strings.Repeat("c", 32)
			case "namespace":
				m.Namespace++
			case "domain":
				m.Domain = "local_services"
			case "sequence":
				m.Sequence++
			case "epoch":
				m.Sequence += 1 << 32
			case "version":
				m.ProtocolVersion = 1
			}
			_ = json.NewEncoder(x).Encode(m)
			_ = x.SetReadDeadline(time.Now().Add(time.Second))
			if _, e = reader.ReadBytes('\n'); e == nil {
				t.Fatal("envelope mismatch accepted")
			}
			_ = x.Close()
			<-done
			if engine.Current() != a.Hash {
				t.Fatal("invalid envelope changed policy")
			}
		})
	}
}

type lostBootstrapV2 struct{ *net.UnixConn }

func (c lostBootstrapV2) Write(b []byte) (int, error) {
	var r firewallipc.ReplyV2
	if json.Unmarshal(b, &r) == nil && r.Verb == "bootstrap" && r.Error == "" {
		_ = c.Close()
		return len(b), nil
	}
	return c.UnixConn.Write(b)
}
func TestScopedIPCV2LostBootstrapNeverRepeats(t *testing.T) {
	s, g, engine, a, _ := fixtureSessionV2(t)
	c := dialSessionV2(t, s, func(c *net.UnixConn) io.ReadWriteCloser { return lostBootstrapV2{c} })
	attachV2(t, c.client)
	if c.client.Bootstrap(context.Background(), a) == nil || engine.Current() != a.Hash || g.Status().Phase != "idle" {
		t.Fatal("lost bootstrap reply")
	}
	c.stop()
	c = dialSessionV2(t, s, nil)
	defer c.stop()
	o := attachV2(t, c.client)
	if o.Hash != a.Hash || o.State.Phase != "idle" {
		t.Fatal(o)
	}
	if c.client.Bootstrap(context.Background(), a) == nil || engine.Current() != a.Hash {
		t.Fatal("bootstrap replay allowed")
	}
}

func TestScopedIPCV2LocalDomainObservation(t *testing.T) {
	ctx := context.Background()
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "src0", Zone: localpolicy.LAN, Addresses: []string{"198.18.1.1"}}}}
	r, e := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
	if e != nil {
		t.Fatal(e)
	}
	compile := func(c configpoc.Config) (string, error) {
		if c.LocalServices == nil || len(c.Rules) != 0 || c.DefaultAction != "deny" {
			return "", errHelper
		}
		a, e := localnft.Compile(*c.LocalServices)
		return a.Digest, e
	}
	artifact, e := localnft.Compile(local)
	if e != nil {
		t.Fatal(e)
	}
	engine := configpoc.NewSimEngine("local-v2")
	g := nftguardian.NewRestricted(engine)
	defer g.Close()
	s, e := NewLocalSessionV2(strings.Repeat("b", 32), 42, engine, g, compile, func(context.Context) (string, localpolicy.Observation, error) {
		return engine.Current(), localpolicy.Observation{Revision: artifact.Revision.Hash, Rules: artifact.Rules}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	x, y := socketpairV2(t)
	done := make(chan error, 1)
	go func() {
		done <- s.ServeInheritedV2(ctx, y, uint32(os.Getuid()), uint32(os.Getgid()), int32(os.Getpid()), strings.Repeat("a", 32))
	}()
	c, e := ConnectInheritedV2(ctx, x, uint32(os.Getuid()), uint32(os.Getgid()), int32(os.Getpid()), strings.Repeat("a", 32), 42, "local_services", compile)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = c.Close(); <-done }()
	attachV2(t, c)
	if c.Bootstrap(ctx, r) != nil {
		t.Fatal("local bootstrap")
	}
	observed, e := c.Observe(ctx)
	if e != nil || observed.Local == nil || observed.Local.Revision != artifact.Revision.Hash || observed.Hash != r.Hash || len(observed.Counters) != 0 {
		t.Fatal("local observation", observed, e)
	}
}

func TestScopedIPCV2PrivateUnixController(t *testing.T) {
	for _, wrongPeer := range []bool{false, true} {
		t.Run(map[bool]string{false: "authenticated", true: "wrong-peer"}[wrongPeer], func(t *testing.T) {
			s, _, engine, a, _ := fixtureSessionV2(t)
			path := filepath.Join(privateDir(t), "v2.sock")
			uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
			listener, e := listenPrivate(path, uid, gid)
			if e != nil {
				t.Fatal(e)
			}
			defer os.Remove(path)
			ids := Identities{APIUID: uid, APIGID: gid}
			if wrongPeer {
				ids.APIUID++
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- serveControllerV2(ctx, listener, Metadata{RunID: strings.Repeat("a", 32), GatewayNamespace: 42}, ids, s)
			}()
			defer func() {
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(time.Second):
					t.Error("controller leaked")
				}
			}()
			conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			if peer(conn, uid, gid) != nil {
				t.Fatal("kernel helper peer mismatch")
			}
			client, e := firewallipc.ConnectV2(ctx, conn, strings.Repeat("a", 32), 42, "firewall", artifactDigest)
			if wrongPeer {
				if e == nil {
					_ = client.Close()
					t.Fatal("foreign kernel peer accepted")
				}
				if engine.Current() != "" {
					t.Fatal("peer rejection changed engine")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			attachV2(t, client)
			if client.Bootstrap(ctx, a) != nil || engine.Current() != a.Hash {
				t.Fatal("private socket bootstrap")
			}
		})
	}
}

func TestScopedIPCV2BurstAndFatalListenerCleanup(t *testing.T) {
	s, _, engine, a, _ := fixtureSessionV2(t)
	path := filepath.Join(privateDir(t), "bounded.sock")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	l, e := listenPrivate(path, uid, gid)
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveControllerV2(ctx, l, Metadata{RunID: strings.Repeat("a", 32), GatewayNamespace: 42}, Identities{APIUID: uid, APIGID: gid}, s)
	}()
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	c, e := firewallipc.ConnectV2(ctx, conn, strings.Repeat("a", 32), 42, "firewall", artifactDigest)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	attachV2(t, c)
	if c.Bootstrap(ctx, a) != nil {
		t.Fatal("bootstrap")
	}
	for i := 0; i < 64; i++ {
		extra, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		attempt, stop := context.WithTimeout(ctx, time.Second)
		other, e := firewallipc.ConnectV2(attempt, extra, strings.Repeat("a", 32), 42, "firewall", artifactDigest)
		stop()
		if e == nil {
			_ = other.Close()
			t.Fatal("burst admitted a second controller")
		}
	}
	s.mu.Lock()
	epoch := s.epoch
	s.mu.Unlock()
	if epoch != 1 || engine.Current() != a.Hash {
		t.Fatal("rejected burst allocated session epochs", epoch)
	}
	_ = l.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("fatal accept error hidden")
		}
	case <-time.After(time.Second):
		t.Fatal("listener error waited forever on active controller")
	}
	if _, e = c.State(ctx); e == nil {
		t.Fatal("fatal listener error left active controller")
	}
}
func revisionsV2(t *testing.T) (configpoc.Revision, configpoc.Revision) {
	t.Helper()
	a, e := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if e != nil {
		t.Fatal(e)
	}
	b, e := configpoc.Canonical(configpoc.Config{SchemaVersion: 2, DefaultAction: "deny", Rules: []configpoc.Rule{{ID: "web", Action: "allow", Match: &configpoc.Match{Source: "198.18.0.2/32", Destination: "198.18.0.6/32", Protocol: "tcp", SourcePorts: configpoc.PortRange{From: 1, To: 65535}, DestinationPorts: configpoc.PortRange{From: 18080, To: 18080}}}}})
	if e != nil {
		t.Fatal(e)
	}
	return a, b
}

type connectionV2 struct {
	client *firewallipc.ClientV2
	stop   func()
}

func dialSessionV2(t *testing.T, s *SessionV2, wrap func(*net.UnixConn) io.ReadWriteCloser) connectionV2 {
	t.Helper()
	a, b := socketpairV2(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		if wrap != nil {
			done <- s.ServeV2(ctx, wrap(b), strings.Repeat("a", 32))
		} else {
			done <- s.ServeInheritedV2(ctx, b, uint32(os.Getuid()), uint32(os.Getgid()), int32(os.Getpid()), strings.Repeat("a", 32))
		}
	}()
	c, e := ConnectInheritedV2(ctx, a, uint32(os.Getuid()), uint32(os.Getgid()), int32(os.Getpid()), strings.Repeat("a", 32), 42, "firewall", artifactDigest)
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	stop := func() {
		_ = c.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("session leaked")
		}
	}
	return connectionV2{c, stop}
}
func fixtureSessionV2(t *testing.T) (*SessionV2, *nftguardian.Guardian, *configpoc.SimEngine, configpoc.Revision, configpoc.Revision) {
	t.Helper()
	a, b := revisionsV2(t)
	engine := configpoc.NewSimEngine("socket-v2")
	guardian := nftguardian.NewRestricted(engine)
	s, e := NewSessionV2(strings.Repeat("b", 32), 42, engine, guardian, func(context.Context) (string, []firewallipc.Counter, string, error) {
		return engine.Current(), nil, strings.Repeat("b", 32) + ".0", nil
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = guardian.Close() })
	return s, guardian, engine, a, b
}
func attachV2(t *testing.T, c *firewallipc.ClientV2) firewallipc.ObservedScope {
	t.Helper()
	o, e := c.Snapshot(context.Background())
	if e != nil || c.AttachObserved(context.Background(), o) != nil {
		t.Fatal("attachment", o, e)
	}
	return o
}
func initializeV2(t *testing.T, s *SessionV2, a configpoc.Revision) connectionV2 {
	t.Helper()
	c := dialSessionV2(t, s, nil)
	o := attachV2(t, c.client)
	if o.State.Phase != "bootstrap" || o.Hash != "" || c.client.Bootstrap(context.Background(), a) != nil {
		c.stop()
		t.Fatal("cold bootstrap")
	}
	return c
}
func TestScopedIPCV2ColdBarrierAndReconnect(t *testing.T) {
	s, g, engine, a, b := fixtureSessionV2(t)
	ctx := context.Background()
	c := dialSessionV2(t, s, nil)
	if c.client.Arm(ctx, "early", a, b, time.Second) == nil || engine.Current() != "" {
		t.Fatal("mutation before attachment")
	}
	c.stop()
	c = initializeV2(t, s, a)
	if c.client.Arm(ctx, "lease", a, b, 2*time.Second) != nil || c.client.Apply(ctx, b) != nil {
		t.Fatal("activation")
	}
	o, e := c.client.Snapshot(ctx)
	if e != nil || o.State.Phase != "pending" {
		t.Fatal(o, e)
	}
	c.stop()
	c = dialSessionV2(t, s, nil)
	attachV2(t, c.client)
	bad := o.State
	bad.Deadline = bad.Deadline.Add(time.Nanosecond)
	if c.client.RecoverScoped(ctx, bad) == nil || engine.Current() != b.Hash || !g.Status().Deadline.Equal(o.State.Deadline) {
		t.Fatal("wrong deadline consumed lease")
	}
	c.stop()
	c = dialSessionV2(t, s, nil)
	defer c.stop()
	observed := attachV2(t, c.client)
	if !observed.State.Deadline.Equal(o.State.Deadline) || c.client.RecoverScoped(ctx, observed.State) != nil || engine.Current() != a.Hash || g.Status().Phase != "idle" {
		t.Fatal("scoped recovery")
	}
}
func TestScopedIPCV2ReplacementLeaseIntact(t *testing.T) {
	for _, sameID := range []bool{false, true} {
		t.Run(map[bool]string{false: "foreign-id", true: "same-id-new-deadline"}[sameID], func(t *testing.T) {
			s, g, engine, a, b := fixtureSessionV2(t)
			ctx := context.Background()
			c := initializeV2(t, s, a)
			defer c.stop()
			if c.client.Arm(ctx, "lease", a, b, 2*time.Second) != nil || c.client.Apply(ctx, b) != nil {
				t.Fatal("fixture")
			}
			old, _ := c.client.State(ctx)
			if g.RecoverLease(old.ID, old.Previous, old.Target, old.Deadline) != nil {
				t.Fatal("test-controlled replacement")
			}
			id := "foreign"
			if sameID {
				id = "lease"
			}
			if g.Arm(id, a, b, 3*time.Second) != nil || g.Apply(ctx, b) != nil {
				t.Fatal("replacement")
			}
			replacement := g.Status()
			if c.client.RecoverScoped(ctx, old) == nil || engine.Current() != b.Hash || g.Status().ID != id || !g.Status().Deadline.Equal(replacement.Deadline) {
				t.Fatal("stale observer recovered replacement")
			}
		})
	}
}

type lostReplyV2 struct{ *net.UnixConn }

func (c lostReplyV2) Write(b []byte) (int, error) {
	var r firewallipc.ReplyV2
	if json.Unmarshal(b, &r) == nil && r.Verb == "recover_scoped" && r.Error == "" {
		_ = c.Close()
		return len(b), nil
	}
	return c.UnixConn.Write(b)
}
func TestScopedIPCV2LostRecoveryReplyIsUncertain(t *testing.T) {
	s, g, engine, a, b := fixtureSessionV2(t)
	ctx := context.Background()
	c := initializeV2(t, s, a)
	if c.client.Arm(ctx, "lease", a, b, 2*time.Second) != nil || c.client.Apply(ctx, b) != nil {
		t.Fatal("fixture")
	}
	c.stop()
	c = dialSessionV2(t, s, func(c *net.UnixConn) io.ReadWriteCloser { return lostReplyV2{c} })
	o := attachV2(t, c.client)
	if c.client.RecoverScoped(ctx, o.State) == nil || engine.Current() != a.Hash || g.Status().Phase != "idle" {
		t.Fatal("lost reply fabricated result")
	}
	if _, e := c.client.State(ctx); e == nil {
		t.Fatal("dead channel reused")
	}
	c.stop()
	c = dialSessionV2(t, s, nil)
	defer c.stop()
	observed := attachV2(t, c.client)
	if observed.Hash != a.Hash || observed.State.Phase != "idle" {
		t.Fatal("reconnect did not observe actual compensation")
	}
}
func TestScopedIPCV2ShortExistingLeaseRebind(t *testing.T) {
	s, g, _, a, b := fixtureSessionV2(t)
	ctx := context.Background()
	c := initializeV2(t, s, a)
	if c.client.Arm(ctx, "short", a, b, 800*time.Millisecond) != nil {
		t.Fatal("arm")
	}
	old, _ := c.client.State(ctx)
	c.stop()
	time.Sleep(450 * time.Millisecond)
	c = dialSessionV2(t, s, nil)
	defer c.stop()
	attachV2(t, c.client)
	guard, e := firewalladmin.NewPreparedGuardedEngine(c.client, firewallipc.AuthorityV2{Client: c.client}, c.client.RecoverScoped)
	if e != nil {
		t.Fatal(e)
	}
	if e = guard.Arm(ctx, "short", a, b, time.Until(old.Deadline)); e != nil {
		t.Fatal(e)
	}
	if !g.Status().Deadline.Equal(old.Deadline) {
		t.Fatal("rebind extended deadline")
	}
}
func TestScopedIPCV2PeerAndProtocolFailures(t *testing.T) {
	s, _, engine, _, _ := fixtureSessionV2(t)
	a, b := socketpairV2(t)
	defer b.Close()
	if _, e := ConnectInheritedV2(context.Background(), a, uint32(os.Getuid()), uint32(os.Getgid()), int32(os.Getpid()+1), strings.Repeat("a", 32), 42, "firewall", artifactDigest); e == nil {
		t.Fatal("foreign peer")
	}
	a, b = socketpairV2(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeV2(ctx, b, strings.Repeat("a", 32)) }()
	_ = json.NewEncoder(a).Encode(hello{Version: 1, RuntimeRun: strings.Repeat("a", 32), Namespace: 42})
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	var out [1]byte
	if n, _ := a.Read(out[:]); n != 0 {
		t.Fatal("v1 handshake accepted")
	}
	_ = a.Close()
	<-done
	if engine.Current() != "" {
		t.Fatal("protocol mismatch had effect")
	}
}
