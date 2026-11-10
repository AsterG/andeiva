package localobserve

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This test reads only this test process. It constructs the private collector
// directly; production New still requires a distinct owned child and namespace.
func selfCollector(t *testing.T) *Collector {
	t.Helper()
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	root, err := proc.OpenRoot(strconv.Itoa(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{root: root}
	c.process, err = os.FindProcess(os.Getpid())
	if err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	identity, err := c.readIdentity()
	if err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	c.pid, c.parent, c.start = identity.pid, identity.parent, identity.start
	c.expected = Expected{UID: identity.uid[0], GID: identity.gid[0], Namespace: identity.namespace, RunID: strings.Repeat("a", 32), Instance: strings.Repeat("b", 32), Generation: 1}
	t.Cleanup(func() { _ = c.Close(); _ = c.process.Release() })
	return c
}

func TestRealOwnProcessDescriptorsAndLoopbackSocketTables(t *testing.T) {
	c := selfCollector(t)
	listeners := []net.Listener{}
	packets := []net.PacketConn{}
	for _, family := range []string{"4", "6"} {
		address := "127.0.0.1:0"
		if family == "6" {
			address = "[::1]:0"
		}
		l, err := net.Listen("tcp"+family, address)
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, l)
		defer l.Close()
		p, err := net.ListenPacket("udp"+family, address)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, p)
		defer p.Close()
	}
	captured, err := c.readCapture()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := correlate(captured, c.expected, c.start)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range listeners {
		tcp := l.Addr().(*net.TCPAddr)
		udp := packets[i].LocalAddr().(*net.UDPAddr)
		for _, wanted := range []struct {
			protocol, address string
			port              int
		}{{"tcp", tcp.IP.String(), tcp.Port}, {"udp", udp.IP.String(), udp.Port}} {
			found := false
			for _, s := range snapshot.Sockets {
				if s.Protocol == wanted.protocol && s.Address == wanted.address && int(s.Port) == wanted.port {
					found = true
					if s.Inode == 0 || s.UID != c.expected.UID {
						t.Fatal("unattributed real socket", s)
					}
				}
			}
			if !found {
				t.Fatalf("real socket absent: %+v in %+v", wanted, snapshot.Sockets)
			}
		}
	}
	// Close real listeners and verify their inodes no longer remain listeners.
	for _, l := range listeners {
		_ = l.Close()
	}
	for _, p := range packets {
		_ = p.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		after, err := c.readCapture()
		if err != nil {
			t.Fatal(err)
		}
		remaining := false
		for _, old := range snapshot.Sockets {
			for _, now := range after.sockets {
				if old.Inode == now.Inode {
					remaining = true
				}
			}
		}
		if !remaining {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed sockets remain in kernel table")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRetainedRootIdentityAndClosureFailClosed(t *testing.T) {
	c := selfCollector(t)
	identity, err := c.readIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*processIdentity){func(p *processIdentity) { p.pid++ }, func(p *processIdentity) { p.parent++ }, func(p *processIdentity) { p.start++ }, func(p *processIdentity) { p.namespace++ }, func(p *processIdentity) { p.uid[3]++ }, func(p *processIdentity) { p.gid[0]++ }} {
		bad := identity
		change(&bad)
		if c.validateIdentity(bad) == nil {
			t.Fatal("changed identity accepted")
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Observe(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed collector", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProductionConstructorRejectsSelfHostAndInvalidInputs(t *testing.T) {
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release()
	link, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := namespaceID(link)
	if err != nil {
		t.Fatal(err)
	}
	expect := expected()
	expect.HostNamespace = host
	expect.Namespace = host
	if _, err := New(p, expect); err == nil {
		t.Fatal("host namespace admitted")
	}
	expect.Namespace = host + 1
	if _, err := New(p, expect); err == nil {
		t.Fatal("current process admitted as owned child")
	}
	if _, err := New(nil, expect); err == nil {
		t.Fatal("nil process")
	}
}

func TestObserveAndCloseAreSerialized(t *testing.T) {
	c := selfCollector(t)
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			_, err := c.Observe()
			if err != nil && !errors.Is(err, ErrClosed) && !errors.Is(err, ErrUnstable) {
				t.Error(err)
			}
		})
	}
	wg.Go(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	wg.Wait()
}
