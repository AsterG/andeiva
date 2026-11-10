package localobserve

import (
	"errors"
	"net"
	"os"
	"path/filepath"
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

func TestRealAcceptedTCPChurnDoesNotChangeListenerObservation(t *testing.T) {
	c := selfCollector(t)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	readListenerCapture := func() capture {
		t.Helper()
		captured, err := c.readCapture()
		if err != nil {
			t.Fatal(err)
		}
		// Other test binaries share this network namespace and may change its
		// foreign listeners. Scope this test's table to its own exact listener,
		// retaining every real FD and identity check. Production observations
		// still compare the complete table, including foreign listener changes.
		listeners := []Socket{}
		for _, socket := range captured.sockets {
			if socket.Protocol == "tcp" && socket.Family == "ipv4" && socket.Address == "127.0.0.1" && int(socket.Port) == port {
				listeners = append(listeners, socket)
			}
		}
		if len(listeners) != 1 {
			t.Fatalf("expected one test listener, got %d", len(listeners))
		}
		captured.sockets = listeners
		return captured
	}
	first := readListenerCapture()
	client, err := net.DialTimeout("tcp4", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := l.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	second := readListenerCapture()
	if len(second.fds) <= len(first.fds) {
		t.Fatal("test did not create additional connected sockets")
	}
	got, err := verifyStable(first, second, c.expected, c.start)
	if err != nil {
		t.Fatal("accepted TCP connection invalidated listener capture", err)
	}
	found := false
	for _, socket := range got.Sockets {
		found = found || socket.Protocol == "tcp" && socket.Address == "127.0.0.1" && int(socket.Port) == port
	}
	if !found {
		t.Fatal("real listener missing from observation")
	}
	_ = client.Close()
	_ = accepted.Close()
	third := readListenerCapture()
	if _, err := verifyStable(second, third, c.expected, c.start); err != nil {
		t.Fatal("connection closure invalidated listener capture", err)
	}
}

func TestEnumeratedFDDisappearanceRemainsUnowned(t *testing.T) {
	dir := t.TempDir()
	for _, fd := range []string{"4", "8"} {
		if err := os.Symlink("socket:[77]", filepath.Join(dir, fd)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, lost := range []string{"fd/8", "fd/4"} {
		fds, err := readSocketFDs(entries, func(path string) (string, error) {
			if path == lost {
				return "", &os.PathError{Op: "readlink", Path: path, Err: os.ErrNotExist}
			}
			if path == "fd/4" {
				return "socket:[77]", nil
			}
			return "socket:[888]", nil
		})
		if err != nil || len(fds) != 1 {
			t.Fatal("transient descriptor disappearance", fds, err)
		}
		first, second := baseCapture(), baseCapture()
		second.fds = fds
		got, err := verifyStable(first, second, expected(), 99)
		if lost == "fd/8" {
			if err != nil || len(got.Sockets) != 1 {
				t.Fatal("unrelated descriptor closure invalidated listener", got, err)
			}
		} else {
			if !errors.Is(err, ErrUnstable) {
				t.Fatal("lost listener descriptor not detected", err)
			}
			first.fds = fds
			got, err = verifyStable(first, second, expected(), 99)
			if err != nil || len(got.Foreign) != 1 || len(got.Sockets) != 0 {
				t.Fatal("missing listener ownership was invented", got, err)
			}
		}
	}
	for _, readErr := range []error{os.ErrPermission, errors.New("readlink I/O failure")} {
		if _, err := readSocketFDs(entries, func(string) (string, error) { return "", readErr }); !errors.Is(err, ErrUnstable) {
			t.Fatal("non-ENOENT read failure ignored", err)
		}
	}
	if _, err := readSocketFDs(entries, func(string) (string, error) { return "socket:[invalid]", nil }); !errors.Is(err, ErrMalformed) {
		t.Fatal("malformed descriptor ignored", err)
	}
}
