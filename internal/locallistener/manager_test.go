package locallistener

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

type testServer struct {
	mu       sync.Mutex
	listener net.Listener
	stopped  bool
	drain    <-chan struct{}
	closeErr error
}

func (s *testServer) Serve(l net.Listener) error {
	s.mu.Lock()
	s.listener = l
	if s.stopped {
		_ = l.Close()
	}
	s.mu.Unlock()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		_ = c.Close()
	}
}
func (s *testServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
}
func (s *testServer) Close() error {
	s.Stop()
	if s.drain != nil {
		<-s.drain
	}
	return s.closeErr
}

func TestRetirementErrorBlocksObservationAndSurvivesClose(t *testing.T) {
	inventory, port := fixture(t)
	m, err := New(inventory, func(localpolicy.Listener, string) (Server, error) {
		return &testServer{closeErr: errors.New("close failed")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Apply(context.Background(), policy(t, inventory, port, true)); err != nil {
		t.Fatal(err)
	}
	if err = m.Apply(context.Background(), policy(t, inventory, port, false)); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	retired := append([]*retirement(nil), m.retired...)
	m.mu.Unlock()
	for _, r := range retired {
		<-r.done
	}
	if _, err = m.Registry(); !errors.Is(err, ErrListener) {
		t.Fatalf("failed retirement reported available: %v", err)
	}
	if err = m.Apply(context.Background(), policy(t, inventory, port, true)); !errors.Is(err, ErrListener) {
		t.Fatalf("failed lifecycle accepted activation: %v", err)
	}
	for range 2 {
		if err = m.Close(); !errors.Is(err, ErrListener) {
			t.Fatalf("lost close failure: %v", err)
		}
	}
}

func fixture(t *testing.T) ([]localpolicy.Interface, uint16) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("actual interface inventory test runs on Linux")
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return []localpolicy.Interface{{Name: "lo", Zone: localpolicy.LAN, Addresses: []string{"127.0.0.1"}}}, port
}
func policy(t *testing.T, inventory []localpolicy.Interface, port uint16, enabled bool) configpoc.Revision {
	t.Helper()
	s, err := localpolicy.DefaultManagement("management", "https", inventory[0], "127.0.0.1", []string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	s.Enabled = enabled
	s.Endpoints = []localpolicy.Endpoint{{Protocol: localpolicy.TCP, FirstPort: port, LastPort: port}}
	c := localpolicy.Config{SchemaVersion: 1, Interfaces: inventory, Services: []localpolicy.Service{s}}
	r, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &c})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRevocationDoesNotWaitForItsOwnCommand(t *testing.T) {
	inventory, port := fixture(t)
	commandReturned := make(chan struct{})
	m, err := New(inventory, func(_ localpolicy.Listener, hash string) (Server, error) {
		if len(hash) != 64 {
			t.Error("missing immutable activation hash")
		}
		return &testServer{drain: commandReturned}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	active := policy(t, inventory, port, true)
	if err = m.Apply(context.Background(), active); err != nil {
		t.Fatal(err)
	}
	registry, err := m.Registry()
	if err != nil || len(registry.Bindings) != 1 || registry.Hash != active.Hash {
		t.Fatal(registry, err)
	}
	done := make(chan error, 1)
	disabled := policy(t, inventory, port, false)
	go func() { done <- m.Apply(context.Background(), disabled) }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(commandReturned)
		t.Fatal("activation waited for originating command")
	}
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
	if err == nil {
		_ = c.Close()
		t.Error("retired listener still accepts connections")
	}
	registry, err = m.Registry()
	if err != nil || len(registry.Bindings) != 0 {
		t.Fatal(registry, err)
	}
	close(commandReturned)
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedReplacementClosesPartialListeners(t *testing.T) {
	inventory, port := fixture(t)
	m, err := New(inventory, func(localpolicy.Listener, string) (Server, error) { return &testServer{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if err = m.Apply(context.Background(), policy(t, inventory, port, true)); err != nil {
		t.Fatal(err)
	}
	target := policy(t, inventory, uint16(occupied.Addr().(*net.TCPAddr).Port), true)
	if m.Apply(context.Background(), target) == nil {
		t.Fatal("occupied port accepted")
	}
	if _, err = m.Registry(); err == nil {
		t.Fatal("failed activation reported verified")
	}
	if err = m.Apply(context.Background(), policy(t, inventory, port, true)); err != nil {
		t.Fatal("compensation failed", err)
	}
}

func TestInventoryAndRevisionCannotBeCallerSelected(t *testing.T) {
	inventory, port := fixture(t)
	calls := 0
	m, err := New(inventory, func(localpolicy.Listener, string) (Server, error) { calls++; return &testServer{}, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r := policy(t, inventory, port, true)
	r.Hash = "invalid"
	if m.Apply(context.Background(), r) == nil || calls != 0 {
		t.Fatal("hash bypass")
	}
	r = policy(t, inventory, port, true)
	r.Config.LocalServices.Interfaces[0].Name = "foreign"
	if m.Apply(context.Background(), r) == nil || calls != 0 {
		t.Fatal("inventory bypass")
	}
}
