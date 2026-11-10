// Package locallistener owns unprivileged managed protocol listeners.
package locallistener

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

var ErrListener = errors.New("ANDEIVA_LOCAL_LISTENER_UNAVAILABLE")

// Stop revokes network access without joining a command that may itself be
// applying this change. Close joins workers only outside the activation callback.
type Server interface {
	Serve(net.Listener) error
	Stop()
	Close() error
}

// Factory binds the immutable envelope hash into the actual protocol handler.
// It must never infer that hash from a later global current revision.
type Factory func(localpolicy.Listener, string) (Server, error)

type entry struct {
	binding  localpolicy.Listener
	server   Server
	listener net.Listener
	done     chan struct{}
}

type retirement struct {
	done chan struct{}
	err  error // Published by closing done; read only after that barrier.
}

type Registry struct {
	Hash     string                 `json:"hash"`
	Bindings []localpolicy.Listener `json:"bindings"`
	Draining int                    `json:"draining"`
}

// Registry describes this process's active servers. An independent supervisor
// must still correlate their real socket inodes/ownership with kernel tables.
type Manager struct {
	mu        sync.Mutex
	inventory []localpolicy.Interface
	factory   Factory
	active    []*entry
	retired   []*retirement
	hash      string
	closed    bool
	failed    bool
}

func New(inventory []localpolicy.Interface, factory Factory) (*Manager, error) {
	if factory == nil || len(inventory) == 0 || len(inventory) > 2 {
		return nil, ErrListener
	}
	c, err := localpolicy.Canonical(localpolicy.Config{SchemaVersion: 1, Interfaces: inventory})
	if err != nil {
		return nil, ErrListener
	}
	return &Manager{inventory: c.Config.Interfaces, factory: factory}, nil
}

func (m *Manager) plan(r configpoc.Revision) ([]localpolicy.Listener, error) {
	c, err := configpoc.Canonical(r.Config)
	if err != nil || c.Hash != r.Hash || c.Config.DefaultAction != "deny" || len(c.Config.Rules) != 0 {
		return nil, ErrListener
	}
	if c.Config.LocalServices == nil {
		return []localpolicy.Listener{}, nil
	}
	l := *c.Config.LocalServices
	if localnft.ValidateManaged(l) != nil {
		return nil, ErrListener
	}
	a, _ := json.Marshal(l.Interfaces)
	b, _ := json.Marshal(m.inventory)
	if string(a) != string(b) {
		return nil, ErrListener
	}
	bindings := []localpolicy.Listener{}
	for _, s := range l.Services {
		if s.Owner != "management" || s.ID != "https" && s.ID != "ssh" || s.ID == "https" && s.Kind != localpolicy.ManagementHTTPS || s.ID == "ssh" && s.Kind != localpolicy.ManagementSSH {
			return nil, ErrListener
		}
		if !s.Enabled {
			continue
		}
		for _, b := range s.Bindings {
			bindings = append(bindings, localpolicy.Listener{Owner: s.Owner, Service: s.ID, Interface: b.Interface, LocalAddress: b.LocalAddress, Protocol: localpolicy.TCP, Port: s.Endpoints[0].FirstPort})
		}
	}
	return bindings, nil
}

func actualAddress(binding localpolicy.Listener) error {
	iface, err := net.InterfaceByName(binding.Interface)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return ErrListener
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return ErrListener
	}
	want, err := netip.ParseAddr(binding.LocalAddress)
	if err != nil {
		return ErrListener
	}
	for _, address := range addresses {
		p, err := netip.ParsePrefix(address.String())
		if err == nil && p.Addr() == want {
			return nil
		}
	}
	return ErrListener
}

func (m *Manager) reap() {
	alive := m.retired[:0]
	for _, retired := range m.retired {
		select {
		case <-retired.done:
			m.failed = m.failed || retired.err != nil
		default:
			alive = append(alive, retired)
		}
	}
	m.retired = alive
}

func (m *Manager) retireActive() {
	for _, e := range m.active {
		e.server.Stop()
		closeErr := e.listener.Close()
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			m.failed = true
		}
		joined := &retirement{done: make(chan struct{})}
		m.retired = append(m.retired, joined)
		go func() { joined.err = e.server.Close(); <-e.done; close(joined.done) }()
	}
	m.active = nil
	m.hash = ""
}

func (m *Manager) Apply(ctx context.Context, r configpoc.Revision) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || ctx.Err() != nil {
		return ErrListener
	}
	bindings, err := m.plan(r)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if actualAddress(binding) != nil {
			return ErrListener
		}
	}
	m.reap()
	if m.failed {
		return ErrListener
	}
	if m.hash == r.Hash {
		for _, e := range m.active {
			select {
			case <-e.done:
				return ErrListener
			default:
			}
		}
		return nil
	}
	// Bound outstanding revoked workers even under rapid repeated activation.
	if len(m.retired)+len(m.active)+len(bindings) > 16 {
		return ErrListener
	}
	m.retireActive()
	fail := func() error { m.retireActive(); return ErrListener }
	for _, binding := range bindings {
		if ctx.Err() != nil {
			return fail()
		}
		server, err := m.factory(binding, r.Hash)
		if err != nil || server == nil {
			return fail()
		}
		family := "tcp6"
		if netip.MustParseAddr(binding.LocalAddress).Is4() {
			family = "tcp4"
		}
		var lc net.ListenConfig
		listener, err := lc.Listen(ctx, family, net.JoinHostPort(binding.LocalAddress, strconv.Itoa(int(binding.Port))))
		if err != nil {
			server.Stop()
			if server.Close() != nil {
				m.failed = true
			}
			return fail()
		}
		e := &entry{binding: binding, server: server, listener: listener, done: make(chan struct{})}
		m.active = append(m.active, e)
		go func() { defer close(e.done); defer e.listener.Close(); _ = e.server.Serve(e.listener) }()
	}
	m.hash = r.Hash
	return nil
}

func (m *Manager) Registry() (Registry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.hash == "" {
		return Registry{}, ErrListener
	}
	m.reap()
	if m.failed {
		return Registry{}, ErrListener
	}
	result := Registry{Hash: m.hash, Bindings: []localpolicy.Listener{}, Draining: len(m.retired)}
	for _, e := range m.active {
		select {
		case <-e.done:
			return Registry{}, ErrListener
		default:
		}
		result.Bindings = append(result.Bindings, e.binding)
	}
	return result, nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	m.closed = true
	m.retireActive()
	drains := append([]*retirement(nil), m.retired...)
	m.mu.Unlock()
	for _, retired := range drains {
		<-retired.done
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reap()
	if m.failed {
		return ErrListener
	}
	return nil
}
