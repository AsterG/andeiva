package localchannel

import (
	"context"
	"net/netip"
	"sync"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

// Listeners joins two independently scoped sources. The worker's declaration
// alone cannot establish effective state; the retained-process collector must
// observe exactly those sockets under the pinned API identity.
type Listeners struct {
	mu                sync.Mutex
	worker, collector *Client
	target            *configpoc.Revision
}

func NewListeners(worker, collector *Client) (*Listeners, error) {
	if worker == nil || collector == nil || worker == collector || worker.observer || !collector.observer || worker.binding != collector.binding {
		return nil, ErrChannel
	}
	return &Listeners{worker: worker, collector: collector}, nil
}

func (l *Listeners) Apply(ctx context.Context, revision configpoc.Revision) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, err := configpoc.Canonical(revision.Config)
	if err != nil || r.Hash != revision.Hash {
		return ErrChannel
	}
	l.target = nil
	if err = l.worker.Apply(ctx, r); err != nil {
		return err
	}
	l.target = &r
	return nil
}

func (l *Listeners) Observe(ctx context.Context) ([]localpolicy.Listener, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.target == nil {
		return nil, ErrChannel
	}
	registry, err := l.worker.Registry(ctx)
	if err != nil || registry.Hash != l.target.Hash {
		return nil, ErrChannel
	}
	kernel, err := l.collector.Observe(ctx)
	if err != nil {
		return nil, ErrChannel
	}
	// A second registry query rejects a listener change spanning kernel capture.
	again, err := l.worker.Registry(ctx)
	if err != nil || again.Hash != registry.Hash || len(again.Bindings) != len(registry.Bindings) {
		return nil, ErrChannel
	}
	for i := range registry.Bindings {
		if again.Bindings[i] != registry.Bindings[i] {
			return nil, ErrChannel
		}
	}
	if len(kernel.Sockets) != len(registry.Bindings) {
		return nil, ErrChannel
	}
	type endpoint struct {
		address string
		port    uint16
	}
	expected := map[endpoint]localpolicy.Listener{}
	for _, binding := range registry.Bindings {
		key := endpoint{binding.LocalAddress, binding.Port}
		if binding.Protocol != localpolicy.TCP || expected[key].Service != "" {
			return nil, ErrChannel
		}
		expected[key] = binding
	}
	seen := map[endpoint]bool{}
	inodes := map[uint64]bool{}
	for _, socket := range kernel.Sockets {
		address, err := netip.ParseAddr(socket.Address)
		if err != nil || address.String() != socket.Address || address.IsUnspecified() || address.Is4In6() || socket.Wildcard || socket.Mapped || socket.Inode == 0 || inodes[socket.Inode] || socket.UID != l.worker.binding.UID || socket.Protocol != "tcp" {
			return nil, ErrChannel
		}
		family := "ipv6"
		if address.Is4() {
			family = "ipv4"
		}
		if socket.Family != family {
			return nil, ErrChannel
		}
		key := endpoint{socket.Address, socket.Port}
		if _, ok := expected[key]; !ok || seen[key] {
			return nil, ErrChannel
		}
		seen[key], inodes[socket.Inode] = true, true
	}
	if l.target.Config.LocalServices == nil {
		if len(registry.Bindings) != 0 {
			return nil, ErrChannel
		}
	} else {
		artifact, err := localpolicy.Compile(*l.target.Config.LocalServices)
		if err != nil {
			return nil, ErrChannel
		}
		comparison, err := localpolicy.Reconcile(*l.target.Config.LocalServices, localpolicy.Observation{Revision: artifact.Revision.Hash, Rules: artifact.Rules, Listeners: registry.Bindings})
		if err != nil || !comparison.Consistent {
			return nil, ErrChannel
		}
	}
	return append([]localpolicy.Listener{}, registry.Bindings...), nil
}
