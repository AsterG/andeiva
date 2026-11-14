package previewruntime

import (
	"context"
	"net/netip"
	"sync"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routedactivation"
)

type routedNetworkDriverV4 interface {
	routedactivation.Network
	PrepareObserved(context.Context, []networkplan.Binding) (networkexecutor.ObservedSnapshot, error)
	VerifyObserved(context.Context, networkexecutor.ObservedSnapshot) error
	RecoverObserved(context.Context, networkexecutor.ObservedSnapshot, networkexecutor.OwnedNamespaceIdentity) error
	RecoverPrepared(context.Context, networkplan.Revision, networkexecutor.PreparedSnapshot, networkexecutor.OwnedNamespaceIdentity) error
	Close() error
}
type routedNetworkFactoryV4 func(context.Context, *networkplan.Revision) (routedNetworkDriverV4, *networkexecutor.LANBootstrapV3, error)

// A selector owns exactly one namespace writer. Preparing a different profile
// closes only an inactive, independently verified empty driver; it never runs
// DHCP or modifies L3. Configured plans remain pinned to one exact desired hash.
type routedNetworkSelectorV4 struct {
	mu             sync.Mutex
	factory        routedNetworkFactoryV4
	driver         routedNetworkDriverV4
	lan            *networkexecutor.LANBootstrapV3
	bindings       []networkplan.Binding
	desired        networkplan.Revision
	prepared       networkexecutor.PreparedSnapshot
	active, closed bool
	closeErr       error
	beforeRestore  func(context.Context) error
}

func routedNetworkProfileV4(input networkplan.Revision) (networkplan.Revision, bool, error) {
	r, err := networkplan.Canonical(input.Config)
	if err != nil || r.Hash != input.Hash || len(r.Config.Interfaces) != 2 || r.Config.DNS.Mode != "none" {
		return networkplan.Revision{}, false, ErrIdentity
	}
	if _, err = networkexecutor.CanonicalLANBootstrapPlanV3(r); err == nil {
		return r, true, nil
	}
	for _, i := range r.Config.Interfaces {
		if i.IPv4.Mode != "static" {
			return networkplan.Revision{}, false, ErrIdentity
		}
		p, e := netip.ParsePrefix(i.IPv4.Address)
		if e != nil || p.Bits() > 30 {
			return networkplan.Revision{}, false, ErrIdentity
		}
	}
	return r, false, nil
}
func newRoutedNetworkSelectorV4(ctx context.Context, bindings []networkplan.Binding, factory routedNetworkFactoryV4) (*routedNetworkSelectorV4, error) {
	if ctx == nil || ctx.Err() != nil || len(bindings) != 2 || factory == nil {
		return nil, ErrIdentity
	}
	d, lan, err := factory(ctx, nil)
	if err != nil {
		return nil, err
	}
	if d == nil || lan != nil {
		if d != nil {
			_ = d.Close()
		}
		return nil, ErrIdentity
	}
	return &routedNetworkSelectorV4{factory: factory, driver: d, bindings: append([]networkplan.Binding(nil), bindings...)}, nil
}
func (s *routedNetworkSelectorV4) selectDriver(ctx context.Context, r networkplan.Revision, dhcp bool) error {
	if s.closed || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if s.active {
		return ErrIdentity
	}
	if s.desired.Hash == r.Hash && s.driver != nil {
		return nil
	}
	if s.driver != nil {
		if _, err := s.driver.PrepareObserved(ctx, s.bindings); err != nil {
			return err
		}
		// The initial static observer already supplies the static profile.
		if !dhcp && s.lan == nil {
			s.desired = r
			s.prepared = networkexecutor.PreparedSnapshot{}
			return nil
		}
		if err := s.driver.Close(); err != nil {
			return err
		}
		s.driver, s.lan = nil, nil
	}
	d, lan, err := s.factory(ctx, &r)
	if err != nil {
		return err
	}
	if d == nil || dhcp != (lan != nil) {
		if d != nil {
			_ = d.Close()
		}
		return ErrIdentity
	}
	s.driver, s.lan, s.desired, s.prepared = d, lan, r, networkexecutor.PreparedSnapshot{}
	return nil
}
func (s *routedNetworkSelectorV4) Prepare(ctx context.Context, input networkplan.Revision) (networkexecutor.PreparedSnapshot, error) {
	r, dhcp, err := routedNetworkProfileV4(input)
	if err != nil {
		return networkexecutor.PreparedSnapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.selectDriver(ctx, r, dhcp); err != nil {
		return networkexecutor.PreparedSnapshot{}, err
	}
	p, err := s.driver.Prepare(ctx, r)
	if err == nil {
		s.prepared = p
	}
	return p, err
}
func (s *routedNetworkSelectorV4) VerifyPrepared(ctx context.Context, p networkexecutor.PreparedSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.driver == nil || s.desired.Hash != p.PlanHash {
		return ErrIdentity
	}
	return s.driver.VerifyPrepared(ctx, p)
}
func (s *routedNetworkSelectorV4) ApplyPrepared(ctx context.Context, r networkplan.Revision, p networkexecutor.PreparedSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.driver == nil || s.active || r.Hash != s.desired.Hash || p.PlanHash != s.desired.Hash || p.Hash != s.prepared.Hash {
		return ErrIdentity
	}
	s.active = true // Even a partial/uncertain effect must use exact compensation.
	return s.driver.ApplyPrepared(ctx, r, p)
}
func (s *routedNetworkSelectorV4) RestorePrepared(ctx context.Context, p networkexecutor.PreparedSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.driver == nil || p.PlanHash != s.desired.Hash || p.Hash != s.prepared.Hash {
		return ErrIdentity
	}
	if s.beforeRestore != nil {
		if err := s.beforeRestore(ctx); err != nil {
			return err
		}
	}
	if err := s.driver.RestorePrepared(ctx, p); err != nil {
		return err
	}
	s.active = false
	return nil
}
func (s *routedNetworkSelectorV4) Verify(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.driver == nil || !s.active {
		return ErrIdentity
	}
	return s.driver.Verify(ctx)
}
func (s *routedNetworkSelectorV4) PrepareObserved(ctx context.Context, bindings []networkplan.Binding) (networkexecutor.ObservedSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.driver == nil || s.active {
		return networkexecutor.ObservedSnapshot{}, ErrIdentity
	}
	return s.driver.PrepareObserved(ctx, bindings)
}
func (s *routedNetworkSelectorV4) VerifyObserved(ctx context.Context, p networkexecutor.ObservedSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.driver == nil || s.active {
		return ErrIdentity
	}
	return s.driver.VerifyObserved(ctx, p)
}
func (s *routedNetworkSelectorV4) RecoverObserved(ctx context.Context, p networkexecutor.ObservedSnapshot, id networkexecutor.OwnedNamespaceIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.driver == nil || s.active {
		return ErrIdentity
	}
	return s.driver.RecoverObserved(ctx, p, id)
}
func (s *routedNetworkSelectorV4) RecoverPrepared(ctx context.Context, input networkplan.Revision, p networkexecutor.PreparedSnapshot, id networkexecutor.OwnedNamespaceIdentity) error {
	r, dhcp, err := routedNetworkProfileV4(input)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active || p.PlanHash != r.Hash {
		return ErrIdentity
	}
	// Recovery must reconstruct through the authenticated selected memento,
	// never require an empty readback or adopt whatever is currently present.
	if s.desired.Hash != r.Hash || s.driver == nil {
		if s.driver != nil {
			if err = s.driver.Close(); err != nil {
				return err
			}
			s.driver, s.lan = nil, nil
		}
		d, lan, e := s.factory(ctx, &r)
		if e != nil {
			return e
		}
		if d == nil || dhcp != (lan != nil) {
			if d != nil {
				_ = d.Close()
			}
			return ErrIdentity
		}
		s.driver, s.lan, s.desired = d, lan, r
	}
	if s.driver == nil {
		return ErrUnavailable
	}
	s.active = true
	s.prepared = p
	if err = s.driver.RecoverPrepared(ctx, r, p, id); err != nil {
		return err
	}
	// RecoverPrepared can reconstruct either selected baseline or target. The
	// target check establishes whether Verify or baseline verification applies.
	if s.driver.Verify(ctx) == nil {
		return nil
	}
	if s.driver.VerifyPrepared(ctx, p) == nil {
		s.active = false
		return nil
	}
	return ErrUnavailable
}
func (s *routedNetworkSelectorV4) DHCP() (networkplan.Revision, *networkexecutor.LANBootstrapV3, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.active || s.lan == nil {
		return networkplan.Revision{}, nil, ErrUnavailable
	}
	r, _, err := routedNetworkProfileV4(s.desired)
	return r, s.lan, err
}

// The callback cannot call Authority or reenter the selector. Retaining this
// lock excludes rollback while root independently selects and activates DHCP.
func (s *routedNetworkSelectorV4) withDHCP(ctx context.Context, call func(networkplan.Revision, *networkexecutor.LANBootstrapV3) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || !s.active || s.lan == nil || s.driver == nil || s.driver.Verify(ctx) != nil {
		return ErrUnavailable
	}
	return call(s.desired, s.lan)
}
func (s *routedNetworkSelectorV4) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.driver != nil {
		s.closeErr = s.driver.Close()
	}
	return s.closeErr
}
