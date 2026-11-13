package networkexecutor

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"sync"

	"github.com/AsterG/andeiva/internal/networkplan"
)

// LANBootstrapV3 is a separate DHCP profile. PreparedSnapshot still means an
// exactly empty IPv4 baseline; the static Executor contract remains unchanged.
// Its caller must hold selected Boot/R2 authority and a closed forwarding gate.
type LANBootstrapV3 struct {
	mu               sync.Mutex
	base             *Executor
	desired          networkplan.Revision
	lan              networkplan.Interface
	prepared         PreparedSnapshot
	lease            *LeaseExecutor
	now              func() (int64, error)
	closedForwarding func() error
}

func CanonicalLANBootstrapPlanV3(input networkplan.Revision) (networkplan.Revision, error) {
	r, err := networkplan.Canonical(input.Config)
	if err != nil || r.Hash != input.Hash || len(r.Config.Interfaces) != 2 || r.Config.DNS.Mode != "none" {
		return networkplan.Revision{}, ErrUnsupported
	}
	lan, wan := false, false
	for _, i := range r.Config.Interfaces {
		switch {
		case i.Role == networkplan.LAN && i.IPv4.Mode == "static" && netip.MustParsePrefix(i.IPv4.Address).Bits() <= 30:
			lan = true
		case i.Role == networkplan.WAN && i.IPv4.Mode == "dhcp" && r.Config.DefaultRoute.InterfaceID == i.ID:
			wan = true
		default:
			return networkplan.Revision{}, ErrUnsupported
		}
	}
	if !lan || !wan {
		return networkplan.Revision{}, ErrUnsupported
	}
	return r, nil
}

func newLANBootstrapV3(base *Executor, desired networkplan.Revision, now func() (int64, error), closed func() error) (*LANBootstrapV3, error) {
	r, err := CanonicalLANBootstrapPlanV3(desired)
	if err != nil || base == nil || base.identity == nil || !validOwnedIdentity(*base.identity) || base.active != nil || now == nil || closed == nil || closed() != nil {
		return nil, ErrScope
	}
	b := &LANBootstrapV3{base: base, desired: r, now: now, closedForwarding: closed}
	for _, i := range r.Config.Interfaces {
		if i.Role == networkplan.LAN {
			b.lan = i
		}
	}
	return b, nil
}

func (b *LANBootstrapV3) guard(ctx context.Context) error {
	return (&LeaseExecutor{base: b.base}).guard(ctx)
}

func (b *LANBootstrapV3) Prepare(ctx context.Context, r networkplan.Revision) (PreparedSnapshot, error) {
	if b == nil {
		return PreparedSnapshot{}, ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	canonical, err := CanonicalLANBootstrapPlanV3(r)
	if err != nil || canonical.Hash != b.desired.Hash || b.base.active != nil || b.lease != nil || b.guard(ctx) != nil || b.closedForwarding() != nil {
		return PreparedSnapshot{}, ErrScope
	}
	first, err := b.base.observe(ctx)
	if err != nil {
		return PreparedSnapshot{}, err
	}
	second, err := b.base.observe(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return PreparedSnapshot{}, ErrObservation
	}
	first, err = canonicalEmptyObservation(first)
	if err != nil {
		return PreparedSnapshot{}, err
	}
	if _, err = networkplan.Bind(canonical, first.inventory()); err != nil {
		return PreparedSnapshot{}, ErrScope
	}
	s := PreparedSnapshot{Version: 1, PlanHash: r.Hash, Links: first.Links, Routes: first.Routes}
	raw, _ := json.Marshal(s)
	s.Hash = leaseSelectedDigestV3(raw)
	return CanonicalPreparedSnapshot(s)
}

func (b *LANBootstrapV3) VerifyPrepared(ctx context.Context, s PreparedSnapshot) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.PlanHash != b.desired.Hash || b.guard(ctx) != nil {
		return ErrScope
	}
	return b.base.VerifyPrepared(ctx, s)
}

func (b *LANBootstrapV3) ApplyPrepared(ctx context.Context, r networkplan.Revision, s PreparedSnapshot) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := CanonicalPreparedSnapshot(s)
	canonical, e := CanonicalLANBootstrapPlanV3(r)
	if err != nil || e != nil || canonical.Hash != b.desired.Hash || s.PlanHash != r.Hash || b.base.active != nil || b.lease != nil || b.guard(ctx) != nil || b.closedForwarding() != nil {
		return ErrScope
	}
	if err = b.base.VerifyPrepared(ctx, s); err != nil {
		return err
	}
	projection := networkplan.Revision{Config: networkplan.Config{Interfaces: []networkplan.Interface{b.lan}}}
	op := operation{kind: "address-add", name: b.lan.Binding.Name, address: b.lan.IPv4.Address}
	b.base.active = &transaction{revision: projection, baseline: s.observation(), operations: []operation{op}}
	b.prepared = s
	if _, err = b.base.execute(ctx, op); err != nil {
		return errors.Join(err, b.base.restore())
	}
	actual, err := b.base.observe(ctx)
	if err != nil || !actual.matches(projection, s.observation()) || b.guard(ctx) != nil {
		return errors.Join(ErrObservation, b.base.restore())
	}
	return nil
}

func (b *LANBootstrapV3) Verify(ctx context.Context) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.guard(ctx) != nil || b.base.active == nil {
		return ErrScope
	}
	if b.lease != nil {
		b.lease.mu.Lock()
		active := b.lease.base.active != nil
		b.lease.mu.Unlock()
		if active {
			return b.lease.Verify(ctx)
		}
	}
	return b.base.Verify(ctx)
}

func (b *LANBootstrapV3) RestorePrepared(ctx context.Context, s PreparedSnapshot) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if s.PlanHash != b.desired.Hash || b.lease != nil || b.guard(ctx) != nil || b.closedForwarding() != nil {
		return ErrBusy
	}
	s, err := CanonicalPreparedSnapshot(s)
	if err != nil || b.base.active != nil && b.prepared.Hash != s.Hash {
		return ErrScope
	}
	actual, err := b.base.observe(ctx)
	known := err == nil && reflect.DeepEqual(actual, s.observation())
	if b.base.active != nil {
		known = known || err == nil && actual.matches(b.base.active.revision, s.observation())
	}
	if !known {
		return ErrObservation
	}
	if err := b.base.restoreUnder(ctx); err != nil {
		return err
	}
	actual, err = b.base.observe(ctx)
	if err != nil || !reflect.DeepEqual(actual, s.observation()) {
		b.base.fenced = true
		return ErrUncertain
	}
	b.prepared = PreparedSnapshot{}
	return nil
}

// RecoverPrepared is read-only and requires the same authenticated selected
// identity. WAN must still be empty; lease recovery is a separate selected path.
func (b *LANBootstrapV3) RecoverPrepared(ctx context.Context, r networkplan.Revision, s PreparedSnapshot, id OwnedNamespaceIdentity) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := CanonicalPreparedSnapshot(s)
	canonical, e := CanonicalLANBootstrapPlanV3(r)
	if err != nil || e != nil || canonical.Hash != b.desired.Hash || s.PlanHash != r.Hash || *b.base.identity != id || b.base.active != nil || b.lease != nil || b.guard(ctx) != nil || b.closedForwarding() != nil {
		return ErrScope
	}
	first, err := b.base.observe(ctx)
	if err != nil {
		return err
	}
	second, err := b.base.observe(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return ErrObservation
	}
	if reflect.DeepEqual(first, s.observation()) {
		return nil
	}
	projection := networkplan.Revision{Config: networkplan.Config{Interfaces: []networkplan.Interface{b.lan}}}
	if !first.matches(projection, s.observation()) {
		return ErrObservation
	}
	b.base.active = &transaction{revision: projection, baseline: s.observation(), operations: []operation{{kind: "address-add", name: b.lan.Binding.Name, address: b.lan.IPv4.Address}}}
	b.prepared = s
	return nil
}

// OpenLease borrows the already guarded namespace runner; it does not open a
// second namespace writer. LAN remains independently owned by this adapter.
func (b *LANBootstrapV3) OpenLease(ctx context.Context, options LeaseOptions) (*LeaseExecutor, error) {
	if b == nil {
		return nil, ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if options.Desired.Hash != b.desired.Hash || b.base.active == nil || b.lease != nil || b.guard(ctx) != nil || b.closedForwarding() != nil || b.base.Verify(ctx) != nil {
		return nil, ErrScope
	}
	borrowed := &Executor{lifetime: b.base.lifetime, run: b.base.run, identity: b.base.identity}
	l, err := newLeaseExecutor(ctx, borrowed, options, b.now)
	if err != nil {
		return nil, err
	}
	b.lease = l
	return l, nil
}

// ReleaseLease requires independently observed empty WAN before giving the LAN
// bootstrap/rollback lane back. It never removes a live lease implicitly.
func (b *LANBootstrapV3) ReleaseLease(ctx context.Context) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease == nil {
		return nil
	}
	b.lease.mu.Lock()
	active := b.lease.base.active != nil
	b.lease.mu.Unlock()
	if active {
		return ErrBusy
	}
	if b.guard(ctx) != nil {
		return ErrObservation
	}
	if b.base.active != nil {
		if b.base.Verify(ctx) != nil {
			return ErrObservation
		}
	} else {
		actual, err := b.base.observe(ctx)
		if err != nil || !reflect.DeepEqual(actual, b.lease.baseline) {
			return ErrObservation
		}
	}
	if err := b.lease.Close(); err != nil {
		return err
	}
	b.lease = nil
	return nil
}

// RecoverSelectedLeaseV3 reconstructs only WAN withdrawal ownership from the
// independently authenticated selected lease. It does not adopt LAN ownership;
// the selected Boot plan must subsequently authorize RecoverPrepared separately.
func (b *LANBootstrapV3) RecoverSelectedLeaseV3(ctx context.Context, options LeaseOptions, s LeaseSelectedSnapshotV3) (*LeaseExecutor, error) {
	if b == nil {
		return nil, ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease != nil || options.Desired.Hash != b.desired.Hash || b.closedForwarding() != nil || b.guard(ctx) != nil {
		return nil, ErrScope
	}
	borrowed := &Executor{lifetime: b.base.lifetime, run: b.base.run, identity: b.base.identity}
	l, _, err := recoverLeaseSelectedV3(ctx, borrowed, options, s, b.now)
	if err != nil {
		return nil, err
	}
	b.lease = l
	return l, nil
}

func (b *LANBootstrapV3) PrepareObserved(ctx context.Context, bindings []networkplan.Binding) (ObservedSnapshot, error) {
	if b == nil {
		return ObservedSnapshot{}, ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease != nil || b.closedForwarding() != nil {
		return ObservedSnapshot{}, ErrScope
	}
	return b.base.PrepareObserved(ctx, bindings)
}

func (b *LANBootstrapV3) VerifyObserved(ctx context.Context, s ObservedSnapshot) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.base.VerifyObserved(ctx, s)
}

func (b *LANBootstrapV3) RecoverObserved(ctx context.Context, s ObservedSnapshot, id OwnedNamespaceIdentity) error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease != nil || b.closedForwarding() != nil || b.guard(ctx) != nil {
		return ErrScope
	}
	return b.base.RecoverObserved(ctx, s, id)
}

func (b *LANBootstrapV3) Close() error {
	if b == nil {
		return ErrScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lease != nil || b.base.active != nil {
		return ErrBusy
	}
	return b.base.Close()
}
