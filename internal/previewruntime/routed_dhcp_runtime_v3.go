package previewruntime

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
)

// Root assembly authenticates a single owner stream. No field below is accepted
// from HTTP or the API/helper request channel. A new owner needs a new assembly.
type RoutedDHCPOwnerFactV3 struct {
	Epoch uint64
	Fact  networkexecutor.LeaseFact
}

type routedDHCPLeaseV3 interface {
	PrepareSelectedSnapshotV3(context.Context) (networkexecutor.LeaseSelectedSnapshotV3, error)
	Refresh(context.Context) (networkexecutor.LeaseOutcome, error)
	VerifySelectedStateV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedStateV3) error
	WithdrawSelectedV3(context.Context) (networkexecutor.LeaseOutcome, error)
}
type routedDHCPGateV3 interface {
	Initialize(context.Context) error
	RecoverClosedSelectedV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3) error
	RecoverWithdrawnSelectedV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3) error
	VerifyClosedSelectedV3(context.Context) error
	Close(context.Context) error
	Stage(context.Context) error
	Open(context.Context) error
	Verify(context.Context) error
}
type routedDHCPForwardingV3 interface {
	Disable(context.Context) error
	VerifyClosed(context.Context) error
	Enable(context.Context, func(context.Context) error) error
}
type routedDHCPReaderV3 interface {
	Resolve(context.Context, string) (routedDHCPWorkV3, error)
	VerifyDHCPReleasedV3(context.Context) error
	LastWithdrawnDHCPV3(context.Context) (*networkexecutor.LeaseSelectedSnapshotV3, error)
}
type routedDHCPWorkV3 interface {
	Reference() configpoc.SelectionReferenceV2
	Snapshot() networkexecutor.LeaseSelectedSnapshotV3
	Epoch() uint64
	Phase() string
	Running() string
}
type routedDHCPSelectedReaderV3 struct {
	*configpoc.RoutedSelectionReaderV2
}

func (r routedDHCPSelectedReaderV3) Resolve(ctx context.Context, work string) (routedDHCPWorkV3, error) {
	return r.ResolveDHCPCurrentV3(ctx, work)
}

// RoutedDHCPRuntimeV3 serializes the retained helper's lease, policy and gate.
// Its watchdog can only close/withdraw. Only selected R2 and a current owner may
// permit an opening. The independent kernel timeout survives helper/API death.
type RoutedDHCPRuntimeV3 struct {
	mu                        sync.Mutex
	identity                  networkexecutor.OwnedNamespaceIdentity
	owner                     networkexecutor.LeaseOwner
	current                   func(context.Context) (RoutedDHCPOwnerFactV3, error)
	reader                    routedDHCPReaderV3
	policy                    func(context.Context, routedDHCPWorkV3) error
	ready                     func() error
	fenced                    func() bool
	forward                   routedDHCPForwardingV3
	buildGate                 func(context.Context, networkexecutor.LeaseGateAuthority) (routedDHCPGateV3, error)
	openLease                 func(context.Context) (routedDHCPLeaseV3, error)
	recoverLease              func(context.Context, networkexecutor.LeaseSelectedSnapshotV3) (routedDHCPLeaseV3, error)
	releaseLease              func(context.Context) error
	gate                      routedDHCPGateV3
	lease                     routedDHCPLeaseV3
	grant                     configpoc.RoutedDHCPGrantV3
	work                      string
	opened, withdrawn, failed bool
}

// Gate callbacks run only while runtime.mu is held. They do not reenter Gate,
// the API writer or its publication barrier.
type routedDHCPGateAuthorityV3 struct{ runtime *RoutedDHCPRuntimeV3 }

func (a routedDHCPGateAuthorityV3) Current(ctx context.Context) (networkexecutor.LeaseGateGrant, error) {
	r := a.runtime
	if r.work == "" || r.sameOwner(ctx, r.grant) != nil {
		return networkexecutor.LeaseGateGrant{}, ErrUnavailable
	}
	return networkexecutor.LeaseGateGrant{Fact: r.grant.Snapshot.Fact(), WorkHash: r.work}, nil
}
func (a routedDHCPGateAuthorityV3) Verify(ctx context.Context, g networkexecutor.LeaseGateGrant) error {
	r := a.runtime
	p, err := r.selected(ctx, g.WorkHash)
	if err != nil || p.Phase() != "applied" || g.Fact != r.grant.Snapshot.Fact() || r.sameOwner(ctx, r.grant) != nil || r.lease.VerifySelectedStateV3(ctx, r.grant.Snapshot, networkexecutor.LeaseSelectedTargetV3) != nil || r.policy(ctx, p) != nil {
		return configpoc.ErrRecovery
	}
	return r.sameOwner(ctx, r.grant)
}

func (r *RoutedDHCPRuntimeV3) sameOwner(ctx context.Context, g configpoc.RoutedDHCPGrantV3) error {
	x, err := r.current(ctx)
	if err != nil || x.Epoch == 0 || x.Epoch != g.Epoch || x.Fact.Owner != r.owner || x.Fact.Revoked || x.Fact != g.Snapshot.Fact() || ctx.Err() != nil {
		return configpoc.ErrRecovery
	}
	return nil
}

func (r *RoutedDHCPRuntimeV3) selected(ctx context.Context, work string) (routedDHCPWorkV3, error) {
	p, err := r.reader.Resolve(ctx, work)
	if err != nil || p == nil || p.Reference().WorkHash != work || p.Snapshot().Identity != r.identity || p.Snapshot().Fact().Owner != r.owner || p.Epoch() == 0 {
		return nil, configpoc.ErrRecovery
	}
	return p, nil
}

func (r *RoutedDHCPRuntimeV3) closeUnder(ctx context.Context) error {
	r.opened = false
	var gateErr error
	if r.gate != nil {
		gateErr = r.gate.Close(ctx)
	}
	forwardErr := r.forward.Disable(ctx)
	if gateErr != nil || forwardErr != nil {
		r.failed = true
		return errors.Join(configpoc.ErrRecovery, gateErr, forwardErr)
	}
	return nil
}

func (r *RoutedDHCPRuntimeV3) currentUnder(ctx context.Context) (configpoc.RoutedDHCPGrantV3, error) {
	if r.failed || r.lease == nil || r.ready() != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	x, err := r.current(ctx)
	if err != nil || x.Epoch == 0 || x.Fact.Owner != r.owner || x.Fact.Revoked {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	s, err := r.lease.PrepareSelectedSnapshotV3(ctx)
	g := configpoc.RoutedDHCPGrantV3{Epoch: x.Epoch, Snapshot: s}
	if err != nil || s.Identity != r.identity || s.Fact() != x.Fact || r.sameOwner(ctx, g) != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	return g, nil
}

func (r *RoutedDHCPRuntimeV3) begin(ctx context.Context) (configpoc.RoutedDHCPGrantV3, error) {
	if r.failed || r.ready() != nil || r.work != "" && !r.withdrawn {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if r.reader.VerifyDHCPReleasedV3(ctx) != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if r.gate == nil {
		if r.forward.VerifyClosed(ctx) != nil {
			return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
		}
		last, err := r.reader.LastWithdrawnDHCPV3(ctx)
		if err != nil {
			return configpoc.RoutedDHCPGrantV3{}, err
		}
		g, err := r.buildGate(ctx, routedDHCPGateAuthorityV3{r})
		if err != nil {
			return configpoc.RoutedDHCPGrantV3{}, err
		}
		r.gate = g
		if last == nil {
			err = g.Initialize(ctx)
		} else {
			err = g.RecoverWithdrawnSelectedV3(ctx, *last)
		}
		if err != nil {
			r.failed = true
			return configpoc.RoutedDHCPGrantV3{}, err
		}
	}
	if r.closeUnder(ctx) != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	if r.lease == nil {
		l, err := r.openLease(ctx)
		if err != nil {
			return configpoc.RoutedDHCPGrantV3{}, err
		}
		r.lease = l
	}
	g, err := r.currentUnder(ctx)
	if err != nil || r.lease.VerifySelectedStateV3(ctx, g.Snapshot, networkexecutor.LeaseSelectedBaselineV3) != nil {
		return configpoc.RoutedDHCPGrantV3{}, configpoc.ErrRecovery
	}
	r.grant, r.work, r.withdrawn = g, "", false
	return g, nil
}

func (r *RoutedDHCPRuntimeV3) verifyClosed(ctx context.Context, hash string, state networkexecutor.LeaseSelectedStateV3) error {
	if r.grant.Snapshot.Hash != hash || r.gate == nil || r.lease == nil || r.gate.VerifyClosedSelectedV3(ctx) != nil || r.forward.VerifyClosed(ctx) != nil {
		return configpoc.ErrRecovery
	}
	return r.lease.VerifySelectedStateV3(ctx, r.grant.Snapshot, state)
}

func (r *RoutedDHCPRuntimeV3) apply(ctx context.Context, work string) error {
	if r.failed || r.ready() != nil || r.closeUnder(ctx) != nil {
		return configpoc.ErrRecovery
	}
	p, err := r.selected(ctx, work)
	if err != nil || p.Phase() != "prepared" || r.lease == nil || !reflect.DeepEqual(p.Snapshot(), r.grant.Snapshot) || p.Epoch() != r.grant.Epoch || r.sameOwner(ctx, r.grant) != nil || r.verifyClosed(ctx, r.grant.Snapshot.Hash, networkexecutor.LeaseSelectedBaselineV3) != nil {
		return configpoc.ErrRecovery
	}
	r.work = work
	if _, err = r.lease.Refresh(ctx); err != nil {
		return errors.Join(err, r.withdraw(ctx, work))
	}
	after, err := r.selected(ctx, work)
	if err != nil || after.Reference() != p.Reference() || r.verifyClosed(ctx, r.grant.Snapshot.Hash, networkexecutor.LeaseSelectedTargetV3) != nil || r.sameOwner(ctx, r.grant) != nil {
		return errors.Join(configpoc.ErrRecovery, r.withdraw(ctx, work))
	}
	return nil
}

func (r *RoutedDHCPRuntimeV3) retire(ctx context.Context) error {
	if !r.withdrawn || r.lease == nil || r.reader.VerifyDHCPReleasedV3(ctx) != nil || r.verifyClosed(ctx, r.grant.Snapshot.Hash, networkexecutor.LeaseSelectedBaselineV3) != nil {
		return configpoc.ErrRecovery
	}
	if err := r.releaseLease(ctx); err != nil {
		return err
	}
	r.lease, r.work, r.grant, r.withdrawn = nil, "", configpoc.RoutedDHCPGrantV3{}, false
	return nil
}

func (r *RoutedDHCPRuntimeV3) open(ctx context.Context, work string) error {
	if r.failed || r.ready() != nil || r.opened || r.work != work || r.gate == nil || r.lease == nil {
		return configpoc.ErrRecovery
	}
	p, err := r.selected(ctx, work)
	if err != nil || p.Phase() != "applied" || p.Epoch() != r.grant.Epoch || !reflect.DeepEqual(p.Snapshot(), r.grant.Snapshot) || r.sameOwner(ctx, r.grant) != nil {
		return configpoc.ErrRecovery
	}
	if err := r.gate.Stage(ctx); err != nil {
		return errors.Join(err, r.closeUnder(ctx))
	}
	if err := r.gate.Open(ctx); err != nil {
		return errors.Join(err, r.closeUnder(ctx))
	}
	if err := r.forward.Enable(ctx, r.gate.Verify); err != nil {
		return errors.Join(err, r.closeUnder(ctx))
	}
	r.opened = true
	return nil
}

func (r *RoutedDHCPRuntimeV3) withdraw(ctx context.Context, work string) error {
	// Retained gate closure precedes even a failed selected-store read. A fresh
	// helper has no token authority and requires supervisor-contained forwarding.
	if r.closeUnder(ctx) != nil {
		return configpoc.ErrRecovery
	}
	p, err := r.selected(ctx, work)
	if err != nil {
		return err
	}
	s := p.Snapshot()
	if r.gate == nil {
		g, e := r.buildGate(ctx, routedDHCPGateAuthorityV3{r})
		if e != nil {
			return e
		}
		r.gate = g
		if e = g.RecoverClosedSelectedV3(ctx, s); e != nil {
			r.failed = true
			return e
		}
	}
	if r.lease == nil {
		l, e := r.recoverLease(ctx, s)
		if e != nil {
			return e
		}
		r.lease = l
	}
	r.grant, r.work = configpoc.RoutedDHCPGrantV3{Epoch: p.Epoch(), Snapshot: s}, work
	if _, err = r.lease.WithdrawSelectedV3(ctx); err != nil {
		r.failed = true
		return err
	}
	if err = r.verifyClosed(ctx, s.Hash, networkexecutor.LeaseSelectedBaselineV3); err != nil {
		r.failed = true
		return err
	}
	r.withdrawn = true
	return nil
}

func (r *RoutedDHCPRuntimeV3) dispatch(ctx context.Context, c firewallipc.RoutedCommandV3) (any, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrIdentity
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var g configpoc.RoutedDHCPGrantV3
	var err error
	switch c.Verb {
	case "dhcp_begin":
		g, err = r.begin(ctx)
	case "dhcp_current":
		g, err = r.currentUnder(ctx)
	case "dhcp_verify":
		err = r.verifyClosed(ctx, c.DHCP.Snapshot, c.DHCP.State)
	case "dhcp_apply":
		err = r.apply(ctx, c.DHCP.Work)
	case "dhcp_open":
		err = r.open(ctx, c.DHCP.Work)
	case "dhcp_withdraw":
		err = r.withdraw(ctx, c.DHCP.Work)
	case "dhcp_retire":
		err = r.retire(ctx)
	case "dhcp_live":
		if r.failed || r.ready() != nil || !r.opened || r.work != c.DHCP.Work {
			err = configpoc.ErrRecovery
		} else {
			err = r.gate.Verify(ctx)
		}
	default:
		err = ErrIdentity
	}
	if c.Verb == "dhcp_current" || c.Verb == "dhcp_begin" {
		return firewallipc.RoutedDHCPGrantV3{Epoch: g.Epoch, Snapshot: g.Snapshot}, err
	}
	return struct{}{}, err
}

// Run watches the authenticated owner while the API is absent. It never grants
// access or publishes selected state. API recovery must still archive withdrawal.
func (r *RoutedDHCPRuntimeV3) Run(ctx context.Context) {
	if r == nil || ctx == nil {
		return
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.Lock()
			if r.opened {
				call, cancel := context.WithTimeout(ctx, 3*time.Second)
				if r.fenced() || r.sameOwner(call, r.grant) != nil {
					_ = r.withdraw(call, r.work)
				}
				cancel()
			}
			r.mu.Unlock()
		}
	}
}
