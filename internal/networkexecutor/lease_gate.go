package networkexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
)

var (
	ErrLeaseGate               = errors.New("ANDEIVA_LEASE_GATE_CLOSED")
	ErrLeaseGateUncertain      = errors.New("ANDEIVA_LEASE_GATE_CLOSURE_UNPROVEN")
	ErrLeaseGateCurrent        = errors.New("ANDEIVA_LEASE_GATE_CURRENT_INVALID")
	ErrLeaseGateSequence       = errors.New("ANDEIVA_LEASE_GATE_SEQUENCE_STALE")
	ErrLeaseGateAuthority      = errors.New("ANDEIVA_LEASE_GATE_AUTHORITY_INVALID")
	ErrLeaseGateChanged        = errors.New("ANDEIVA_LEASE_GATE_AUTHORITY_CHANGED")
	ErrLeaseGateRenewal        = errors.New("ANDEIVA_LEASE_GATE_SAME_EFFECTIVE_RENEWAL")
	ErrLeaseGateMarginClosed   = errors.New("ANDEIVA_LEASE_GATE_MARGIN_CLOSED")
	ErrLeaseGateExpired        = errors.New("ANDEIVA_LEASE_GATE_TOKEN_EXPIRED")
	ErrLeaseGateDeadline       = errors.New("ANDEIVA_LEASE_GATE_DEADLINE_INVALID")
	ErrLeaseGateReady          = errors.New("ANDEIVA_LEASE_GATE_NOT_READY")
	ErrLeaseGateState          = errors.New("ANDEIVA_LEASE_GATE_INVALID_STATE")
	ErrLeaseGateReadback       = errors.New("ANDEIVA_LEASE_GATE_READBACK_INVALID")
	ErrLeaseGateContext        = errors.New("ANDEIVA_LEASE_GATE_CONTEXT_ENDED")
	ErrLeaseGateLifetime       = errors.New("ANDEIVA_LEASE_GATE_LIFETIME_ENDED")
	ErrLeaseGateDisposed       = errors.New("ANDEIVA_LEASE_GATE_DISPOSED")
	ErrLeaseGateFenced         = errors.New("ANDEIVA_LEASE_GATE_FENCED")
	ErrLeaseGateFenceCreate    = errors.New("ANDEIVA_LEASE_GATE_FENCE_CREATE")
	ErrLeaseGateFenceClose     = errors.New("ANDEIVA_LEASE_GATE_FENCE_CLOSE")
	ErrLeaseGateFenceOperation = errors.New("ANDEIVA_LEASE_GATE_FENCE_OPERATION")
	ErrLeaseGateFenceReject    = errors.New("ANDEIVA_LEASE_GATE_FENCE_REJECT")
	ErrLeaseGateFenceRecovery  = errors.New("ANDEIVA_LEASE_GATE_FENCE_RECOVERY")
)

// LeaseGateGrant is supervisor provenance, never a public request DTO. WorkHash
// identifies selected work but cannot authorize it without Authority.Verify.
type LeaseGateGrant struct {
	Fact     LeaseFact
	WorkHash string
}

// LeaseGateAuthority must be implemented by trusted assembly holding the selected
// work and DHCP owner authority. Verify checks the exact L3 delta, LAN baseline,
// selected durable work/reserve, policy and absence of offload. Assembly serializes
// these checks with policy/owner changes. Callbacks must not call back into Gate.
type LeaseGateAuthority interface {
	Current(context.Context) (LeaseGateGrant, error)
	Verify(context.Context, LeaseGateGrant) error
}

type LeaseGateOptions struct {
	Desired   networkplan.Revision
	Owner     LeaseOwner
	Authority LeaseGateAuthority
	// Internal opt-in: expected token expiry may prove closure, never reopening.
	CloseOnExpiryV4 bool
}

// LeaseGate is an isolated, continuous-execution experiment. It only restricts
// forwarding; it neither enables IP forwarding nor supplies the firewall policy.
// Kernel timeout is not a BOOTTIME/suspend guarantee. There is no adoption,
// persistence, Confirm or rollback operation that can restore a token.
type LeaseGate struct {
	mu                                    sync.Mutex
	identity                              OwnedNamespaceIdentity
	lifetime                              context.Context
	opts                                  LeaseGateOptions
	wan                                   networkplan.Interface
	kernel                                leaseGateKernel
	now                                   func() (int64, error)
	closedForwarding                      func() error
	release                               func() error
	initialized, opened, fenced, disposed bool
	fenceReason                           error
	seen                                  uint64
	staged                                LeaseGateGrant
	timeout                               int64
	expiryFloorBootNS                     int64
}

type leaseGateKernel interface {
	Check(context.Context, []byte) error
	Apply(context.Context, []byte) error
	Observe(context.Context) ([]byte, error)
}

// CheckFreshSequenceV4 rejects consumed grants before a caller prepares work.
// It grants no forwarding authority; Stage still performs every fresh check.
func (g *LeaseGate) CheckFreshSequenceV4(ctx context.Context, sequence uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return err
	}
	if !g.initialized || g.opened || g.staged != (LeaseGateGrant{}) || sequence <= g.seen {
		return ErrLeaseGate
	}
	return nil
}

func newLeaseGate(lifetime context.Context, id OwnedNamespaceIdentity, options LeaseGateOptions, kernel leaseGateKernel, now func() (int64, error), closed func() error) (*LeaseGate, error) {
	if lifetime == nil || lifetime.Err() != nil || !validOwnedIdentity(id) || options.Authority == nil || kernel == nil || now == nil || closed == nil {
		return nil, ErrScope
	}
	r, err := networkplan.Canonical(options.Desired.Config)
	if err != nil || r.Hash != options.Desired.Hash || len(r.Config.Interfaces) != 2 || r.Config.DNS.Mode != "none" {
		return nil, ErrScope
	}
	o := options.Owner
	if o.Namespace != id.Namespace || o.BootID != id.BootID || o.RunID != id.RunID || o.PID <= 1 || o.StartTicks == 0 || !leaseGateHex(o.Incarnation, 32) {
		return nil, ErrScope
	}
	g := &LeaseGate{lifetime: lifetime, identity: id, opts: options, kernel: kernel, now: now, closedForwarding: closed}
	g.opts.Desired = r
	for _, i := range r.Config.Interfaces {
		switch {
		case i.Role == networkplan.WAN && i.IPv4.Mode == "dhcp":
			g.wan = i
		case i.Role == networkplan.LAN && i.IPv4.Mode == "static" && netip.MustParsePrefix(i.IPv4.Address).Bits() <= 30:
		default:
			return nil, ErrScope
		}
	}
	if g.wan.ID == "" || r.Config.DefaultRoute.InterfaceID != g.wan.ID || closed() != nil {
		return nil, ErrScope
	}
	return g, nil
}

func leaseGateHex(s string, size int) bool {
	if len(s) != size || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (g *LeaseGate) ready(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errors.Join(ErrLeaseGate, ErrLeaseGateContext)
	}
	if g.lifetime.Err() != nil {
		return errors.Join(ErrLeaseGate, ErrLeaseGateLifetime)
	}
	if g.disposed {
		return errors.Join(ErrLeaseGate, ErrLeaseGateDisposed)
	}
	if g.fenced {
		return errors.Join(ErrLeaseGate, ErrLeaseGateFenced, g.fenceReason)
	}
	return nil
}

func (g *LeaseGate) current(ctx context.Context) (LeaseGateGrant, error) {
	x, err := g.opts.Authority.Current(ctx)
	if errors.Is(err, ErrLeaseGateRenewal) || errors.Is(err, ErrLeaseGateMarginClosed) {
		return LeaseGateGrant{}, errors.Join(ErrLeaseGate, err)
	}
	f := x.Fact
	now, clockErr := g.now()
	if err != nil || clockErr != nil || now <= 0 || f.Owner != g.opts.Owner || f.Sequence == 0 || f.Revoked || f.DesiredHash != g.opts.Desired.Hash || f.WAN != g.wan.Binding || f.DeadlineBootNS <= now || f.DeadlineBootNS-now > int64(7*24*time.Hour) || !leaseGateHex(x.WorkHash, 64) {
		return LeaseGateGrant{}, ErrLeaseGate
	}
	c := g.opts.Desired.Config
	c.Interfaces = append([]networkplan.Interface(nil), c.Interfaces...)
	for i := range c.Interfaces {
		if c.Interfaces[i].ID == g.wan.ID {
			c.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "static", Address: f.Address, Gateway: f.Gateway}
		}
	}
	if _, err := networkplan.Canonical(c); err != nil {
		return LeaseGateGrant{}, ErrLeaseGate
	}
	p, err := netip.ParsePrefix(f.Address)
	if err != nil || p.Bits() > 30 {
		return LeaseGateGrant{}, ErrLeaseGate
	}
	return x, nil
}

func (g *LeaseGate) same(ctx context.Context, x LeaseGateGrant) error {
	actual, err := g.current(ctx)
	if err != nil || actual != x {
		return errors.Join(ErrLeaseGate, err)
	}
	return nil
}

func leaseGateDigest(x LeaseGateGrant) string {
	b, _ := json.Marshal(x)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (g *LeaseGate) apply(ctx context.Context, batch []byte) error {
	if err := g.kernel.Check(ctx, batch); err != nil {
		return err
	}
	return g.kernel.Apply(ctx, batch)
}

// Initialize creates only an absent fixed table, with both sets empty. Existing
// tables are not adopted or replaced. The constructor itself has no mutations.
func (g *LeaseGate) Initialize(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return err
	}
	if g.initialized || g.closedForwarding() != nil {
		return ErrLeaseGate
	}
	if err := g.apply(ctx, leaseGateCreate(g.wan.Binding.Name)); err != nil {
		// A failed create may mean a foreign existing table. Never flush it.
		g.fenced = true
		g.fenceReason = ErrLeaseGateFenceCreate
		return errors.Join(ErrLeaseGateUncertain, err)
	}
	g.initialized = true
	if _, err := g.read(ctx, false, false); err != nil {
		return g.fail(err)
	}
	return nil
}

// Close irreversibly removes this instance's token. It never restores a prior
// grant. A failure to prove closure requires supervisor forwarding-off/teardown.
func (g *LeaseGate) Close(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx == nil || g.disposed || !g.initialized {
		return ErrLeaseGate
	}
	return g.closeUnder(ctx)
}

func (g *LeaseGate) closeUnder(ctx context.Context) error {
	sequence := g.staged.Fact.Sequence
	marked := g.opened || sequence != 0
	if marked {
		nativeLeasePhaseV4("close_start", sequence, g.expiryFloorBootNS)
	}
	g.opened = false
	g.staged = LeaseGateGrant{}
	g.timeout = 0
	g.expiryFloorBootNS = 0
	err := g.apply(ctx, leaseGateClose())
	_, observed := g.read(ctx, false, false)
	if observed != nil {
		g.fenced = true
		g.fenceReason = errors.Join(ErrLeaseGateFenceClose, observed)
		return errors.Join(ErrLeaseGateUncertain, err, observed)
	}
	// Lost ACK is resolved only by the complete closed readback, never replay.
	if marked {
		nativeLeasePhaseV4("closed", sequence, 0)
	}
	return nil
}

func (g *LeaseGate) fail(cause error) error {
	g.fenced = true
	g.fenceReason = errors.Join(ErrLeaseGateFenceOperation, cause)
	ctx, cancel := context.WithTimeout(g.lifetime, 3*time.Second)
	defer cancel()
	return errors.Join(ErrLeaseGate, cause, g.closeUnder(ctx))
}

// Only trusted classified renewal or margin closure can retain a closed gate
// for fresh evidence. Generic failures preserve legacy fencing.
func (g *LeaseGate) rejectClosed(ctx context.Context, cause error) error {
	if !errors.Is(cause, ErrLeaseGateRenewal) && !errors.Is(cause, ErrLeaseGateMarginClosed) {
		return g.fail(cause)
	}
	// A rejected grant may consume the request deadline. Proving closure is a
	// safety action and must use the gate lifetime, not the failed RPC context.
	cleanup, cancel := context.WithTimeout(g.lifetime, 3*time.Second)
	defer cancel()
	if err := g.closeUnder(cleanup); err != nil {
		g.fenced = true
		g.fenceReason = errors.Join(ErrLeaseGateFenceReject, err)
		return errors.Join(ErrLeaseGateUncertain, cause, err)
	}
	return errors.Join(ErrLeaseGate, cause)
}

// Stage is called after Close, namespace forwarding-off and L3/policy/work
// verification. A sequence is consumed before the first mutation; no retry or
// rollback can recreate the same grant's timeout.
func (g *LeaseGate) Stage(ctx context.Context) error {
	if done := StartNativeLeaseSpanV4("gate_stage"); done != nil {
		defer done()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return errors.Join(ErrLeaseGateReady, err)
	}
	if !g.initialized || g.opened || g.staged.Fact.Sequence != 0 {
		return ErrLeaseGateState
	}
	if g.closedForwarding() != nil {
		return g.fail(ErrScope)
	}
	if _, err := g.read(ctx, false, false); err != nil {
		return g.fail(errors.Join(ErrLeaseGateReadback, err))
	}
	x, err := g.current(ctx)
	if err != nil {
		return g.rejectClosed(ctx, errors.Join(ErrLeaseGateCurrent, err))
	}
	if x.Fact.Sequence <= g.seen {
		return g.rejectClosed(ctx, ErrLeaseGateSequence)
	}
	if err := g.opts.Authority.Verify(ctx, x); err != nil {
		return g.rejectClosed(ctx, errors.Join(ErrLeaseGateAuthority, err))
	}
	if err := g.same(ctx, x); err != nil {
		return g.rejectClosed(ctx, errors.Join(ErrLeaseGateChanged, err))
	}
	now, err := g.now()
	// libnftables JSON times are seconds. Leave two whole seconds for rounding
	// and latency, then prove the actual remaining time after kernel readback.
	ttl := (x.Fact.DeadlineBootNS-now)/int64(time.Second) - 2
	if err != nil || now <= 0 || ttl <= 0 || ttl > int64(7*24*time.Hour/time.Second) {
		return g.rejectClosed(ctx, ErrLeaseGateDeadline)
	}
	g.seen, g.staged, g.timeout = x.Fact.Sequence, x, ttl
	// Sampled before apply: this lower bound may close early, but cannot extend
	// either the actual kernel timeout or the authenticated lease deadline.
	g.expiryFloorBootNS = now + ttl*int64(time.Second)
	applyErr := g.apply(ctx, leaseGateStage(g.wan.Binding.Name, leaseGateDigest(x), ttl))
	if _, err := g.read(ctx, false, true); err != nil {
		return g.fail(errors.Join(applyErr, err))
	}
	if err := g.same(ctx, x); err != nil {
		// Unclassified changes preserve the legacy permanent fence. Only the
		// trusted renewal classification permits a verified close and retry;
		// the consumed sequence remains in g.seen in either case.
		return g.rejectClosed(ctx, errors.Join(ErrLeaseGateChanged, err))
	}
	return nil
}

// Open changes only the non-expiring enable set. It never touches the expiring
// set, including on uncertain ACK. Readback time is sampled after receipt.
func (g *LeaseGate) Open(ctx context.Context) error {
	if done := StartNativeLeaseSpanV4("gate_open"); done != nil {
		defer done()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return err
	}
	if !g.initialized || g.opened || g.staged.Fact.Sequence == 0 {
		return ErrLeaseGate
	}
	if g.closedForwarding() != nil {
		return g.fail(ErrScope)
	}
	if _, err := g.read(ctx, false, true); err != nil {
		return g.fail(err)
	}
	if err := g.opts.Authority.Verify(ctx, g.staged); err != nil {
		if errors.Is(err, ErrLeaseGateRenewal) || errors.Is(err, ErrLeaseGateMarginClosed) {
			return g.rejectClosed(ctx, err)
		}
		return g.fail(err)
	}
	if err := g.same(ctx, g.staged); err != nil {
		return g.rejectClosed(ctx, err)
	}
	applyErr := g.apply(ctx, leaseGateOpen(g.wan.Binding.Name))
	if _, err := g.read(ctx, true, true); err != nil {
		return g.fail(errors.Join(applyErr, err))
	}
	if err := g.same(ctx, g.staged); err != nil {
		return g.rejectClosed(ctx, err)
	}
	g.opened = true
	return nil
}

// Verify is a fresh readback, not a cached statement of permission.
func (g *LeaseGate) Verify(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.ready(ctx); err != nil {
		return err
	}
	if !g.opened {
		return ErrLeaseGate
	}
	if due, err := g.closeExpiredV4(); due || err != nil {
		return err
	}
	if _, err := g.read(ctx, true, true); err != nil {
		// Expiry can cross while querying the kernel. A complete verified close
		// is still mandatory; the failed read alone never establishes closure.
		if due, expiryErr := g.closeExpiredV4(); due || expiryErr != nil {
			return expiryErr
		}
		return g.fail(err)
	}
	if err := g.opts.Authority.Verify(ctx, g.staged); err != nil {
		if errors.Is(err, ErrLeaseGateRenewal) || errors.Is(err, ErrLeaseGateMarginClosed) {
			return g.rejectClosed(ctx, err)
		}
		return g.fail(errors.Join(ErrLeaseGateAuthority, err))
	}
	if err := g.same(ctx, g.staged); err != nil {
		return g.rejectClosed(ctx, errors.Join(ErrLeaseGateChanged, err))
	}
	return nil
}

// Caller holds g.mu. Expected expiry keeps the consumed sequence watermark and
// grants no retry of that token. Uncertain closure retains the normal fence.
func (g *LeaseGate) closeExpiredV4() (bool, error) {
	if !g.opts.CloseOnExpiryV4 || g.staged.Fact.Sequence == 0 || g.expiryFloorBootNS == 0 {
		return false, nil
	}
	now, err := g.now()
	if err != nil || now <= 0 {
		return false, g.fail(ErrLeaseGateDeadline)
	}
	if now < g.expiryFloorBootNS {
		return false, nil
	}
	cleanup, cancel := context.WithTimeout(g.lifetime, 3*time.Second)
	defer cancel()
	if err := g.closeUnder(cleanup); err != nil {
		return true, errors.Join(ErrLeaseGateUncertain, err)
	}
	return true, errors.Join(ErrLeaseGate, ErrLeaseGateExpired)
}

// Dispose releases namespace pins only after a proven Close. It leaves the
// closed gate in the owned namespace; only its supervisor may tear that down.
func (g *LeaseGate) Dispose() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.disposed || g.opened || g.staged.Fact.Sequence != 0 || g.fenced {
		return ErrLeaseGate
	}
	g.disposed = true
	if g.release != nil {
		return g.release()
	}
	return nil
}
