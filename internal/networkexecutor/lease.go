package networkexecutor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
)

var ErrLeaseUnavailable = errors.New("ANDEIVA_NETWORK_LEASE_UNAVAILABLE")

// LeaseOwner is authenticated supervisor provenance, not a public request DTO.
// RunID is the retained network manager; Incarnation identifies this DHCP owner.
// Numeric PID, an address in the kernel or a digest cannot establish ownership.
type LeaseOwner struct {
	Namespace                  uint64
	BootID, RunID, Incarnation string
	PID                        uint32
	StartTicks                 uint64
}

// LeaseFact must come from the private authenticated owner stream. Sequence
// advances on grants AND revocations; a new owner requires a new constructor.
// No decoder or unauthenticated IPC is provided by this package.
type LeaseFact struct {
	Owner            LeaseOwner
	Sequence         uint64
	DesiredHash      string
	WAN              networkplan.Binding
	Address, Gateway string
	DeadlineBootNS   int64
	Revoked          bool
}

type LeaseOptions struct {
	Desired networkplan.Revision
	Owner   LeaseOwner
	Current func(context.Context) (LeaseFact, error)
}

type LeaseOutcome string

const (
	LeaseApplied           LeaseOutcome = "applied"
	LeaseEvidenceRefreshed LeaseOutcome = "evidence_refreshed"
	LeaseBaselineRestored  LeaseOutcome = "baseline_restored"
	LeaseWANWithdrawn      LeaseOutcome = "wan_withdrawn"
	LeaseFenced            LeaseOutcome = "fenced"
)

// LeaseExecutor is an opt-in, closed-forwarding L3 experiment. It preserves an
// existing static LAN and owns only its WAN additions. It does not replace the
// static Executor, provide durable ownership, run an expiry service or permit
// forwarding. Trusted assembly must drive Refresh on events/deadlines. Until
// authenticated selected-work recovery exists, opening an occupied WAN fails.
type LeaseExecutor struct {
	mu       sync.Mutex
	base     *Executor
	desired  networkplan.Revision
	wan, lan networkplan.Interface
	owner    LeaseOwner
	current  func(context.Context) (LeaseFact, error)
	now      func() (int64, error)
	baseline observation
	fact     LeaseFact
	seen     uint64
}

func newLeaseExecutor(ctx context.Context, base *Executor, options LeaseOptions, now func() (int64, error)) (*LeaseExecutor, error) {
	if base == nil || base.identity == nil || base.identity.Namespace == base.identity.Host || base.identity.Host == 0 || options.Current == nil || now == nil {
		return nil, ErrScope
	}
	r, err := networkplan.Canonical(options.Desired.Config)
	if err != nil || r.Hash != options.Desired.Hash || len(r.Config.Interfaces) != 2 || r.Config.DNS.Mode != "none" {
		return nil, ErrUnsupported
	}
	l := &LeaseExecutor{base: base, desired: r, owner: options.Owner, current: options.Current, now: now}
	for _, i := range r.Config.Interfaces {
		switch {
		case i.Role == networkplan.WAN && i.IPv4.Mode == "dhcp":
			l.wan = i
		case i.Role == networkplan.LAN && i.IPv4.Mode == "static" && netip.MustParsePrefix(i.IPv4.Address).Bits() <= 30:
			l.lan = i
		default:
			return nil, ErrUnsupported
		}
	}
	if l.wan.ID == "" || l.lan.ID == "" || r.Config.DefaultRoute.InterfaceID != l.wan.ID || !l.validOwner() {
		return nil, ErrScope
	}
	if err := l.guard(ctx); err != nil {
		return nil, err
	}
	first, err := base.observe(ctx)
	if err != nil {
		return nil, err
	}
	second, err := base.observe(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return nil, ErrObservation
	}
	// Reuse the strict two-link L2 profile without relaxing empty IPv4 snapshots.
	l2 := observation{Links: append([]link(nil), first.Links...)}
	for i := range l2.Links {
		l2.Links[i].Addresses = nil
	}
	if _, err := canonicalEmptyObservation(l2); err != nil {
		return nil, err
	}
	if _, err := networkplan.Bind(r, first.inventory()); err != nil {
		return nil, ErrScope
	}
	lanOnly := networkplan.Revision{Config: networkplan.Config{Interfaces: []networkplan.Interface{l.lan}}}
	if !first.matches(lanOnly, first) {
		return nil, ErrUnsupported
	}
	b, err := json.Marshal(first)
	if err != nil || len(b) > MaxPreparedSnapshot {
		return nil, ErrScope
	}
	l.baseline = first
	return l, nil
}

func (l *LeaseExecutor) validOwner() bool {
	i := l.base.identity
	o := l.owner
	if o.Namespace != i.Namespace || o.BootID != i.BootID || o.RunID != i.RunID || o.PID <= 1 || o.StartTicks == 0 || len(o.Incarnation) != 32 || o.Incarnation != strings.ToLower(o.Incarnation) {
		return false
	}
	_, err := hex.DecodeString(o.Incarnation)
	return err == nil
}

func (l *LeaseExecutor) guard(ctx context.Context) error {
	if l == nil || l.base == nil {
		return ErrScope
	}
	if err := l.base.ready(ctx); err != nil {
		return err
	}
	b, err := l.base.execute(ctx, operation{kind: "rules"})
	if err != nil {
		return err
	}
	var rules []struct {
		Priority uint32 `json:"priority"`
		Source   string `json:"src"`
		Table    string `json:"table"`
	}
	if decode(b, &rules, true) != nil || len(rules) != 3 {
		return ErrScope
	}
	for i, want := range []struct {
		p uint32
		t string
	}{{0, "local"}, {32766, "main"}, {32767, "default"}} {
		if rules[i].Priority != want.p || rules[i].Source != "all" || rules[i].Table != want.t {
			return ErrScope
		}
	}
	return nil
}

func (l *LeaseExecutor) resolve(ctx context.Context) (LeaseFact, networkplan.Revision, error) {
	f, err := l.current(ctx)
	if err != nil {
		return LeaseFact{}, networkplan.Revision{}, ErrLeaseUnavailable
	}
	if f.Owner != l.owner || f.Sequence == 0 || f.DesiredHash != l.desired.Hash || f.WAN != l.wan.Binding {
		return f, networkplan.Revision{}, ErrScope
	}
	if f.Revoked {
		if f.Address != "" || f.Gateway != "" || f.DeadlineBootNS != 0 {
			return f, networkplan.Revision{}, ErrScope
		}
		return f, networkplan.Revision{}, ErrLeaseUnavailable
	}
	now, err := l.now()
	if err != nil || now <= 0 || f.DeadlineBootNS <= now || f.DeadlineBootNS-now > int64(7*24*time.Hour) {
		return f, networkplan.Revision{}, ErrLeaseUnavailable
	}
	// The realized projection is internal only. Desired remains canonical DHCP.
	config := l.desired.Config
	config.Interfaces = append([]networkplan.Interface(nil), config.Interfaces...)
	for i := range config.Interfaces {
		if config.Interfaces[i].ID == l.wan.ID {
			config.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "static", Address: f.Address, Gateway: f.Gateway}
		}
	}
	r, err := networkplan.Canonical(config)
	if err != nil {
		return f, networkplan.Revision{}, ErrScope
	}
	p := netip.MustParsePrefix(f.Address)
	if p.Bits() > 30 {
		return f, networkplan.Revision{}, ErrUnsupported
	}
	return f, r, nil
}

func (l *LeaseExecutor) observeExpected(ctx context.Context) error {
	if err := l.guard(ctx); err != nil {
		return err
	}
	o, err := l.base.observe(ctx)
	if err != nil {
		return err
	}
	if l.base.active == nil {
		if !reflect.DeepEqual(o, l.baseline) {
			return ErrObservation
		}
	} else if !l.matches(o, l.base.active.revision, true) {
		return ErrObservation
	}
	return nil
}

// matches preserves all LAN facts exactly and checks only the owned WAN delta
// against the static semantic verifier. This never rewrites the desired plan.
func (l *LeaseExecutor) matches(o observation, r networkplan.Revision, withRoute bool) bool {
	kept := observation{Links: append([]link(nil), o.Links...), Routes: []route{}}
	wanOnly := observation{Links: append([]link(nil), o.Links...), Routes: []route{}}
	for i := range kept.Links {
		if kept.Links[i].Name == l.wan.Binding.Name {
			kept.Links[i].Addresses = []address{}
		} else {
			wanOnly.Links[i].Addresses = []address{}
		}
	}
	for _, route := range o.Routes {
		if route.Device == l.wan.Binding.Name {
			wanOnly.Routes = append(wanOnly.Routes, route)
		} else {
			kept.Routes = append(kept.Routes, route)
		}
	}
	if !reflect.DeepEqual(kept, l.baseline) {
		return false
	}
	projected := r
	projected.Config = r.Config
	projected.Config.Interfaces = nil
	for _, i := range r.Config.Interfaces {
		if i.ID == l.wan.ID {
			projected.Config.Interfaces = []networkplan.Interface{i}
		}
	}
	if !withRoute {
		projected.Config.DefaultRoute = networkplan.DefaultRoute{}
	}
	return wanOnly.matches(projected, l.baseline)
}

func (l *LeaseExecutor) fence(err error) (LeaseOutcome, error) {
	l.base.fenced = true
	return LeaseFenced, errors.Join(ErrUncertain, err)
}

// Refresh consumes one new owner sequence. Same-tuple renewal updates evidence
// in memory only. It extends no persisted or kernel deadline. Changing a tuple
// withdraws the old one first; compensation never resurrects that older lease.
func (l *LeaseExecutor) Refresh(ctx context.Context) (LeaseOutcome, error) {
	if l == nil || l.base == nil {
		return LeaseFenced, ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.base.ready(ctx); err != nil {
		return LeaseFenced, err
	}
	if err := l.observeExpected(ctx); err != nil {
		return l.fence(err)
	}
	f, r, err := l.resolve(ctx)
	if f.Owner == l.owner && f.Sequence != 0 && f.Sequence <= l.seen {
		// The current fact may expire without a new event; that is withdrawal,
		// not a replay that is permitted to keep an expired address active.
		if !errors.Is(err, ErrLeaseUnavailable) {
			if l.base.active == nil {
				return LeaseEvidenceRefreshed, ErrScope
			}
			now, clockErr := l.now()
			if clockErr == nil && now > 0 && now < l.fact.DeadlineBootNS {
				return LeaseEvidenceRefreshed, ErrScope
			}
			// A replay cannot extend the deadline retained with installed state.
			err = ErrLeaseUnavailable
		}
	}
	if err != nil {
		if f.Owner == l.owner && f.Sequence > l.seen {
			l.seen = f.Sequence
		}
		out, withdrawErr := l.withdrawLocked(LeaseWANWithdrawn)
		return out, errors.Join(err, withdrawErr)
	}
	l.seen = f.Sequence
	if l.base.active != nil && f.Address == l.fact.Address && f.Gateway == l.fact.Gateway {
		l.fact = f
		return LeaseEvidenceRefreshed, nil
	}
	hadWAN := l.base.active != nil
	if hadWAN {
		if _, err := l.withdrawLocked(LeaseWANWithdrawn); err != nil {
			return LeaseFenced, err
		}
	}
	if err := l.sameFact(ctx, f); err != nil {
		return LeaseWANWithdrawn, err
	}
	tx := &transaction{revision: r, baseline: l.baseline}
	l.base.active = tx
	for _, op := range []operation{{kind: "address-add", name: l.wan.Binding.Name, address: f.Address}, {kind: "route-add", name: l.wan.Binding.Name, gateway: f.Gateway, metric: r.Config.DefaultRoute.Metric}} {
		if err = l.sameFact(ctx, f); err == nil {
			err = l.guard(ctx)
		}
		if err == nil {
			err = l.base.checkLinks(ctx, l.baseline)
		}
		if err != nil {
			return l.failedApply(err, hadWAN)
		}
		tx.operations = append(tx.operations, op)
		if _, err = l.base.execute(ctx, op); err != nil {
			return l.failedApply(err, hadWAN)
		}
	}
	if err = l.sameFact(ctx, f); err == nil {
		err = l.observeExpected(ctx)
	}
	if err != nil {
		return l.failedApply(err, hadWAN)
	}
	l.fact = f
	return LeaseApplied, nil
}

func (l *LeaseExecutor) sameFact(ctx context.Context, want LeaseFact) error {
	f, _, err := l.resolve(ctx)
	if err != nil {
		return err
	}
	if f != want {
		return ErrScope
	}
	return nil
}

func (l *LeaseExecutor) failedApply(cause error, hadWAN bool) (LeaseOutcome, error) {
	outcome := LeaseBaselineRestored
	if hadWAN {
		outcome = LeaseWANWithdrawn
	}
	out, err := l.withdrawLocked(outcome)
	return out, errors.Join(cause, err)
}

func (l *LeaseExecutor) withdrawLocked(outcome LeaseOutcome) (LeaseOutcome, error) {
	ctx, cancel := context.WithTimeout(l.base.lifetime, 15*time.Second)
	defer cancel()
	if err := l.guard(ctx); err != nil {
		return l.fence(err)
	}
	o, err := l.base.observe(ctx)
	if err != nil {
		return l.fence(err)
	}
	known := reflect.DeepEqual(o, l.baseline)
	if tx := l.base.active; tx != nil {
		known = known || len(tx.operations) >= 1 && l.matches(o, tx.revision, false) || len(tx.operations) >= 2 && l.matches(o, tx.revision, true)
	}
	if !known {
		return l.fence(ErrObservation)
	}
	if err := l.base.restoreUnder(ctx); err != nil {
		return l.fence(err)
	}
	o, err = l.base.observe(ctx)
	if err != nil || !reflect.DeepEqual(o, l.baseline) {
		return l.fence(ErrObservation)
	}
	l.fact = LeaseFact{}
	return outcome, nil
}

// Withdraw restores the original pre-lease LAN/empty-WAN baseline. WANWithdrawn
// from Refresh instead means authority expired/changed; neither outcome claims
// successful restoration of an earlier DHCP lease.
func (l *LeaseExecutor) Withdraw(ctx context.Context) (LeaseOutcome, error) {
	if l == nil || l.base == nil {
		return LeaseFenced, ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.base.ready(ctx); err != nil {
		return LeaseFenced, err
	}
	if err := l.observeExpected(ctx); err != nil {
		return l.fence(err)
	}
	return l.withdrawLocked(LeaseBaselineRestored)
}

// Verify is read-only. Expiry requires the owner/controller to call Refresh;
// this experimental adapter cannot be used as an autonomous forwarding guard.
func (l *LeaseExecutor) Verify(ctx context.Context) error {
	if l == nil || l.base == nil {
		return ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.base.ready(ctx); err != nil {
		return err
	}
	if err := l.observeExpected(ctx); err != nil {
		_, e := l.fence(err)
		return e
	}
	if l.base.active == nil {
		return ErrLeaseUnavailable
	}
	return l.sameFact(ctx, l.fact)
}

// Close never silently discards ownership of installed WAN state.
func (l *LeaseExecutor) Close() error {
	if l == nil || l.base == nil {
		return ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.base.active != nil {
		return ErrBusy
	}
	return l.base.Close()
}
