package networkexecutor

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
)

// LeaseObservationV4 is trusted source progress, never effect authority. Margin
// is mutually exclusive with Fact. No decoder or public request accepts it.
type LeaseObservationV4 struct {
	Epoch  uint64
	Fact   LeaseFact
	Margin *LeaseMarginObservationV4
}

// Immutable, closure-only identity/address association. It deliberately contains
// neither a lease deadline nor a conversion to LeaseFact or an owned reference.
type LeaseMarginObservationV4 struct {
	owner       LeaseOwner
	desiredHash string
	epoch       uint64
	address     string
}

func NewLeaseMarginObservationV4(owner LeaseOwner, desiredHash string, epoch uint64, addressHint string) (*LeaseMarginObservationV4, error) {
	boot := owner.BootID
	if owner.Namespace == 0 || owner.PID <= 1 || owner.StartTicks == 0 || !leaseGateHex(owner.RunID, 32) || !leaseGateHex(owner.Incarnation, 32) || len(boot) != 36 || boot[8] != '-' || boot[13] != '-' || boot[18] != '-' || boot[23] != '-' || !leaseGateHex(strings.ReplaceAll(boot, "-", ""), 32) || !leaseGateHex(desiredHash, 64) || epoch == 0 || !leaseObservationAddressV4(addressHint) {
		return nil, ErrScope
	}
	return &LeaseMarginObservationV4{owner, desiredHash, epoch, addressHint}, nil
}

func leaseObservationAddressV4(address string) bool {
	p, err := netip.ParsePrefix(address)
	if err != nil || p.String() != address || !p.Addr().Is4() || p.Addr().IsUnspecified() || p.Addr().IsLoopback() || p.Addr().IsMulticast() || p.Bits() < 1 || p.Bits() > 30 {
		return false
	}
	raw := p.Addr().As4()
	mask := uint32(1)<<uint(32-p.Bits()) - 1
	host := binary.BigEndian.Uint32(raw[:]) & mask
	return host != 0 && host != mask
}

type leaseObservationPendingV4 struct {
	retained LeaseFact
	valid    bool
}

func (*leaseObservationPendingV4) Error() string { return "ANDEIVA_LEASE_OBSERVATION_PENDING_V4" }

func pendingLeaseObservationV4(err error) *leaseObservationPendingV4 {
	pending, ok := err.(*leaseObservationPendingV4)
	if !ok || pending == nil || !pending.valid {
		return nil
	}
	return pending
}

// NewLeaseObservationPendingV4 is only for trusted in-process adapters and
// their tests after independent observation. It validates retained shape, not
// provenance or liveness, and always returns an error, never effect authority.
// No decoder or public request may invoke it to classify untrusted evidence.
func NewLeaseObservationPendingV4(retained LeaseFact) error {
	if _, err := NewLeaseMarginObservationV4(retained.Owner, retained.DesiredHash, retained.Sequence, retained.Address); err != nil || retained.Revoked || retained.DeadlineBootNS <= 0 || !linkName.MatchString(retained.WAN.Name) || retained.WAN.Name == "lo" {
		return ErrScope
	}
	mac, err := net.ParseMAC(retained.WAN.HardwareAddress)
	if err != nil || len(mac) != 6 || mac.String() != retained.WAN.HardwareAddress || mac[0]&1 != 0 || retained.WAN.HardwareAddress == "00:00:00:00:00:00" {
		return ErrScope
	}
	prefix, err := netip.ParsePrefix(retained.Address)
	gateway, gatewayErr := netip.ParseAddr(retained.Gateway)
	if err != nil || gatewayErr != nil || gateway.String() != retained.Gateway || !prefix.Contains(gateway) || gateway == prefix.Addr() || !leaseObservationAddressV4(netip.PrefixFrom(gateway, prefix.Bits()).String()) {
		return ErrScope
	}
	return &leaseObservationPendingV4{retained: retained, valid: true}
}

// The witness suppresses no checks and authorizes only closure/reconciliation.
// Consumers must independently verify all other predicates before classifying it.
// Raw source classification is deliberately direct: wrapping or joining a
// witness with another failure must not hide that failure as pending progress.
func IsLeaseObservationPendingV4(err error) bool { return pendingLeaseObservationV4(err) != nil }
func MatchesLeaseObservationPendingV4(err error, expected LeaseFact) bool {
	p := pendingLeaseObservationV4(err)
	return p != nil && p.retained == expected
}

type leaseObservationSnapshotV4 struct {
	epoch     uint64
	fact      LeaseFact
	margin    LeaseMarginObservationV4
	hasMargin bool
}

func (l *LeaseExecutor) readObservationV4(ctx context.Context) (leaseObservationSnapshotV4, error) {
	var out leaseObservationSnapshotV4
	x, err := l.getObservationV4(ctx)
	// A callback error, even one wrapping an old witness, cannot mint another
	// trusted observation. Keep its original legacy generic-rejection behavior.
	if err != nil || x.Epoch == 0 {
		return out, ErrScope
	}
	out.epoch, out.fact = x.Epoch, x.Fact
	if x.Margin != nil {
		if x.Fact != (LeaseFact{}) {
			return out, ErrScope
		}
		out.margin, out.hasMargin = *x.Margin, true
		m := out.margin
		if m.epoch != x.Epoch || m.owner != l.owner || m.desiredHash != l.desired.Hash || m.address != l.fact.Address || !leaseObservationAddressV4(m.address) {
			return leaseObservationSnapshotV4{}, ErrScope
		}
	}
	return out, nil
}

func (l *LeaseExecutor) validObservationFactV4(f LeaseFact, now int64, live bool) bool {
	if f.Owner != l.owner || f.Sequence == 0 || f.Revoked || f.DesiredHash != l.desired.Hash || f.WAN != l.wan.Binding || f.DeadlineBootNS <= 0 || !leaseObservationAddressV4(f.Address) {
		return false
	}
	if live && f.DeadlineBootNS <= now || f.DeadlineBootNS > now && f.DeadlineBootNS-now > int64(7*24*time.Hour) {
		return false
	}
	config := l.desired.Config
	config.Interfaces = append([]networkplan.Interface(nil), config.Interfaces...)
	for i := range config.Interfaces {
		if config.Interfaces[i].ID == l.wan.ID {
			config.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "static", Address: f.Address, Gateway: f.Gateway}
		}
	}
	_, err := networkplan.Canonical(config)
	return err == nil
}

// VerifyObservationV4 never refreshes fact/seen/deadline or mutates/fences L3.
// Its independent source callback must be read-only and must not reenter lease,
// bootstrap, runtime, gate or forwarding callbacks (the lease lock is held).
func (l *LeaseExecutor) VerifyObservationV4(ctx context.Context) error {
	if l == nil {
		return ErrScope
	}
	if l.getObservationV4 == nil {
		return l.Verify(ctx)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.base == nil || l.base.identity == nil || !validOwnedIdentity(*l.base.identity) || !l.validOwner() || l.base.ready(ctx) != nil || l.base.active == nil || l.guard(ctx) != nil {
		return ErrScope
	}
	now, err := l.now()
	if err != nil || now <= 0 || l.fact.Sequence != l.seen || !l.validObservationFactV4(l.fact, now, false) {
		return ErrScope
	}
	before, err := l.readObservationV4(ctx)
	if err != nil {
		return ErrScope
	}
	kind := uint8(0)
	if before.hasMargin {
		kind = 2
	} else {
		f := before.fact
		if !l.validObservationFactV4(f, now, true) {
			return ErrScope
		}
		if f != l.fact {
			if f.Sequence <= l.fact.Sequence || f.Address != l.fact.Address || f.Gateway != l.fact.Gateway {
				return ErrScope
			}
			kind = 1
		}
	}
	if l.observeExpected(ctx) != nil || l.observeExpected(ctx) != nil {
		return ErrScope
	}
	after, err := l.readObservationV4(ctx)
	if err != nil || after != before || l.guard(ctx) != nil || l.base.ready(ctx) != nil {
		return ErrScope
	}
	end, err := l.now()
	if err != nil || end < now || !before.hasMargin && !l.validObservationFactV4(after.fact, end, true) {
		return ErrScope
	}
	if kind != 0 {
		return NewLeaseObservationPendingV4(l.fact)
	}
	return nil
}
