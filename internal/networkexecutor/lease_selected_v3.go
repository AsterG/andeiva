package networkexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"

	"github.com/AsterG/andeiva/internal/networkplan"
)

func leaseSelectedDigestV3(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// LeaseSelectedSnapshotV3 describes a verified LAN/empty-WAN baseline and one
// proposed owned WAN delta. It is data, not recovery authority. Only selected
// work authenticated by the caller can authorize its use after process loss.
// It deliberately does not relax PreparedSnapshot's empty-IPv4 contract.
type LeaseSelectedSnapshotV3 struct {
	Version          int                    `json:"version"`
	Identity         OwnedNamespaceIdentity `json:"identity"`
	Desired          networkplan.Revision   `json:"desired"`
	OwnerPID         uint32                 `json:"owner_pid"`
	OwnerStartTicks  uint64                 `json:"owner_start_ticks,string"`
	OwnerIncarnation string                 `json:"owner_incarnation"`
	Sequence         uint64                 `json:"sequence,string"`
	DeadlineBootNS   int64                  `json:"deadline_boot_ns,string"`
	WANIndex         int                    `json:"wan_index"`
	WAN              networkplan.Binding    `json:"wan"`
	Address          string                 `json:"address"`
	Gateway          string                 `json:"gateway"`
	Metric           uint32                 `json:"metric"`
	RouteTable       string                 `json:"route_table"`
	RouteProtocol    string                 `json:"route_protocol"`
	Links            []SnapshotLink         `json:"baseline_links"`
	Routes           []SnapshotRoute        `json:"baseline_routes"`
	Hash             string                 `json:"hash"`
}

func (s LeaseSelectedSnapshotV3) Fact() LeaseFact {
	return LeaseFact{Owner: LeaseOwner{Namespace: s.Identity.Namespace, BootID: s.Identity.BootID, RunID: s.Identity.RunID, PID: s.OwnerPID, StartTicks: s.OwnerStartTicks, Incarnation: s.OwnerIncarnation}, Sequence: s.Sequence, DeadlineBootNS: s.DeadlineBootNS, DesiredHash: s.Desired.Hash, WAN: s.WAN, Address: s.Address, Gateway: s.Gateway}
}

func CanonicalLeaseSelectedSnapshotV3(input LeaseSelectedSnapshotV3) (LeaseSelectedSnapshotV3, error) {
	if !leaseGateHex(input.Hash, 64) {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	s, err := canonicalLeaseSelectedV3(input)
	if err != nil || s.Hash != input.Hash {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	return s, nil
}

func canonicalLeaseSelectedV3(input LeaseSelectedSnapshotV3) (LeaseSelectedSnapshotV3, error) {
	if input.Version != 3 || !validOwnedIdentity(input.Identity) || input.OwnerPID <= 1 || input.OwnerStartTicks == 0 || !leaseGateHex(input.OwnerIncarnation, 32) || input.Sequence == 0 || input.DeadlineBootNS <= 0 || input.WANIndex <= 0 || input.RouteTable != "main" || input.RouteProtocol != "static" || len(input.Links) < 2 || len(input.Links) > 3 || len(input.Routes) > 4 {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	r, err := networkplan.Canonical(input.Desired.Config)
	if err != nil || r.Hash != input.Desired.Hash || len(r.Config.Interfaces) != 2 || r.Config.DNS.Mode != "none" || r.Config.DefaultRoute.Metric != input.Metric {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	var wan, lan networkplan.Interface
	for _, i := range r.Config.Interfaces {
		switch {
		case i.Role == networkplan.WAN && i.IPv4.Mode == "dhcp":
			wan = i
		case i.Role == networkplan.LAN && i.IPv4.Mode == "static" && netip.MustParsePrefix(i.IPv4.Address).Bits() <= 30:
			lan = i
		default:
			return LeaseSelectedSnapshotV3{}, ErrScope
		}
	}
	if wan.ID == "" || lan.ID == "" || wan.Binding != input.WAN || r.Config.DefaultRoute.InterfaceID != wan.ID {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	projected := r.Config
	projected.Interfaces = append([]networkplan.Interface(nil), r.Config.Interfaces...)
	for i := range projected.Interfaces {
		if projected.Interfaces[i].ID == wan.ID {
			projected.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "static", Address: input.Address, Gateway: input.Gateway}
		}
	}
	if _, err := networkplan.Canonical(projected); err != nil {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	p, err := netip.ParsePrefix(input.Address)
	if err != nil || p.Bits() > 30 {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	// Detach before sorting or retaining any nested caller-owned slice.
	b, err := json.Marshal(input)
	if err != nil || len(b) > MaxPreparedSnapshot {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	var s LeaseSelectedSnapshotV3
	if json.Unmarshal(b, &s) != nil {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	s.Desired = r
	l2 := observation{Links: append([]link(nil), s.Links...)}
	for i := range l2.Links {
		l2.Links[i].Addresses = nil
	}
	l2, err = canonicalEmptyObservation(l2)
	if err != nil {
		return LeaseSelectedSnapshotV3{}, err
	}
	for i := range l2.Links {
		for _, old := range s.Links {
			if old.Name == l2.Links[i].Name {
				l2.Links[i].Addresses = append([]address{}, old.Addresses...)
			}
		}
		if l2.Links[i].Name == wan.Binding.Name && l2.Links[i].Index != s.WANIndex {
			return LeaseSelectedSnapshotV3{}, ErrScope
		}
	}
	s.Links = l2.Links
	sortRoutes(s.Routes)
	for i := 1; i < len(s.Routes); i++ {
		if reflect.DeepEqual(s.Routes[i-1], s.Routes[i]) {
			return LeaseSelectedSnapshotV3{}, ErrScope
		}
	}
	o := observation{Links: s.Links, Routes: s.Routes}
	if _, err := networkplan.Bind(r, o.inventory()); err != nil {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	if !o.matches(networkplan.Revision{Config: networkplan.Config{Interfaces: []networkplan.Interface{lan}}}, o) {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	s.Hash = ""
	b, err = json.Marshal(s)
	if err != nil || len(b) > MaxPreparedSnapshot {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	s.Hash = leaseSelectedDigestV3(b)
	return s, nil
}

// PrepareSelectedSnapshotV3 captures the actual retained baseline and the
// current proposed grant before effects. It does not claim the target is applied.
func (l *LeaseExecutor) PrepareSelectedSnapshotV3(ctx context.Context) (LeaseSelectedSnapshotV3, error) {
	if l == nil || l.base == nil {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.base == nil || l.base.identity == nil {
		return LeaseSelectedSnapshotV3{}, ErrScope
	}
	if err := l.observeExpected(ctx); err != nil {
		return LeaseSelectedSnapshotV3{}, err
	}
	f, _, err := l.resolve(ctx)
	if err != nil {
		return LeaseSelectedSnapshotV3{}, err
	}
	s := LeaseSelectedSnapshotV3{Version: 3, Identity: *l.base.identity, Desired: l.desired, OwnerPID: f.Owner.PID, OwnerStartTicks: f.Owner.StartTicks, OwnerIncarnation: f.Owner.Incarnation, Sequence: f.Sequence, DeadlineBootNS: f.DeadlineBootNS, WAN: f.WAN, Address: f.Address, Gateway: f.Gateway, Metric: l.desired.Config.DefaultRoute.Metric, RouteTable: "main", RouteProtocol: "static", Links: l.baseline.Links, Routes: l.baseline.Routes}
	for _, link := range l.baseline.Links {
		if link.Name == l.wan.Binding.Name {
			s.WANIndex = link.Index
		}
	}
	s, err = canonicalLeaseSelectedV3(s)
	if err != nil {
		return LeaseSelectedSnapshotV3{}, err
	}
	if err = l.sameFact(ctx, f); err != nil {
		return LeaseSelectedSnapshotV3{}, err
	}
	return s, nil
}

type LeaseSelectedStateV3 string

const (
	LeaseSelectedBaselineV3 LeaseSelectedStateV3 = "baseline"
	LeaseSelectedAddressV3  LeaseSelectedStateV3 = "owned-address-only"
	LeaseSelectedTargetV3   LeaseSelectedStateV3 = "owned-target"
)

// recoverLeaseSelectedV3 is read-only. A selected snapshot must be authenticated
// by the store reader BEFORE invocation. Neither hash equality nor an address
// observed in the kernel can establish provenance. New boot/run is refused.
func recoverLeaseSelectedV3(ctx context.Context, base *Executor, options LeaseOptions, snapshot LeaseSelectedSnapshotV3, now func() (int64, error)) (*LeaseExecutor, LeaseSelectedStateV3, error) {
	s, err := CanonicalLeaseSelectedSnapshotV3(snapshot)
	if err != nil || base == nil || base.identity == nil || *base.identity != s.Identity || options.Owner != s.Fact().Owner || options.Desired.Hash != s.Desired.Hash || options.Current == nil || now == nil {
		return nil, "", ErrScope
	}
	r, err := networkplan.Canonical(options.Desired.Config)
	if err != nil || r.Hash != s.Desired.Hash {
		return nil, "", ErrScope
	}
	l := &LeaseExecutor{base: base, desired: r, owner: options.Owner, current: options.Current, now: now, baseline: observation{Links: s.Links, Routes: s.Routes}, seen: s.Sequence}
	for _, i := range r.Config.Interfaces {
		if i.Role == networkplan.WAN {
			l.wan = i
		} else {
			l.lan = i
		}
	}
	if err := l.guard(ctx); err != nil {
		return nil, "", err
	}
	first, err := base.observe(ctx)
	if err != nil {
		return nil, "", err
	}
	second, err := base.observe(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return nil, "", ErrObservation
	}
	if reflect.DeepEqual(first, l.baseline) {
		return l, LeaseSelectedBaselineV3, nil
	}
	projected := r.Config
	projected.Interfaces = append([]networkplan.Interface(nil), r.Config.Interfaces...)
	for i := range projected.Interfaces {
		if projected.Interfaces[i].ID == l.wan.ID {
			projected.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "static", Address: s.Address, Gateway: s.Gateway}
		}
	}
	realized, err := networkplan.Canonical(projected)
	if err != nil {
		return nil, "", ErrScope
	}
	full := l.matches(first, realized, true)
	if !full && !l.matches(first, realized, false) {
		return nil, "", ErrObservation
	}
	tx := &transaction{revision: realized, baseline: l.baseline, operations: []operation{{kind: "address-add", name: l.wan.Binding.Name, address: s.Address}}}
	state := LeaseSelectedAddressV3
	if full {
		tx.operations = append(tx.operations, operation{kind: "route-add", name: l.wan.Binding.Name, gateway: s.Gateway, metric: s.Metric})
		state = LeaseSelectedTargetV3
	}
	base.active = tx
	l.fact = s.Fact()
	return l, state, nil
}

// WithdrawSelectedV3 also accepts the exactly authenticated address-only partial
// state reconstructed above. It never recreates an old lease or touches LAN.
func (l *LeaseExecutor) WithdrawSelectedV3(ctx context.Context) (LeaseOutcome, error) {
	if l == nil || l.base == nil {
		return LeaseFenced, ErrScope
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.base.ready(ctx); err != nil {
		return LeaseFenced, err
	}
	return l.withdrawLocked(LeaseWANWithdrawn)
}
