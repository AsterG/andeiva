package previewruntime

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routednft"
)

// Explicit kernel/selected-reader doubles. These tests prove orchestration and
// wire rejection, not native packets, owner FD authentication or physical R2.
type dhcpRuntimeWorkV3 struct {
	grant       configpoc.RoutedDHCPGrantV3
	phase, hash string
	generation  uint64
}

func (p dhcpRuntimeWorkV3) Reference() configpoc.SelectionReferenceV2 {
	return configpoc.SelectionReferenceV2{WorkHash: p.hash, Generation: p.generation}
}
func (p dhcpRuntimeWorkV3) Snapshot() networkexecutor.LeaseSelectedSnapshotV3 {
	return p.grant.Snapshot
}
func (p dhcpRuntimeWorkV3) Epoch() uint64   { return p.grant.Epoch }
func (p dhcpRuntimeWorkV3) Phase() string   { return p.phase }
func (p dhcpRuntimeWorkV3) Running() string { return strings.Repeat("d", 64) }

type dhcpRuntimeReaderV3 struct {
	work   *dhcpRuntimeWorkV3
	denied bool
	events *[]string
	after  func()
	last   *networkexecutor.LeaseSelectedSnapshotV3
}

func (x *dhcpRuntimeReaderV3) Resolve(_ context.Context, hash string) (routedDHCPWorkV3, error) {
	*x.events = append(*x.events, "selected")
	if x.denied || x.work == nil || hash != x.work.hash {
		return nil, configpoc.ErrRecovery
	}
	p := *x.work
	if x.after != nil {
		x.after()
	}
	return p, nil
}
func (x *dhcpRuntimeReaderV3) VerifyDHCPReleasedV3(context.Context) error {
	if x.denied || x.work != nil {
		return configpoc.ErrRecovery
	}
	return nil
}
func (x *dhcpRuntimeReaderV3) LastWithdrawnDHCPV3(ctx context.Context) (*networkexecutor.LeaseSelectedSnapshotV3, error) {
	return x.last, x.VerifyDHCPReleasedV3(ctx)
}

type dhcpRuntimeKernelV3 struct {
	events                []string
	forward, gate, target bool
	authority             networkexecutor.LeaseGateAuthority
	grant                 networkexecutor.LeaseGateGrant
	stages                int
	fact                  *RoutedDHCPOwnerFactV3
	snapshot              networkexecutor.LeaseSelectedSnapshotV3
	failOpen              bool
	failDispose           bool
	disposed              bool
}

func (k *dhcpRuntimeKernelV3) Initialize(context.Context) error {
	k.events = append(k.events, "initialize")
	return nil
}

func (k *dhcpRuntimeKernelV3) RecoverClosedSelectedV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3) error {
	k.events = append(k.events, "recover-gate")
	k.gate = false
	return nil
}
func (k *dhcpRuntimeKernelV3) RecoverWithdrawnSelectedV3(ctx context.Context, _ networkexecutor.LeaseSelectedSnapshotV3) error {
	return k.VerifyClosedSelectedV3(ctx)
}
func (k *dhcpRuntimeKernelV3) VerifyClosedSelectedV3(context.Context) error {
	if k.gate || k.forward {
		return configpoc.ErrRecovery
	}
	return nil
}
func (k *dhcpRuntimeKernelV3) DisposeWithdrawnSelectedV3(ctx context.Context, s networkexecutor.LeaseSelectedSnapshotV3) error {
	k.events = append(k.events, "dispose-gate")
	if k.failDispose || k.disposed || !reflect.DeepEqual(s, k.snapshot) || k.VerifyClosedSelectedV3(ctx) != nil {
		return configpoc.ErrRecovery
	}
	k.disposed = true
	return nil
}
func (k *dhcpRuntimeKernelV3) Close(context.Context) error {
	k.events = append(k.events, "gate-close")
	k.gate = false
	return nil
}
func (k *dhcpRuntimeKernelV3) Stage(ctx context.Context) error {
	if k.gate || k.forward {
		return configpoc.ErrRecovery
	}
	g, err := k.authority.Current(ctx)
	if err != nil || k.authority.Verify(ctx, g) != nil {
		return configpoc.ErrRecovery
	}
	k.grant = g
	k.stages++
	k.events = append(k.events, "stage")
	return nil
}
func (k *dhcpRuntimeKernelV3) Open(ctx context.Context) error {
	if k.failOpen || k.forward || k.authority.Verify(ctx, k.grant) != nil {
		return configpoc.ErrRecovery
	}
	k.events = append(k.events, "open")
	k.gate = true
	return nil
}
func (k *dhcpRuntimeKernelV3) Verify(ctx context.Context) error {
	if !k.gate {
		return configpoc.ErrRecovery
	}
	return k.authority.Verify(ctx, k.grant)
}

func (k *dhcpRuntimeKernelV3) VerifyRetainedV4(_ context.Context, grant networkexecutor.LeaseGateGrant) error {
	if !k.gate || k.grant != grant {
		return configpoc.ErrRecovery
	}
	return nil
}

type dhcpRuntimeForwardV3 struct{ k *dhcpRuntimeKernelV3 }

func (f dhcpRuntimeForwardV3) VerifyOpen(context.Context) error {
	if !f.k.forward {
		return configpoc.ErrRecovery
	}
	return nil
}

func (f dhcpRuntimeForwardV3) Disable(context.Context) error {
	f.k.events = append(f.k.events, "forward-off")
	f.k.forward = false
	return nil
}
func (f dhcpRuntimeForwardV3) VerifyClosed(context.Context) error {
	if f.k.forward {
		return configpoc.ErrRecovery
	}
	return nil
}
func (f dhcpRuntimeForwardV3) Enable(ctx context.Context, verify func(context.Context) error) error {
	if verify(ctx) != nil {
		return configpoc.ErrRecovery
	}
	f.k.events = append(f.k.events, "forward-on")
	f.k.forward = true
	return verify(ctx)
}

type dhcpRuntimeLeaseV3 struct{ k *dhcpRuntimeKernelV3 }

type dhcpRuntimeRenewableLeaseV4 struct {
	dhcpRuntimeLeaseV3
	refresh func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error
}

type dhcpRuntimeInterleavedLeaseV4 struct {
	routedDHCPLeaseV3
	verify func() error
}

func (l dhcpRuntimeInterleavedLeaseV4) VerifySelectedStateV3(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedStateV3) error {
	return l.verify()
}

func (l dhcpRuntimeRenewableLeaseV4) RefreshSameEffectiveSelectedV4(ctx context.Context, previous, next networkexecutor.LeaseSelectedSnapshotV3) error {
	return l.refresh(ctx, previous, next)
}

func (l dhcpRuntimeLeaseV3) PrepareSelectedSnapshotV3(context.Context) (networkexecutor.LeaseSelectedSnapshotV3, error) {
	return l.k.snapshot, nil
}
func (l dhcpRuntimeLeaseV3) Refresh(context.Context) (networkexecutor.LeaseOutcome, error) {
	if l.k.forward || l.k.gate {
		return networkexecutor.LeaseFenced, configpoc.ErrRecovery
	}
	l.k.events = append(l.k.events, "L3-add")
	l.k.target = true
	return networkexecutor.LeaseApplied, nil
}
func (l dhcpRuntimeLeaseV3) VerifySelectedStateV3(_ context.Context, s networkexecutor.LeaseSelectedSnapshotV3, state networkexecutor.LeaseSelectedStateV3) error {
	if state == networkexecutor.LeaseSelectedBaselineV3 && !l.k.target && networkexecutor.ValidateSameEffectiveLeaseV4(s, l.k.snapshot) == nil {
		return nil // Baseline proof is physical and requires no live old grant.
	}
	if !reflect.DeepEqual(s, l.k.snapshot) || (state == networkexecutor.LeaseSelectedBaselineV3 && l.k.target) || (state == networkexecutor.LeaseSelectedTargetV3 && (!l.k.target || l.k.fact.Fact.Revoked || l.k.fact.Fact != s.Fact())) {
		return configpoc.ErrRecovery
	}
	return nil
}
func (l dhcpRuntimeLeaseV3) WithdrawSelectedV3(context.Context) (networkexecutor.LeaseOutcome, error) {
	if l.k.forward || l.k.gate {
		return networkexecutor.LeaseFenced, configpoc.ErrRecovery
	}
	l.k.events = append(l.k.events, "L3-withdraw")
	l.k.target = false
	return networkexecutor.LeaseWANWithdrawn, nil
}

func dhcpRuntimeSnapshotV3(t *testing.T) networkexecutor.LeaseSelectedSnapshotV3 {
	t.Helper()
	p := routednft.LabPolicy().Network.Config
	for i := range p.Interfaces {
		if p.Interfaces[i].Role == networkplan.WAN {
			p.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "dhcp"}
		}
	}
	n, err := networkplan.Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	s := networkexecutor.LeaseSelectedSnapshotV3{Version: 3, Identity: (&routedTransportAuthorityV3{}).Identity(), Desired: n, OwnerPID: 50, OwnerStartTicks: 123, OwnerIncarnation: strings.Repeat("b", 32), Sequence: 1, DeadlineBootNS: int64(240 * time.Second), WANIndex: 3, WAN: n.Config.Interfaces[1].Binding, Address: "198.19.0.1/24", Gateway: "198.19.0.2", Metric: n.Config.DefaultRoute.Metric, RouteTable: "main", RouteProtocol: "static", Links: []networkexecutor.SnapshotLink{
		{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{{Family: "inet", Local: "198.18.0.1", Bits: 24, Scope: "global", Label: "lan0", Valid: 4294967295, Preferred: 4294967295}}},
		{Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}}}, Routes: []networkexecutor.SnapshotRoute{{Destination: "198.18.0.0/24", Device: "lan0", Protocol: "kernel", Scope: "link", Source: "198.18.0.1", Table: "main", Type: "unicast"}, {Destination: "198.18.0.1", Device: "lan0", Protocol: "kernel", Scope: "host", Source: "198.18.0.1", Table: "local", Type: "local"}}}
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	s.Hash = hex.EncodeToString(h[:])
	s, err = networkexecutor.CanonicalLeaseSelectedSnapshotV3(s)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func dhcpRuntimeFixtureV3(t *testing.T) (*RoutedDHCPRuntimeV3, *dhcpRuntimeKernelV3, *dhcpRuntimeReaderV3, *RoutedDHCPOwnerFactV3) {
	t.Helper()
	s := dhcpRuntimeSnapshotV3(t)
	fact := &RoutedDHCPOwnerFactV3{Epoch: 1, Fact: s.Fact()}
	k := &dhcpRuntimeKernelV3{fact: fact, snapshot: s}
	reader := &dhcpRuntimeReaderV3{events: &k.events}
	r := &RoutedDHCPRuntimeV3{identity: s.Identity, owner: s.Fact().Owner, reader: reader, current: func(context.Context) (RoutedDHCPOwnerFactV3, error) { return *fact, nil }, ready: func() error { return nil }, policy: func(context.Context, routedDHCPWorkV3) error { k.events = append(k.events, "policy"); return nil }, forward: dhcpRuntimeForwardV3{k}}
	r.buildGate = func(_ context.Context, a networkexecutor.LeaseGateAuthority) (routedDHCPGateV3, error) {
		k.authority = a
		return k, nil
	}
	r.fenced = func() bool { return false }
	r.baseline = func(context.Context) error {
		if k.target || k.forward || k.gate {
			return configpoc.ErrRecovery
		}
		return nil
	}
	r.openLease = func(context.Context) (routedDHCPLeaseV3, error) { return dhcpRuntimeLeaseV3{k}, nil }
	r.recoverLease = func(_ context.Context, s networkexecutor.LeaseSelectedSnapshotV3) (routedDHCPLeaseV3, error) {
		k.events = append(k.events, "recover-lease")
		if !reflect.DeepEqual(s, k.snapshot) {
			return nil, configpoc.ErrRecovery
		}
		return dhcpRuntimeLeaseV3{k}, nil
	}
	r.releaseLease = func(context.Context) error { k.events = append(k.events, "release"); return nil }
	return r, k, reader, fact
}

func dhcpRuntimeRenewedSnapshotV4(t *testing.T, previous networkexecutor.LeaseSelectedSnapshotV3) networkexecutor.LeaseSelectedSnapshotV3 {
	t.Helper()
	next := previous
	next.Sequence++
	next.DeadlineBootNS += int64(time.Second)
	next.Hash = ""
	b, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	next.Hash = hex.EncodeToString(h[:])
	canonical, err := networkexecutor.CanonicalLeaseSelectedSnapshotV3(next)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestRoutedDHCPRuntimeV4SameEffectiveRenewalKeepsSelectionAndClosesFirst(t *testing.T) {
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	previous, err := r.begin(context.Background())
	if err != nil {
		t.Fatal("begin", err)
	}
	work := &dhcpRuntimeWorkV3{grant: previous, phase: "prepared", hash: strings.Repeat("e", 64), generation: 4}
	reader.work = work
	if err = r.apply(context.Background(), work.hash); err != nil {
		t.Fatal("apply", err)
	}
	work.phase = "applied"
	if err = r.open(context.Background(), work.hash); err != nil {
		t.Fatal("open", err)
	}
	retainedGate := r.gate
	next := previous
	next.Epoch++
	next.Snapshot = dhcpRuntimeRenewedSnapshotV4(t, previous.Snapshot)
	*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
	k.snapshot = next.Snapshot // New owner evidence, while selected work remains immutable.
	var refreshCalls int
	r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(_ context.Context, gotPrevious, gotNext networkexecutor.LeaseSelectedSnapshotV3) error {
		refreshCalls++
		if k.forward || k.gate || !k.target || !reflect.DeepEqual(gotPrevious, previous.Snapshot) || !reflect.DeepEqual(gotNext, next.Snapshot) {
			return configpoc.ErrRecovery
		}
		k.events = append(k.events, "renew-proof")
		return nil
	}}
	ctx := context.Background()
	if r.lease.VerifySelectedStateV3(ctx, previous.Snapshot, networkexecutor.LeaseSelectedTargetV3) == nil {
		t.Fatal("superseded lease unexpectedly verified as current")
	}
	if err := (routedDHCPGateAuthorityV3{r}).Verify(ctx, networkexecutor.LeaseGateGrant{WorkHash: work.hash, Fact: previous.Snapshot.Fact()}); !errors.Is(err, networkexecutor.ErrLeaseGateRenewal) {
		t.Fatal("same-effective owner race was not classified for a closed renewal handoff", err)
	}
	k.events = nil
	out, err := r.renewSameEffectiveV4(context.Background(), work.hash, next.Snapshot.Hash)
	if err != nil || !reflect.DeepEqual(out, next) || refreshCalls != 1 {
		t.Fatal("renew", out, err, refreshCalls)
	}
	if r.gate != retainedGate || r.work != work.hash || !reflect.DeepEqual(work.Snapshot(), previous.Snapshot) || !reflect.DeepEqual(r.grant, next) {
		t.Fatal("renewal rewrote immutable selected work")
	}
	if !k.gate || !k.forward || !k.target || !r.opened || r.renewalWaiting {
		t.Fatal("renewal did not safely restore forwarding")
	}
	closeIndex, proofIndex, openIndex := -1, -1, -1
	for i, event := range k.events {
		switch event {
		case "gate-close":
			closeIndex = i
		case "renew-proof":
			proofIndex = i
		case "open":
			openIndex = i
		case "L3-add", "L3-withdraw":
			t.Fatal("same-effective renewal changed L3", k.events)
		}
	}
	if closeIndex < 0 || proofIndex <= closeIndex || openIndex <= proofIndex {
		t.Fatal("unsafe renewal order", k.events)
	}
	// A retried RPC after its reply was lost is idempotent and does not reopen
	// or refresh the selected L3 proof a second time.
	count := func(event string) int {
		n := 0
		for _, got := range k.events {
			if got == event {
				n++
			}
		}
		return n
	}
	proofs, opens, forwardsOn := count("renew-proof"), count("open"), count("forward-on")
	if got, retryErr := r.renewSameEffectiveV4(context.Background(), work.hash, next.Snapshot.Hash); retryErr != nil || !reflect.DeepEqual(got, next) || refreshCalls != 1 || count("renew-proof") != proofs || count("open") != opens || count("forward-on") != forwardsOn {
		t.Fatal("lost-reply retry", retryErr, refreshCalls, k.events)
	}
}

func TestRoutedDHCPRuntimeV4ChangedGrantClosesBeforeRejectingRenewal(t *testing.T) {
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	previous, err := r.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	work := &dhcpRuntimeWorkV3{grant: previous, phase: "applied", hash: strings.Repeat("f", 64), generation: 5}
	reader.work = work
	r.work, r.grant, r.lease = work.hash, previous, dhcpRuntimeLeaseV3{k}
	// Model an already-applied selected target and an open forwarding token.
	k.target, k.gate, k.forward = true, true, true
	k.grant = networkexecutor.LeaseGateGrant{WorkHash: work.hash, Fact: previous.Snapshot.Fact()}
	r.opened = true
	changed := dhcpRuntimeRenewedSnapshotV4(t, previous.Snapshot)
	changed.Address = "198.19.0.9/24"
	changed.Hash = ""
	b, _ := json.Marshal(changed)
	h := sha256.Sum256(b)
	changed.Hash = hex.EncodeToString(h[:])
	changed, err = networkexecutor.CanonicalLeaseSelectedSnapshotV3(changed)
	if err != nil {
		t.Fatal(err)
	}
	*fact = RoutedDHCPOwnerFactV3{Epoch: previous.Epoch + 1, Fact: changed.Fact()}
	k.snapshot = changed
	k.events = nil
	if _, err = r.renewSameEffectiveV4(context.Background(), work.hash, changed.Hash); err == nil {
		t.Fatal("changed tuple accepted")
	}
	if k.gate || k.forward || r.opened || !r.renewalWaiting {
		t.Fatal("invalid renewal left old forwarding open", k.events)
	}
}

func TestRoutedDHCPRuntimeV4ReplayCannotRestorePermission(t *testing.T) {
	for _, invalid := range []string{"epoch-replay", "sequence-replay"} {
		t.Run(invalid, func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
				t.Fatal(err)
			}
			previous, err := r.begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			work := &dhcpRuntimeWorkV3{grant: previous, phase: "prepared", hash: strings.Repeat("c", 64)}
			reader.work = work
			if err = r.apply(ctx, work.hash); err != nil {
				t.Fatal(err)
			}
			work.phase = "applied"
			if err = r.open(ctx, work.hash); err != nil {
				t.Fatal(err)
			}
			gate, stages := r.gate, k.stages
			next := configpoc.RoutedDHCPGrantV3{Epoch: previous.Epoch + 1, Snapshot: dhcpRuntimeRenewedSnapshotV4(t, previous.Snapshot)}
			switch invalid {
			case "epoch-replay":
				next.Epoch = previous.Epoch
			case "sequence-replay":
				next.Snapshot.Sequence = previous.Snapshot.Sequence
			}
			next.Snapshot.Hash = ""
			data, _ := json.Marshal(next.Snapshot)
			hash := sha256.Sum256(data)
			next.Snapshot.Hash = hex.EncodeToString(hash[:])
			next.Snapshot, err = networkexecutor.CanonicalLeaseSelectedSnapshotV3(next.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
			k.snapshot = next.Snapshot
			r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
				t.Error("replayed authority reached proof refresh")
				return configpoc.ErrRecovery
			}}
			if _, err = r.renewSameEffectiveV4(ctx, work.hash, next.Snapshot.Hash); err == nil {
				t.Fatal("invalid grant accepted")
			}
			if r.opened || k.gate || k.forward || !k.target || k.stages != stages || r.gate != gate || r.work != work.hash || !reflect.DeepEqual(r.grant, previous) || !reflect.DeepEqual(work.grant, previous) {
				t.Fatal("invalid authority restored permission or replaced retained work/gate")
			}
		})
	}
}

func TestRoutedDHCPRuntimeV4RetirementAfterRenewalsKeepsTerminalGate(t *testing.T) {
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	ctx := context.Background()
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	initial, err := r.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	work := &dhcpRuntimeWorkV3{grant: initial, phase: "prepared", hash: strings.Repeat("c", 64)}
	reader.work = work
	if err = r.apply(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	work.phase = "applied"
	if err = r.open(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	retainedGate := r.gate
	r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
		if k.forward || k.gate || !k.target {
			return configpoc.ErrRecovery
		}
		return nil
	}}
	for range 2 {
		next := configpoc.RoutedDHCPGrantV3{Epoch: r.grant.Epoch + 1, Snapshot: dhcpRuntimeRenewedSnapshotV4(t, r.grant.Snapshot)}
		*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
		k.snapshot = next.Snapshot
		if _, err = r.renewSameEffectiveV4(ctx, work.hash, next.Snapshot.Hash); err != nil {
			t.Fatal(err)
		}
	}
	consumedSequence := k.grant.Fact.Sequence
	if consumedSequence <= initial.Snapshot.Sequence || r.gate != retainedGate {
		t.Fatal("renewals replaced the gate or lost its consumed sequence")
	}
	if err = r.withdraw(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	reader.work, reader.last = nil, &initial.Snapshot
	if err = r.retire(ctx); err != nil {
		t.Fatal("terminal retirement failed", err)
	}
	if !r.retired || r.failed || r.gate != retainedGate || k.disposed || r.work != "" || r.lease != nil || k.gate || k.forward || k.target || k.grant.Fact.Sequence != consumedSequence {
		t.Fatal("retirement replaced the gate, reset its sequence, retained L3, or invented an integrity failure")
	}
	releases := 0
	for _, event := range k.events {
		if event == "release" {
			releases++
		}
	}
	if releases != 1 {
		t.Fatal("terminal retirement did not release its lease exactly once")
	}
	for _, replay := range []RoutedDHCPOwnerFactV3{{Epoch: initial.Epoch, Fact: initial.Snapshot.Fact()}, *fact} {
		*fact = replay
		k.events = nil
		if _, err = r.begin(ctx); err == nil || len(k.events) != 0 || r.lease != nil || r.work != "" {
			t.Fatal("retired instance admitted another acquisition", err)
		}
		if _, err = r.renewSameEffectiveV4(ctx, work.hash, initial.Snapshot.Hash); err == nil {
			t.Fatal("retired instance accepted a replay")
		}
		if r.SetRenewalProfileV4(RoutedDHCPLegacyRenewalV4) == nil {
			t.Fatal("retired instance changed its profile")
		}
	}
	// The owning helper retains exactly this closed gate until resource cleanup.
	if err = r.closeUnder(ctx); err != nil || r.gate != retainedGate || r.gate.VerifyClosedSelectedV3(ctx) != nil || k.grant.Fact.Sequence != consumedSequence {
		t.Fatal("terminal cleanup changed retained authority", err)
	}
	releases = 0
	for _, event := range k.events {
		if event == "release" {
			releases++
		}
		if event == "initialize" || event == "stage" || event == "open" || event == "L3-add" {
			t.Fatal("cleanup reacquired or reset authority")
		}
	}
	if releases != 0 {
		t.Fatal("terminal cleanup released the lease twice")
	}
}

func TestRoutedDHCPRuntimeV4RenewalProofFailureKeepsForwardingClosed(t *testing.T) {
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	ctx := context.Background()
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	previous, err := r.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	work := &dhcpRuntimeWorkV3{grant: previous, phase: "prepared", hash: strings.Repeat("d", 64), generation: 4}
	reader.work = work
	if err = r.apply(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	work.phase = "applied"
	if err = r.open(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	next := configpoc.RoutedDHCPGrantV3{Epoch: previous.Epoch + 1, Snapshot: dhcpRuntimeRenewedSnapshotV4(t, previous.Snapshot)}
	*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
	k.snapshot = next.Snapshot
	proofs := 0
	r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
		proofs++
		if k.forward || k.gate || r.opened {
			t.Fatal("renewal proof ran before verified closure")
		}
		return networkexecutor.ErrObservation
	}}
	// Classification permits closing the obsolete token, never opening a new one.
	if err = (routedDHCPGateAuthorityV3{r}).Verify(ctx, k.grant); !errors.Is(err, networkexecutor.ErrLeaseGateRenewal) {
		t.Fatal("same-effective renewal not classified", err)
	}
	k.events = nil
	if _, err = r.renewSameEffectiveV4(ctx, work.hash, next.Snapshot.Hash); err == nil || proofs != 1 {
		t.Fatal("failed physical proof accepted", err, proofs)
	}
	if k.forward || k.gate || r.opened || !reflect.DeepEqual(r.grant, previous) || !reflect.DeepEqual(work.Snapshot(), previous.Snapshot) {
		t.Fatal("failed renewal restored authority or rewrote selected work")
	}
	for _, event := range k.events {
		if event == "stage" || event == "open" || event == "forward-on" {
			t.Fatal("failed proof reached activation", k.events)
		}
	}
}

func TestRoutedDHCPRuntimeV4RenewalDuringAuthorityChecksOnlyRequestsClosure(t *testing.T) {
	for _, phase := range []string{"lease", "policy", "final-owner"} {
		t.Run(phase, func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
				t.Fatal(err)
			}
			previous, err := r.begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			work := &dhcpRuntimeWorkV3{grant: previous, phase: "prepared", hash: strings.Repeat("e", 64)}
			reader.work = work
			if err = r.apply(ctx, work.hash); err != nil {
				t.Fatal(err)
			}
			work.phase = "applied"
			if err = r.open(ctx, work.hash); err != nil {
				t.Fatal(err)
			}
			next := dhcpRuntimeRenewedSnapshotV4(t, previous.Snapshot)
			advance := func() { *fact = RoutedDHCPOwnerFactV3{Epoch: previous.Epoch + 1, Fact: next.Fact()}; k.snapshot = next }
			switch phase {
			case "lease":
				r.lease = dhcpRuntimeInterleavedLeaseV4{r.lease, func() error { advance(); return configpoc.ErrRecovery }}
			case "policy":
				r.policy = func(context.Context, routedDHCPWorkV3) error { advance(); return configpoc.ErrRecovery }
			case "final-owner":
				reads := 0
				r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
					reads++
					if reads == 2 {
						advance()
					}
					return *fact, nil
				}
			}
			k.events = nil
			err = (routedDHCPGateAuthorityV3{r}).Verify(ctx, k.grant)
			if phase == "policy" || phase == "lease" {
				if err == nil || errors.Is(err, networkexecutor.ErrLeaseGateRenewal) || errors.Is(err, networkexecutor.ErrLeaseGateMarginClosed) {
					t.Fatal("concurrent renewal hid a generic verification failure", err)
				}
			} else if !errors.Is(err, networkexecutor.ErrLeaseGateRenewal) {
				t.Fatal("fresh same-effective race not classified for closure", err)
			}
			if !reflect.DeepEqual(r.grant, previous) || !reflect.DeepEqual(work.grant, previous) || r.renewalWaiting {
				t.Fatal("classification changed authority")
			}
			for _, event := range k.events {
				if event == "stage" || event == "open" || event == "forward-on" {
					t.Fatal("classification opened authority")
				}
			}
		})
	}
}

func TestRoutedDHCPRuntimeV4ReconciliationRefreshWaitsForFullInspection(t *testing.T) {
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	ctx := context.Background()
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	previous, err := r.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	work := &dhcpRuntimeWorkV3{grant: previous, phase: "prepared", hash: strings.Repeat("c", 64)}
	reader.work = work
	if err = r.apply(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	work.phase = "applied"
	if err = r.open(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	next := configpoc.RoutedDHCPGrantV3{Epoch: previous.Epoch + 1, Snapshot: dhcpRuntimeRenewedSnapshotV4(t, previous.Snapshot)}
	*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
	k.snapshot = next.Snapshot
	proofs := 0
	r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
		proofs++
		if k.forward || k.gate || r.opened {
			t.Fatal("refresh before closure")
		}
		return nil
	}}
	ready := false
	r.ready = func() error {
		if !ready {
			return configpoc.ErrRecovery
		}
		return nil
	}
	r.refreshReady = func() bool { return true } // Previously qualified, now Reconciling.
	for attempt := 0; attempt < 2; attempt++ {
		if _, err = r.renewSameEffectiveV4(ctx, work.hash, next.Snapshot.Hash); err == nil {
			t.Fatal("incomplete inspection reported renewal success")
		}
		if k.gate || k.forward || r.opened || !r.renewalWaiting || proofs != 1 || !reflect.DeepEqual(r.grant, next) || ready {
			t.Fatal("refresh opened authority or changed qualification", proofs)
		}
	}
	ready = true // Only the independent full-inspection lane may establish this.
	if got, err := r.renewSameEffectiveV4(ctx, work.hash, next.Snapshot.Hash); err != nil || !reflect.DeepEqual(got, next) || proofs != 1 || !k.gate || !k.forward || !r.opened {
		t.Fatal("qualified retry did not open the refreshed grant exactly once", err, proofs)
	}
}

func TestRoutedDHCPRuntimeV3SelectedLifecycleAndClosureOrder(t *testing.T) {
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	ctx := context.Background()
	g, err := r.begin(ctx)
	if err != nil || k.target || k.forward || k.gate {
		t.Fatal("begin", err)
	}
	work := &dhcpRuntimeWorkV3{grant: g, phase: "prepared", hash: strings.Repeat("c", 64), generation: 1}
	reader.work = work
	if err = r.apply(ctx, work.hash); err != nil {
		t.Fatal("apply", err)
	}
	if err = r.open(ctx, work.hash); err == nil || k.forward || k.gate {
		t.Fatal("opened unselected Applied phase")
	}
	work.phase = "applied"
	if err = r.open(ctx, work.hash); err != nil || !k.forward || !k.gate {
		t.Fatal("open", err)
	}
	stages := k.stages
	if err = r.open(ctx, work.hash); err == nil || k.stages != stages {
		t.Fatal("same work restaged")
	}
	fact.Fact.Revoked = true
	fact.Fact.Sequence++
	k.events = nil
	if err = r.withdraw(ctx, work.hash); err != nil || k.forward || k.gate || k.target {
		t.Fatal("withdraw", err)
	}
	if len(k.events) < 4 || k.events[0] != "gate-close" || k.events[1] != "forward-off" || k.events[2] != "selected" {
		t.Fatal("effects preceded closure", k.events)
	}
	if r.retire(ctx) == nil {
		t.Fatal("released before selected archive")
	}
	reader.work = nil
	reader.last = &g.Snapshot
	if r.retire(ctx) != nil || r.lease != nil || r.work != "" {
		t.Fatal("terminal release")
	}
}

func TestRoutedDHCPRuntimeV3RejectsUnprovenWorkAndOwnerChanges(t *testing.T) {
	for _, mode := range []string{"missing-selection", "wrong-owner", "wrong-phase", "changed-after-read", "open-failure"} {
		t.Run(mode, func(t *testing.T) {
			r, k, reader, fact := dhcpRuntimeFixtureV3(t)
			ctx := context.Background()
			g, err := r.begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			work := &dhcpRuntimeWorkV3{grant: g, phase: "prepared", hash: strings.Repeat("c", 64), generation: 1}
			reader.work = work
			switch mode {
			case "missing-selection":
				reader.denied = true
			case "wrong-owner":
				work.grant.Snapshot.OwnerPID++
			case "wrong-phase":
				work.phase = "applied"
			case "changed-after-read":
				reader.after = func() { fact.Fact.Revoked = true }
			case "open-failure":
				k.failOpen = true
			}
			err = r.apply(ctx, work.hash)
			if mode == "open-failure" {
				if err != nil {
					t.Fatal(err)
				}
				work.phase = "applied"
				err = r.open(ctx, work.hash)
			}
			if err == nil || k.forward || k.gate {
				t.Fatal("invalid authority admitted", err)
			}
			if mode != "open-failure" && k.target {
				t.Fatal("unproven WAN delta survived")
			}
		})
	}
}

func TestRoutedDHCPRuntimeV3FreshHelperOnlyWithdrawsSelectedWAN(t *testing.T) {
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	ctx := context.Background()
	g := configpoc.RoutedDHCPGrantV3{Epoch: fact.Epoch, Snapshot: k.snapshot}
	reader.work = &dhcpRuntimeWorkV3{grant: g, phase: "applied", hash: strings.Repeat("c", 64)}
	k.target = true
	fact.Fact.Revoked = true
	if err := r.withdraw(ctx, reader.work.hash); err != nil || k.target || k.forward || k.gate || !r.withdrawn {
		t.Fatal("selected recovery", err)
	}
	if r.open(ctx, reader.work.hash) == nil {
		t.Fatal("dead owner reopened")
	}
}

func TestRoutedDHCPCurrentRemainsReadOnlyAvailableDuringIntegrityInspection(t *testing.T) {
	r, k, _, _ := dhcpRuntimeFixtureV3(t)
	r.lease = dhcpRuntimeLeaseV3{k}
	r.ready = func() error { return configpoc.ErrRecovery }
	grant, err := r.currentUnder(context.Background())
	if err != nil || grant.Epoch == 0 {
		t.Fatal("read-only current observation was blocked by inspection", err)
	}
	before := append([]string(nil), k.events...)
	if _, err := r.begin(context.Background()); !errors.Is(err, configpoc.ErrRecovery) {
		t.Fatal("effectful begin bypassed inspection readiness", err)
	}
	if !reflect.DeepEqual(before, k.events) || k.target || k.forward || k.gate {
		t.Fatal("inspection-time observation caused dataplane mutation")
	}
}

func TestRoutedDHCPRuntimeV3WatchdogClosesAfterOwnerLoss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, k, reader, fact := dhcpRuntimeFixtureV3(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g, err := r.begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		reader.work = &dhcpRuntimeWorkV3{grant: g, phase: "prepared", hash: strings.Repeat("c", 64)}
		if err = r.apply(ctx, reader.work.hash); err != nil {
			t.Fatal(err)
		}
		reader.work.phase = "applied"
		if err = r.open(ctx, reader.work.hash); err != nil {
			t.Fatal(err)
		}
		fact.Fact.Revoked = true
		done := make(chan struct{})
		go func() { defer close(done); r.Run(ctx) }()
		time.Sleep(time.Second)
		synctest.Wait()
		r.mu.Lock()
		closed := !k.forward && !k.gate && !k.target && r.withdrawn
		r.mu.Unlock()
		cancel()
		<-done
		if !closed {
			t.Fatal("owner loss left permission")
		}
	})
}

func TestRoutedDHCPRuntimeV3WatchdogDoesNotConfuseCheckingWithFence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, k, reader, _ := dhcpRuntimeFixtureV3(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g, err := r.begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		reader.work = &dhcpRuntimeWorkV3{grant: g, phase: "prepared", hash: strings.Repeat("c", 64)}
		if err = r.apply(ctx, reader.work.hash); err != nil {
			t.Fatal(err)
		}
		reader.work.phase = "applied"
		if err = r.open(ctx, reader.work.hash); err != nil {
			t.Fatal(err)
		}
		// Periodic integrity checking temporarily prevents new openings but does
		// not revoke unchanged authority. A persistent fence does revoke it.
		r.ready = func() error { return configpoc.ErrRecovery }
		done := make(chan struct{})
		go func() { defer close(done); r.Run(ctx) }()
		time.Sleep(time.Second)
		synctest.Wait()
		r.mu.Lock()
		if !k.forward || !k.gate || !k.target || r.withdrawn {
			t.Fatal("routine checking revoked current authority")
		}
		r.fenced = func() bool { return true }
		r.mu.Unlock()
		time.Sleep(time.Second)
		synctest.Wait()
		r.mu.Lock()
		closed := !k.forward && !k.gate && !k.target && r.withdrawn
		r.mu.Unlock()
		cancel()
		<-done
		if !closed {
			t.Fatal("persistent fence left permission")
		}
	})
}

func TestRoutedDHCPV3PrivateChannelNegotiatesWithoutRequestOwner(t *testing.T) {
	r, _, _, _ := dhcpRuntimeFixtureV3(t)
	authority := &routedTransportAuthorityV3{}
	s, err := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if err != nil {
		t.Fatal(err)
	}
	s.dhcp = r
	s.integrity = &routedIntegrityGateV3{}
	s.inventory = func(context.Context) (networkinventory.Snapshot, error) {
		return networkinventory.Snapshot{}, ErrUnavailable
	}
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeRoutedV3(ctx, b, r.identity.RunID) }()
	c, err := firewallipc.ConnectRoutedDHCPV3(ctx, a, r.identity.RunID, r.identity.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g, err := c.Call(ctx, "dhcp_begin", firewallipc.RoutedDHCPRequestV3{})
	if err != nil || g.DHCP.Epoch != 1 || g.DHCP.Snapshot.Fact().Owner != r.owner {
		t.Fatal("authenticated helper grant", err)
	}
	if _, err = c.Call(ctx, "dhcp_apply", map[string]any{"work": strings.Repeat("c", 64), "owner_pid": 50}); err == nil {
		t.Fatal("caller supplied owner accepted")
	}
	_ = c.Close()
	<-done
}

func TestRoutedDHCPControllerV3RechecksAfterRenewalRacesLive(t *testing.T) {
	previous := configpoc.RoutedDHCPGrantV3{Epoch: 1, Snapshot: dhcpRuntimeSnapshotV3(t)}
	nextSnapshot := previous.Snapshot
	nextSnapshot.Sequence++
	nextSnapshot.DeadlineBootNS += int64(5 * time.Second)
	nextSnapshot.Hash = ""
	encoded, err := json.Marshal(nextSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	nextSnapshot.Hash = hex.EncodeToString(digest[:])
	nextSnapshot, err = networkexecutor.CanonicalLeaseSelectedSnapshotV3(nextSnapshot)
	if err != nil || networkexecutor.ValidateSameEffectiveLeaseV4(previous.Snapshot, nextSnapshot) != nil {
		t.Fatal("renewal fixture", err)
	}
	next := configpoc.RoutedDHCPGrantV3{Epoch: 2, Snapshot: nextSnapshot}
	work := strings.Repeat("c", 64)
	run, helperRun, ns := strings.Repeat("a", 32), strings.Repeat("f", 32), uint64(22)
	clientConn, helperConn := net.Pipe()
	defer clientConn.Close()
	verbs := make(chan string, 8)
	helperDone := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(helperConn)
		enc := json.NewEncoder(helperConn)
		if !scanner.Scan() {
			helperDone <- scanner.Err()
			return
		}
		hello, e := firewallipc.DecodeRoutedHelloV3(scanner.Bytes(), false)
		if e != nil {
			helperDone <- e
			return
		}
		if e = enc.Encode(firewallipc.RoutedHelloV3{ProtocolVersion: firewallipc.RoutedProtocolV3, RuntimeRun: hello.RuntimeRun, Namespace: hello.Namespace, Domain: hello.Domain, RequiredFeatures: hello.RequiredFeatures, Run: helperRun, Epoch: 1}); e != nil {
			helperDone <- e
			return
		}
		last := uint64(1) << 32
		currentCalls := 0
		for _, want := range []string{"dhcp_current", "dhcp_live", "dhcp_current", "dhcp_renew"} {
			if !scanner.Scan() {
				helperDone <- scanner.Err()
				return
			}
			raw := append([]byte(nil), scanner.Bytes()...)
			req, _, decodeErr := firewallipc.DecodeRoutedRequestV3(raw, helperRun, ns, last)
			if decodeErr != nil || req.Verb != want {
				helperDone <- errors.Join(decodeErr, errors.New("unexpected routed RPC sequence"))
				return
			}
			last = req.Sequence
			verbs <- req.Verb
			payload := json.RawMessage(`{}`)
			code := ""
			switch req.Verb {
			case "dhcp_live":
				code = "ANDEIVA_CONFIG_RECOVERY_REQUIRED"
			case "dhcp_current":
				currentCalls++
				grant := previous
				if currentCalls == 2 {
					grant = next
				}
				payload, _ = json.Marshal(firewallipc.RoutedDHCPGrantV3{Epoch: grant.Epoch, Snapshot: grant.Snapshot})
			case "dhcp_renew":
				var request firewallipc.RoutedDHCPRequestV3
				if json.Unmarshal(req.Payload, &request) != nil || request.Work != work || request.Snapshot != next.Snapshot.Hash {
					helperDone <- errors.New("renewal request did not bind current work and snapshot")
					return
				}
				payload, _ = json.Marshal(firewallipc.RoutedDHCPGrantV3{Epoch: next.Epoch, Snapshot: next.Snapshot})
			}
			reply := firewallipc.RoutedReplyV3{ProtocolVersion: firewallipc.RoutedProtocolV3, Run: helperRun, Sequence: req.Sequence, Namespace: ns, Domain: req.Domain, Verb: req.Verb, Error: code, Payload: payload}
			wire, marshalErr := json.Marshal(reply)
			if marshalErr != nil {
				helperDone <- marshalErr
				return
			}
			if _, _, decodeErr := firewallipc.DecodeRoutedReplyV3(wire, req); decodeErr != nil {
				helperDone <- errors.Join(errors.New(req.Verb+" reply rejected"), decodeErr)
				return
			}
			if e = enc.Encode(reply); e != nil {
				helperDone <- e
				return
			}
		}
		helperDone <- nil
	}()

	ctx := context.Background()
	client, err := firewallipc.ConnectRoutedDHCPRenewalV4(ctx, clientConn, run, ns, false, false)
	if err != nil {
		t.Fatal("connect renewal-capable helper", err)
	}
	controller := &RoutedDHCPControllerV3{remote: &routedDHCPRemoteV3{client: client}, work: work, grant: previous}
	if err := controller.reconcileLocked(ctx); err != nil {
		helperErr := <-helperDone
		t.Fatalf("same-effective renewal race withdrew live selection: %v; fake helper: %v", err, helperErr)
	}
	if controller.work != work || !reflect.DeepEqual(controller.grant, next) {
		t.Fatal("controller rewrote the immutable selected work or operational baseline")
	}
	if err := <-helperDone; err != nil {
		t.Fatal("fake helper", err)
	}
	close(verbs)
	var got []string
	for verb := range verbs {
		got = append(got, verb)
	}
	if !reflect.DeepEqual(got, []string{"dhcp_current", "dhcp_live", "dhcp_current", "dhcp_renew"}) {
		t.Fatalf("RPC sequence = %v", got)
	}
}
