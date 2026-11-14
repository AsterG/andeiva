package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type dhcpRuntimeForwardV3 struct{ k *dhcpRuntimeKernelV3 }

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
