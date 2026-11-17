//go:build linux

package previewruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/nftguardian"
	"github.com/AsterG/andeiva/internal/routedactivation"
	"github.com/AsterG/andeiva/internal/routednft"
)

type observationChainNetworkV4 struct {
	*routedTestNetwork
	pending func() error
}

func (n observationChainNetworkV4) VerifyObservationV4(ctx context.Context) error {
	if err := n.routedTestNetwork.Verify(ctx); err != nil {
		return err
	}
	return n.pending()
}

type observationChainWorkV4 struct {
	routedDHCPWorkV3
	running string
}

func (w observationChainWorkV4) Running() string { return w.running }

type observationChainReaderV4 struct {
	*dhcpRuntimeReaderV3
	running string
}

func (r observationChainReaderV4) Resolve(ctx context.Context, hash string) (routedDHCPWorkV3, error) {
	w, err := r.dhcpRuntimeReaderV3.Resolve(ctx, hash)
	if err != nil {
		return nil, err
	}
	return observationChainWorkV4{w, r.running}, nil
}

// Only kernel/network/listener I/O is doubled. Engine, Group, semantic nft
// readback, authority Observe, integrity inspection and GateAuthority are real.
func observationChainAuthorityV4(t *testing.T, pending func() error) (*RoutedAuthority, *routedTestKernel, *routedTestNetwork, *routedTestListeners, string) {
	t.Helper()
	ctx := context.Background()
	policy := routednft.LabPolicy()
	legacy, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 4, DefaultAction: "deny", Rules: []configpoc.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}}, {Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}}}, Services: []localpolicy.Service{}}
	localRevision, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
	if err != nil {
		t.Fatal(err)
	}
	firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		t.Fatal(err)
	}
	target, err := configpoc.NewRoutedActivationBundleV1(firewall, localRevision)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := networkexecutor.PreparedSnapshot{Version: 1, PlanHash: policy.Network.Hash, Links: []networkexecutor.SnapshotLink{
		{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}},
		{Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", MTU: 1500, Flags: []string{"UP"}, Addresses: []networkexecutor.SnapshotAddress{}},
	}, Routes: []networkexecutor.SnapshotRoute{}}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	snapshot.Hash = hex.EncodeToString(sum[:])
	kernel := &routedTestKernel{objects: map[routedactivation.Table][]map[string]any{}}
	initial, err := firewallnft.Compile(legacy.Config)
	if err != nil || kernel.Apply(ctx, initial.Create) != nil {
		t.Fatal("initial deny", err)
	}
	network := &routedTestNetwork{snapshot: snapshot}
	listeners := &routedTestListeners{}
	plan := configpoc.RoutedTransitionV1{Version: 1, Operation: "observation-chain", Previous: strings.Repeat("1", 64), Target: strings.Repeat("2", 64), BeforeOwned: strings.Repeat("3", 64), TargetOwned: strings.Repeat("4", 64), Dependencies: strings.Repeat("5", 64)}
	started := time.Now().UTC()
	var prepared routedactivation.PreparationV1
	engine, err := routedactivation.New(kernel, observationChainNetworkV4{network, pending}, listeners, routedactivation.Options{Legacy: legacy, ResolvePlan: func(call context.Context, got configpoc.RoutedTransitionV1, previous *configpoc.RoutedActivationBundleV1, bundle configpoc.RoutedActivationBundleV1, deadline time.Time) (routedactivation.PreparationV1, error) {
		if call.Err() != nil || got != plan || previous != nil || bundle.Composite.Hash != target.Composite.Hash || !deadline.Equal(started.Add(10*time.Second)) {
			return routedactivation.PreparationV1{}, configpoc.ErrRecovery
		}
		return prepared, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err = engine.Prepare(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	group, err := nftguardian.NewGroup(engine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = group.Close() })
	if err = group.BootstrapStartup(ctx, plan, target, started); err != nil {
		t.Fatal("bootstrap", err)
	}
	state, hash, err := group.SnapshotObservedContext(ctx)
	if err != nil || hash != target.Composite.Hash {
		t.Fatal(state, hash, err)
	}
	if err = group.ConfirmLease(ctx, plan, state); err != nil {
		t.Fatal("confirm", err)
	}
	return &RoutedAuthority{engine: engine, group: group}, kernel, network, listeners, target.Composite.Hash
}

func TestRoutedDHCPObservationChainV4LateMarginClosesAndFreshInspectionRecovers(t *testing.T) {
	ctx := context.Background()
	r, k, reader, fact := dhcpRuntimeFixtureV3(t)
	masked, maskOnPolicy := false, false
	retained := fact.Fact
	authority, policyKernel, policyNetwork, listeners, running := observationChainAuthorityV4(t, func() error {
		if masked {
			return networkexecutor.NewLeaseObservationPendingV4(retained)
		}
		return nil
	})
	r.reader = observationChainReaderV4{reader, running}
	r.current = func(context.Context) (RoutedDHCPOwnerFactV3, error) {
		if masked {
			return RoutedDHCPOwnerFactV3{}, routedDHCPMarginClosedV4{fact.Epoch + 1, fact.Fact.Address}
		}
		return *fact, nil
	}
	s, integrityReader, _ := integritySessionFixtureV3(t)
	if _, err := s.integrity.attach(ctx, integrityReader.ref); err != nil {
		t.Fatal(err)
	}
	inspect := func() {
		t.Helper()
		result, err := s.integrity.inspect(ctx, integrityReader.ref, authority)
		if err != nil || result.State != configpoc.IntegrityCompleteV1 {
			t.Fatal("full inspection", result, err)
		}
	}
	inspect()
	r.ready = func() error {
		s.integrity.mu.Lock()
		defer s.integrity.mu.Unlock()
		if s.integrity.blockedLocked() || s.integrity.phase != routedIntegrityReadyV3 {
			return configpoc.ErrRecovery
		}
		return nil
	}
	r.refreshReady = func() bool {
		s.integrity.mu.Lock()
		defer s.integrity.mu.Unlock()
		return !s.integrity.blockedLocked() && s.integrity.lastComplete != (configpoc.SelectionReferenceV2{}) && (s.integrity.phase == routedIntegrityReadyV3 || s.integrity.phase == routedIntegrityReconcilingV3)
	}
	policyCalls := 0
	r.policy = func(call context.Context, p routedDHCPWorkV3) error {
		policyCalls++
		if r.ready() != nil {
			return configpoc.ErrRecovery
		}
		if maskOnPolicy {
			masked = true
			maskOnPolicy = false
		}
		receipt, hash, err := authority.Observe(call)
		if err != nil {
			return errors.Join(configpoc.ErrRecovery, err)
		}
		if !integrityPhysicalIdleV3(receipt, hash) || hash != p.Running() {
			return configpoc.ErrRecovery
		}
		return nil
	}
	if err := r.SetRenewalProfileV4(RoutedDHCPSameEffectiveRenewalV4); err != nil {
		t.Fatal(err)
	}
	grant, err := r.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	work := &dhcpRuntimeWorkV3{grant: grant, phase: "prepared", hash: strings.Repeat("e", 64)}
	reader.work = work
	if err = r.apply(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	work.phase = "applied"
	if err = r.open(ctx, work.hash); err != nil {
		t.Fatal(err)
	}
	gate, watermark, stages := r.gate, k.grant, k.stages
	writes, networkEffects, listenerEffects := len(policyKernel.batches), policyNetwork.calls, listeners.calls
	beforePolicy := policyCalls
	maskOnPolicy = true
	err = (routedDHCPGateAuthorityV3{r}).Verify(ctx, watermark)
	if !errors.Is(err, networkexecutor.ErrLeaseGateMarginClosed) || errors.Is(err, networkexecutor.ErrLeaseGateRenewal) || !masked || policyCalls != beforePolicy+1 {
		t.Fatal("late policy margin did not traverse real Engine/Group classification", err, policyCalls, beforePolicy)
	}
	if closeErr := r.closeRenewalErrorV4(ctx, err); !errors.Is(closeErr, networkexecutor.ErrLeaseGateMarginClosed) {
		t.Fatal(closeErr)
	}
	if r.forward.VerifyClosed(ctx) != nil || r.gate.VerifyClosedSelectedV3(ctx) != nil || r.opened || !r.renewalWaiting || r.gate != gate || k.grant != watermark || k.stages != stages || !reflect.DeepEqual(r.grant, grant) || reader.work != work {
		t.Fatal("closure changed retained Work, gate or watermark", k.events)
	}
	// A real inspection while masked cannot qualify the gate. A later fresh
	// grant first refreshes proof under closure; only full inspection restores Ready.
	result, err := s.integrity.inspect(ctx, integrityReader.ref, authority)
	if err != nil || result.State == configpoc.IntegrityCompleteV1 || r.ready() == nil {
		t.Fatal("masked inspection qualified readiness", result, err)
	}
	next := grant
	next.Epoch += 2
	next.Snapshot = dhcpRuntimeRenewedSnapshotV4(t, grant.Snapshot)
	*fact = RoutedDHCPOwnerFactV3{Epoch: next.Epoch, Fact: next.Snapshot.Fact()}
	k.snapshot = next.Snapshot
	masked = false
	proofs := 0
	r.lease = dhcpRuntimeRenewableLeaseV4{dhcpRuntimeLeaseV3{k}, func(context.Context, networkexecutor.LeaseSelectedSnapshotV3, networkexecutor.LeaseSelectedSnapshotV3) error {
		if k.forward || k.gate || !k.target {
			return configpoc.ErrRecovery
		}
		proofs++
		return nil
	}}
	if _, err = r.renewSameEffectiveModeV4(ctx, work.hash, next.Snapshot.Hash, true); !errors.Is(err, configpoc.ErrRecovery) || proofs != 1 || k.gate || k.forward || r.ready() == nil {
		t.Fatal("closed refresh bypassed inspection", err, proofs)
	}
	inspect()
	if _, err = r.renewSameEffectiveV4(ctx, work.hash, next.Snapshot.Hash); err != nil || !r.opened || !k.gate || !k.forward || r.gate != gate || reader.work != work || k.grant.Fact != next.Snapshot.Fact() || k.stages != stages+1 {
		t.Fatal("fresh inspected grant failed to reopen same gate", err, k.events)
	}
	if len(policyKernel.batches) != writes || policyNetwork.calls != networkEffects || listeners.calls != listenerEffects {
		t.Fatal("read-only recovery reapplied policy/network/listeners")
	}
}
