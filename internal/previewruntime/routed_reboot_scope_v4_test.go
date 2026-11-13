package previewruntime

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

type rebootChannelFixtureV4 struct {
	*freshScopeChannelFixtureV3
	proof configpoc.RoutedRebootScopeEvidenceV4
	calls int
}

func (f *rebootChannelFixtureV4) ProveRebootScope(_ context.Context, work string) (configpoc.RoutedRebootScopeEvidenceV4, error) {
	f.calls++
	if work != f.proof.Work {
		return configpoc.RoutedRebootScopeEvidenceV4{}, ErrIdentity
	}
	return f.proof, nil
}

func TestRoutedRebootScopeV4PrivateChannelAndFence(t *testing.T) {
	// Pipe double exercises protocol/fence only, not root receipt provenance.
	authority := &routedTransportAuthorityV3{}
	s, err := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if err != nil {
		t.Fatal(err)
	}
	marker := &integrityMarkerFixtureV3{}
	s.integrity = &routedIntegrityGateV3{fence: marker, anchor: integrityRefFixtureV3(), phase: routedIntegrityReconcilingV3}
	s.inventory = func(context.Context) (networkinventory.Snapshot, error) {
		return networkinventory.Snapshot{}, ErrIdentity
	}
	next := authority.Identity()
	old := next
	old.BootID = "22345678-1234-1234-1234-123456789abc"
	old.RunID = strings.Repeat("b", 32)
	proof := configpoc.RoutedRebootScopeEvidenceV4{Version: 4, Old: old, New: next, Work: strings.Repeat("c", 64), ReceiptSHA256: strings.Repeat("d", 64), MetadataSHA256: strings.Repeat("e", 64), DrainedAtOldBootNS: 1 << 61, ObservedAtNewBootNS: 1, Before: strings.Repeat("f", 64), Dependencies: strings.Repeat("a", 64)}
	witness := &rebootChannelFixtureV4{freshScopeChannelFixtureV3: &freshScopeChannelFixtureV3{}, proof: proof}
	s.rebootScope = witness
	s.integrity.anchor = configpoc.SelectionReferenceV2{}
	if _, err = s.dispatch(context.Background(), firewallipc.RoutedCommandV3{Verb: "reboot_scope", FreshScope: firewallipc.RoutedFreshScopeRequestV3{Work: proof.Work}}); err == nil || witness.calls != 0 {
		t.Fatal("new boot issued proof before anchor")
	}
	s.integrity.anchor = integrityRefFixtureV3()
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeRoutedV3(ctx, b, next.RunID) }()
	c, err := firewallipc.ConnectRoutedRebootScopeV4(ctx, a, next.RunID, next.Namespace, false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	remote := &routedRebootScopeRemoteV4{c}
	got, err := remote.ProveRebootScope(ctx, proof.Work)
	if err != nil || got != proof || !c.RebootScopeEnabled() || c.FreshScopeEnabled() {
		t.Fatal("reboot proof", err)
	}
	if _, err = c.Call(ctx, "fresh_scope", firewallipc.RoutedFreshScopeRequestV3{Work: proof.Work}); err == nil {
		t.Fatal("v3 request accepted on v4")
	}
	_ = marker.MarkBlocked()
	if _, err = remote.ProveRebootScope(ctx, proof.Work); err == nil || witness.calls != 1 {
		t.Fatal("receipt bypassed fence", err)
	}
	_ = c.Close()
	<-done
}
