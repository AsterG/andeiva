package previewruntime

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

func retirementReceiptFixtureV3() RootRetirementReceiptV3 {
	return RootRetirementReceiptV3{Version: 3, Old: networkexecutor.OwnedNamespaceIdentity{UID: 62002, GID: 62003, Namespace: 42, Host: 40, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32)}, MetadataSHA256: strings.Repeat("b", 64), DrainedAtBootNS: 1000}
}

type freshScopeChannelFixtureV3 struct {
	proof configpoc.RoutedFreshScopeEvidenceV3
}

func (f *freshScopeChannelFixtureV3) ProveFreshScope(_ context.Context, work string) (configpoc.RoutedFreshScopeEvidenceV3, error) {
	if work != f.proof.Work {
		return configpoc.RoutedFreshScopeEvidenceV3{}, ErrIdentity
	}
	return f.proof, nil
}
func (*freshScopeChannelFixtureV3) verifyPlan(context.Context, configpoc.RoutedSelectedPlanV1) error {
	return ErrIdentity
}
func (*freshScopeChannelFixtureV3) Close() error { return nil }

func TestRoutedFreshScopeV3PrivateChannelBindsReplyAndRejectsRequestProof(t *testing.T) {
	// Transport double only: this does not qualify root receipt FDs or kernel.
	authority := &routedTransportAuthorityV3{}
	s, err := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if err != nil {
		t.Fatal(err)
	}
	s.integrity = &routedIntegrityGateV3{}
	s.inventory = func(context.Context) (networkinventory.Snapshot, error) {
		return networkinventory.Snapshot{}, ErrIdentity
	}
	next := authority.Identity()
	old := next
	old.Namespace++
	old.RunID = strings.Repeat("b", 32)
	proof := configpoc.RoutedFreshScopeEvidenceV3{Version: 3, Old: old, New: next, Work: strings.Repeat("c", 64), ReceiptSHA256: strings.Repeat("d", 64), MetadataSHA256: strings.Repeat("e", 64), DrainedAtBootNS: 10, ObservedAtBootNS: 20, Before: strings.Repeat("f", 64), Dependencies: strings.Repeat("a", 64)}
	s.freshScope = &freshScopeChannelFixtureV3{proof}
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.ServeRoutedV3(ctx, b, next.RunID) }()
	c, err := firewallipc.ConnectRoutedFreshScopeV3(ctx, a, next.RunID, next.Namespace, false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	remote := &routedFreshScopeRemoteV3{c}
	got, err := remote.ProveFreshScope(ctx, proof.Work)
	if err != nil || got != proof {
		t.Fatal("helper evidence", err)
	}
	if _, err = c.Call(ctx, "fresh_scope", map[string]any{"work": proof.Work, "proof": proof}); err == nil {
		t.Fatal("caller-supplied authority accepted")
	}
	_ = c.Close()
	<-done
}

func TestRootRetirementReceiptV3FixedSizeAndIntegrity(t *testing.T) {
	r := retirementReceiptFixtureV3()
	raw, err := EncodeRootRetirementReceiptV3(r)
	if err != nil || len(raw) != RootRetirementReceiptSizeV3 {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeRootRetirementReceiptV3(raw)
	if err != nil || got.Old != r.Old || got.MetadataSHA256 != r.MetadataSHA256 || got.DrainedAtBootNS != r.DrainedAtBootNS || len(got.IntegritySHA256) != 64 {
		t.Fatalf("decode: %v", err)
	}
	for name, bad := range map[string][]byte{
		"empty-slot":    make([]byte, RootRetirementReceiptSizeV3),
		"truncated":     raw[:len(raw)-1],
		"appended":      append(append([]byte{}, raw...), ' '),
		"changed-body":  bytes.Replace(raw, []byte(`"drained_at_boot_ns":1000`), []byte(`"drained_at_boot_ns":1001`), 1),
		"padding-write": append(append([]byte{}, raw[:len(raw)-1]...), '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRootRetirementReceiptV3(bad); err == nil {
				t.Fatal("unproven receipt accepted")
			}
		})
	}
}

func TestRootRetirementReceiptV3RejectsUnprovenScope(t *testing.T) {
	for name, mutate := range map[string]func(*RootRetirementReceiptV3){
		"root-helper":   func(r *RootRetirementReceiptV3) { r.Old.UID = 0 },
		"host":          func(r *RootRetirementReceiptV3) { r.Old.Namespace = r.Old.Host },
		"zero-time":     func(r *RootRetirementReceiptV3) { r.DrainedAtBootNS = 0 },
		"caller-digest": func(r *RootRetirementReceiptV3) { r.IntegritySHA256 = strings.Repeat("c", 64) },
		"metadata":      func(r *RootRetirementReceiptV3) { r.MetadataSHA256 = "missing" },
		"run":           func(r *RootRetirementReceiptV3) { r.Old.RunID = strings.Repeat("A", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			r := retirementReceiptFixtureV3()
			mutate(&r)
			if _, err := EncodeRootRetirementReceiptV3(r); err == nil {
				t.Fatal("invalid receipt encoded")
			}
		})
	}
}
