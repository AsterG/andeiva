//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
	"github.com/AsterG/andeiva/internal/routednft"
)

func preflightBootstrapFixtureV4() routedSelectedPreflightBootstrapV4 {
	ids := Identities{SchemaVersion: 1, APIUID: 1001, APIGID: 1002, HelperUID: 1003, IPCGID: 1004}
	m := Metadata{SchemaVersion: 2, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: 11, GatewayNamespace: 22}
	b := routedSelectedPreflightBootstrapV4{Version: 4, Nonce: strings.Repeat("b", 32), Parent: 123, Start: 456, Metadata: m, IDs: ids, Purpose: RoutedPreflightRetirementV4, Identity: networkexecutor.OwnedNamespaceIdentity{UID: ids.HelperUID, GID: ids.IPCGID, Namespace: 22, Host: 11, BootID: m.BootID, RunID: m.RunID}}
	for i := range b.Access {
		b.Access[i] = recoveryreserve.ReaderAccessV2{Version: 1, OwnerUID: 1001, ReaderGID: 1005}
	}
	return b
}

func TestRoutedSelectedPreflightV4CaplessProcessAndBoundedCodec(t *testing.T) {
	b := preflightBootstrapFixtureV4()
	status := "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n"
	if !b.valid() || routedPreflightProcessV4(1003, 1003, 1004, 1004, []int{1005}, status, b) != nil {
		t.Fatal("valid capless reader rejected")
	}
	lan := b
	lan.Purpose = RoutedPreflightDHCPServerV1
	lan.Work = configpoc.RoutedWorkReferenceV1{Work: strings.Repeat("c", 64), Lineage: "lineage", Generation: 1}
	if !lan.valid() || routedPreflightProcessV4(1003, 1003, 1004, 1004, []int{1005}, status, lan) != nil {
		t.Fatal("valid capless LAN preflight rejected")
	}
	for name, mutate := range map[string]func(*routedSelectedPreflightBootstrapV4){
		"profile":                func(v *routedSelectedPreflightBootstrapV4) { v.Version = 3 },
		"nonce":                  func(v *routedSelectedPreflightBootstrapV4) { v.Nonce = "bad" },
		"root reader":            func(v *routedSelectedPreflightBootstrapV4) { v.IDs.HelperUID = 0 },
		"owner reader collision": func(v *routedSelectedPreflightBootstrapV4) { v.Access[0].ReaderGID = v.IDs.APIGID },
		"retirement work":        func(v *routedSelectedPreflightBootstrapV4) { v.Work.Work = strings.Repeat("c", 64) },
		"unknown purpose":        func(v *routedSelectedPreflightBootstrapV4) { v.Purpose = "apply" },
		"DHCP no work":           func(v *routedSelectedPreflightBootstrapV4) { v.Purpose = RoutedPreflightDHCPV4 },
		"LAN DHCP no work":       func(v *routedSelectedPreflightBootstrapV4) { v.Purpose = RoutedPreflightDHCPServerV1 },
	} {
		t.Run(name, func(t *testing.T) {
			v := b
			mutate(&v)
			if v.valid() {
				t.Fatal("accepted")
			}
		})
	}
	for name, groups := range map[string][]int{"missing reader": {1004}, "foreign group": {1005, 0}} {
		t.Run(name, func(t *testing.T) {
			if routedPreflightProcessV4(1003, 1003, 1004, 1004, groups, status, b) == nil {
				t.Fatal("accepted")
			}
		})
	}
	if routedPreflightProcessV4(0, 0, 1004, 1004, []int{1005}, status, b) == nil || routedPreflightProcessV4(1003, 1003, 1004, 1004, []int{1005}, strings.ReplaceAll(status, "0000000000000000", "0000000000001000"), b) == nil {
		t.Fatal("root or NET_ADMIN accepted")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var decoded routedSelectedPreflightBootstrapV4
	if routedPrivateDecodeV4(raw, &decoded) != nil {
		t.Fatal("roundtrip")
	}
	for _, bad := range [][]byte{append(raw, raw...), bytes.Replace(raw, []byte(`"version":4`), []byte(`"Version":4`), 1), bytes.Replace(raw, []byte(`"version":4`), []byte(`"version":4,"version":4`), 1), bytes.Repeat([]byte(" "), routedPrivateFrameV4+1), []byte(`null`)} {
		if routedPrivateDecodeV4(bad, &decoded) == nil {
			t.Fatal("malformed frame accepted")
		}
	}
}

func TestRoutedSelectedPreflightV4LANServerTarget(t *testing.T) {
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{
		{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}},
		{Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}},
	}, Services: []localpolicy.Service{}}
	localRevision, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
	if err != nil {
		t.Fatal(err)
	}
	bundleFor := func(policy routednft.Policy) configpoc.RoutedActivationBundleV1 {
		t.Helper()
		firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := configpoc.NewRoutedActivationBundleV1(firewall, localRevision)
		if err != nil {
			t.Fatal(err)
		}
		return bundle
	}
	policy := routednft.LabPolicy()
	legacy := bundleFor(policy)
	policy.SchemaVersion = 2
	policy.DHCPServer = &dhcpserver.Config{SchemaVersion: 1, Enabled: true, Scopes: []dhcpserver.Scope{{
		ID: "office", InterfaceID: "lan", Subnet: "198.18.0.0/24", Router: "198.18.0.1",
		Pools:        []dhcpserver.Pool{{First: "198.18.0.10", Last: "198.18.0.20"}},
		LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000,
	}}}
	enabled := bundleFor(policy)
	policy.DHCPServer.Enabled = false
	disabled := bundleFor(policy)
	identity := preflightBootstrapFixtureV4().Identity
	work := configpoc.RoutedWorkReferenceV1{Work: strings.Repeat("c", 64), Lineage: "lineage", Generation: 1}
	result := RoutedSelectedPreflightResultV4{
		Identity: identity, Work: work, Bundle: enabled, Resolution: "target",
		Reference: configpoc.SelectionReferenceV2{Selection: strings.Repeat("d", 64), State: strings.Repeat("e", 64), WorkHash: work.Work, Lineage: work.Lineage, Mode: "active"},
	}
	if routedPreflightResultV4(result, RoutedPreflightDHCPServerV1, identity, work) != nil {
		t.Fatal("canonical active LAN server policy rejected")
	}
	if routedPreflightResultV4(result, RoutedPreflightDHCPV4, identity, work) == nil {
		t.Fatal("static WAN treated as a DHCP acquisition plan")
	}
	for name, mutate := range map[string]func(*RoutedSelectedPreflightResultV4){
		"legacy policy": func(v *RoutedSelectedPreflightResultV4) { v.Bundle = legacy },
		"disabled":      func(v *RoutedSelectedPreflightResultV4) { v.Bundle = disabled },
		"unresolved":    func(v *RoutedSelectedPreflightResultV4) { v.Resolution = "" },
		"before side":   func(v *RoutedSelectedPreflightResultV4) { v.Resolution = "before" },
		"pending":       func(v *RoutedSelectedPreflightResultV4) { v.Reference.Mode = "pending" },
		"foreign scope": func(v *RoutedSelectedPreflightResultV4) { v.Identity.Namespace++ },
		"forged work":   func(v *RoutedSelectedPreflightResultV4) { v.Reference.WorkHash = strings.Repeat("f", 64) },
		"stale work":    func(v *RoutedSelectedPreflightResultV4) { v.Work.Generation++ },
		"forged bundle": func(v *RoutedSelectedPreflightResultV4) { v.Bundle.Composite.Hash = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			v := result
			mutate(&v)
			if routedPreflightResultV4(v, RoutedPreflightDHCPServerV1, identity, work) == nil {
				t.Fatal("invalid server preflight accepted")
			}
		})
	}
}

func TestRoutedSelectedPreflightV4RealFullReaderCorrelation(t *testing.T) {
	f := newRoutedIPCFixtureWithPolicyV3(t, configpoc.SelectionFullHistoryV2)
	ctx := context.Background()
	out, err := routedReadPreflightV4(ctx, f.reader, RoutedPreflightRetirementV4, f.identity, configpoc.RoutedWorkReferenceV1{})
	if err != nil || out.Identity != f.identity || out.Reference.WorkHash == "" {
		t.Fatal("current full-history source", err)
	}
	if routedPreflightResultV4(out, RoutedPreflightRetirementV4, f.identity, configpoc.RoutedWorkReferenceV1{}) != nil {
		t.Fatal("result rejected")
	}
	foreign := f.identity
	foreign.RunID = strings.Repeat("e", 32)
	if _, err = routedReadPreflightV4(ctx, f.reader, RoutedPreflightRetirementV4, foreign, configpoc.RoutedWorkReferenceV1{}); err == nil {
		t.Fatal("foreign scope accepted")
	}
	if _, err = routedReadPreflightV4(ctx, f.reader, RoutedPreflightDHCPV4, f.identity, configpoc.RoutedWorkReferenceV1{Work: out.Reference.WorkHash, Lineage: out.Reference.Lineage, Generation: 1}); err == nil {
		t.Fatal("NoNetwork treated as DHCP")
	}
	plan, err := f.reader.Resolve(ctx, out.Reference, configpoc.SelectionMatchTargetV2)
	if err != nil {
		t.Fatal("NoNetwork selected plan", err)
	}
	if _, err = routedReadPreflightV4(ctx, f.reader, RoutedPreflightDHCPServerV1, f.identity, plan.Reference()); err == nil {
		t.Fatal("NoNetwork treated as DHCP server")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = routedReadPreflightV4(cancelled, f.reader, RoutedPreflightRetirementV4, f.identity, configpoc.RoutedWorkReferenceV1{}); err == nil {
		t.Fatal("cancelled read accepted")
	}
}

func TestRoutedSelectedPreflightV4NonRootCannotLaunch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root boundary")
	}
	if _, err := ReadRoutedSelectedPreflightV4(context.Background(), RoutedSelectedPreflightOptionsV4{}); err == nil {
		t.Fatal("non-root launcher")
	}
}
