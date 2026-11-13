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
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/recoveryreserve"
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
	for name, mutate := range map[string]func(*routedSelectedPreflightBootstrapV4){
		"profile":                func(v *routedSelectedPreflightBootstrapV4) { v.Version = 3 },
		"nonce":                  func(v *routedSelectedPreflightBootstrapV4) { v.Nonce = "bad" },
		"root reader":            func(v *routedSelectedPreflightBootstrapV4) { v.IDs.HelperUID = 0 },
		"owner reader collision": func(v *routedSelectedPreflightBootstrapV4) { v.Access[0].ReaderGID = v.IDs.APIGID },
		"retirement work":        func(v *routedSelectedPreflightBootstrapV4) { v.Work.Work = strings.Repeat("c", 64) },
		"unknown purpose":        func(v *routedSelectedPreflightBootstrapV4) { v.Purpose = "apply" },
		"DHCP no work":           func(v *routedSelectedPreflightBootstrapV4) { v.Purpose = RoutedPreflightDHCPV4 },
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
