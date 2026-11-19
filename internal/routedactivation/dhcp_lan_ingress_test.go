package routedactivation

import (
	"bytes"
	"context"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/networkplan"
)

type checkedIngressKernel struct {
	kernelFixture
	checked []byte
}

func (k *checkedIngressKernel) Check(ctx context.Context, data []byte) error {
	k.checked = bytes.Clone(data)
	return k.kernelFixture.Check(ctx, data)
}

func lanIngressFixture(t *testing.T) (DependenciesV1, func(string, bool, uint32) configpoc.RoutedActivationBundleV1) {
	t.Helper()
	_, deps, target := artifactFixture(t)
	network := deps.Network.Config
	for i := range network.Interfaces {
		if network.Interfaces[i].Role == networkplan.WAN {
			network.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "dhcp"}
		}
	}
	var err error
	deps.Network, err = networkplan.Canonical(network)
	if err != nil {
		t.Fatal(err)
	}
	return deps, func(scope string, active bool, leaseSeconds uint32) configpoc.RoutedActivationBundleV1 {
		t.Helper()
		fw := target.Firewall.Config
		policy := *fw.Routed
		policy.SchemaVersion = 2
		policy.Network = deps.Network
		policy.DHCPServer = &dhcpserver.Config{SchemaVersion: 1, Enabled: active, Scopes: []dhcpserver.Scope{{
			ID: scope, InterfaceID: "lan", Subnet: "198.18.0.0/24", Router: "198.18.0.1",
			Pools:        []dhcpserver.Pool{{First: "198.18.0.10", Last: "198.18.0.20"}},
			LeaseSeconds: leaseSeconds, RenewSeconds: 60, RebindSeconds: 90,
		}}}
		fw.Routed = &policy
		firewall, err := configpoc.CanonicalRouted(fw)
		if err != nil {
			t.Fatal(err)
		}
		bundle, err := configpoc.NewRoutedActivationBundleV1(firewall, target.LocalServices)
		if err != nil {
			t.Fatal(err)
		}
		return bundle
	}
}

func lanIngressTables(bundle configpoc.RoutedActivationBundleV1) [3]TableStateV1 {
	return [3]TableStateV1{
		{Presence: Absent},
		{Presence: Present, Revision: &bundle.Firewall},
		{Presence: Present, Revision: &bundle.LocalServices},
	}
}

func TestDHCPServerIngressChecksAndRestoresSameNetwork(t *testing.T) {
	deps, bundle := lanIngressFixture(t)
	disabled := bundle("office", false, 120)
	enabled := bundle("office", true, 120)
	changed := bundle("warehouse", true, 120)
	for _, transition := range []struct {
		name           string
		before, target configpoc.RoutedActivationBundleV1
	}{
		{"enable", disabled, enabled},
		{"change scope", enabled, changed},
		{"disable", changed, disabled},
	} {
		t.Run(transition.name, func(t *testing.T) {
			ctx := context.Background()
			before, target := lanIngressTables(transition.before), lanIngressTables(transition.target)
			kernel := &checkedIngressKernel{kernelFixture: kernelFixture{objects: map[Table][]map[string]any{}}}
			engine := &Engine{kernel: kernel, prepared: PreparationV1{Dependencies: deps}}
			targetEnabled := transition.target.Firewall.Config.Routed.DHCPServer.Enabled
			deny, err := denyTablesFor(transition.target, deps)
			if err != nil || deny[RoutedTable].Revision.Config.Routed.DHCPServer.Enabled ||
				transition.target.Firewall.Config.Routed.DHCPServer.Enabled != targetEnabled {
				t.Fatal("deny lost its DHCP fence or mutated the target", err)
			}
			for _, tables := range [][3]TableStateV1{before, target, deny} {
				for i, state := range tables {
					if !engine.remember(i, state) {
						t.Fatal("known fixture state rejected")
					}
				}
			}
			absent := [3]TableStateV1{{Presence: Absent}, {Presence: Absent}, {Presence: Absent}}
			initial, err := engine.compileChange(absent, before, deps)
			if err != nil || kernel.Apply(ctx, initial) != nil {
				t.Fatal("unverified initial tables", err)
			}
			for _, step := range [][2][3]TableStateV1{{before, target}, {target, deny}, {deny, before}} {
				wanted, err := engine.compileChange(step[0], step[1], deps)
				if err != nil || !bytes.Contains(wanted, []byte(`"delete":{"table":{"family":"inet","name":"andeiva_local"}}`)) {
					t.Fatal("no exact LocalTable replacement", err)
				}
				priorLocal := kernel.objects[LocalTable]
				if err := engine.applyTables(ctx, step[1]); err != nil {
					t.Fatal("checked application rejected", err)
				}
				if !bytes.Equal(kernel.checked, wanted) || !bytes.Equal(kernel.batches[len(kernel.batches)-1], wanted) {
					t.Fatal("Check and Apply did not use the same computed batch")
				}
				readback, _, err := kernel.Observe(ctx, LocalTable)
				server := step[1][RoutedTable].Revision.Config.Routed.DHCPServer
				if err != nil || !bytes.Contains(readback, []byte("andeiva-dhcp-acquisition:v1")) ||
					bytes.Contains(readback, []byte("andeiva-dhcp-server:v1:")) != server.Enabled {
					t.Fatal("unexpected WAN acquisition or LAN server control", err)
				}
				if server.Enabled && !bytes.Contains(readback, []byte("andeiva-dhcp-server:v1:"+server.Scopes[0].ID)) {
					t.Fatal("readback contains the wrong scope")
				}
				actual, err := engine.knownTables(ctx)
				if err != nil || actual[RoutedTable].Revision.Hash != step[1][RoutedTable].Revision.Hash {
					t.Fatal("readback did not bind the effective routed policy", err)
				}
				ingress, err := routedLocalIngress(actual[RoutedTable], deps)
				if err != nil {
					t.Fatal(err)
				}
				currentLocal := kernel.objects[LocalTable]
				kernel.objects[LocalTable] = priorLocal
				if engine.tableMatches(ctx, LocalTable, actual[LocalTable], deps, ingress) {
					t.Fatal("current routed policy accepted the previous LocalTable")
				}
				kernel.objects[LocalTable] = currentLocal
			}
		})
	}
}

func TestDHCPServerIngressKeepsTableForLeaseOnlyChange(t *testing.T) {
	deps, bundle := lanIngressFixture(t)
	before, after := lanIngressTables(bundle("office", true, 120)), lanIngressTables(bundle("office", true, 240))
	kernel := &kernelFixture{objects: map[Table][]map[string]any{}}
	engine := &Engine{kernel: kernel, prepared: PreparationV1{Dependencies: deps}}
	batch, err := engine.compileChange(before, after, deps)
	if err != nil || bytes.Contains(batch, []byte(`"andeiva_local"`)) || before[RoutedTable].Revision.Hash == after[RoutedTable].Revision.Hash {
		t.Fatal("lease timing unnecessarily replaced identical Local-In rules", err)
	}
}

func TestDHCPServerStoppedPolicyKeepsStaticManagementIngress(t *testing.T) {
	deps, bundle := lanIngressFixture(t)
	before := bundle("office", true, 120)
	conf := before.Firewall.Config
	projected := lanServerStoppedPolicy(*conf.Routed)
	conf.Routed = &projected
	effective, err := configpoc.CanonicalRouted(conf)
	if err != nil {
		t.Fatal(err)
	}
	want := bundle("office", false, 120).Firewall
	if effective.Hash != want.Hash || !before.Firewall.Config.Routed.DHCPServer.Enabled {
		t.Fatal("effective policy changed more than the LAN DHCP state or mutated the selected revision")
	}
	ingress, err := routedLocalIngress(TableStateV1{Presence: Present, Revision: &effective}, deps)
	if err != nil {
		t.Fatal(err)
	}
	local, err := ingress.compile(&before.LocalServices, deps.Neighbors)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"198.18.0.1", "18443", "andeiva-dhcp-acquisition:v1"} {
		if !bytes.Contains(local.Create, []byte(value)) {
			t.Fatalf("stopped service projection dropped %s", value)
		}
	}
	if bytes.Contains(local.Create, []byte("andeiva-dhcp-server:v1:")) {
		t.Fatal("stopped service projection retained a LAN DHCP rule")
	}
}

func TestDHCPServerIngressRequiresLocalTable(t *testing.T) {
	deps, bundle := lanIngressFixture(t)
	target := lanIngressTables(bundle("office", true, 120))
	absent := [3]TableStateV1{{Presence: Absent}, {Presence: Absent}, {Presence: Absent}}
	target[LocalTable] = absent[LocalTable]
	engine := &Engine{kernel: &kernelFixture{}, prepared: PreparationV1{Dependencies: deps}}
	if _, err := engine.compileChange(absent, target, deps); err != ErrState {
		t.Fatal("enabled DHCP server accepted without a LocalTable on compile", err)
	}
	ingress, err := routedLocalIngress(target[RoutedTable], deps)
	if err != nil || engine.tableMatches(context.Background(), LocalTable, target[LocalTable], deps, ingress) {
		t.Fatal("enabled DHCP server accepted without a LocalTable on readback", err)
	}
}
