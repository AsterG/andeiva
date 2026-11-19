package previewruntime

import (
	"errors"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"github.com/AsterG/andeiva/internal/routednft"
)

func selectedDHCPServerBindingFixtureV1(t *testing.T) RoutedSelectedPreflightResultV4 {
	t.Helper()
	policy := routednft.LabPolicy()
	policy.SchemaVersion = 2
	var err error
	network := policy.Network.Config
	network.Interfaces = append(network.Interfaces, networkplan.Interface{
		ID: "lan2", Role: networkplan.LAN, Zone: "inside",
		Binding: networkplan.Binding{Name: "lan2", HardwareAddress: "02:00:00:00:01:02"},
		IPv4:    networkplan.IPv4{Mode: "static", Address: "198.18.1.1/24"},
	})
	policy.Network, err = networkplan.Canonical(network)
	if err != nil {
		t.Fatal(err)
	}
	policy.DHCPServer = &dhcpserver.Config{SchemaVersion: 1, Enabled: true, Scopes: []dhcpserver.Scope{
		{ID: "office", InterfaceID: "lan", Subnet: "198.18.0.0/24", Router: "198.18.0.1",
			Pools:        []dhcpserver.Pool{{First: "198.18.0.10", Last: "198.18.0.20"}},
			LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000},
		{ID: "branch", InterfaceID: "lan2", Subnet: "198.18.1.0/24", Router: "198.18.1.1",
			Pools:        []dhcpserver.Pool{{First: "198.18.1.10", Last: "198.18.1.20"}},
			LeaseSeconds: 3600, RenewSeconds: 1800, RebindSeconds: 3000},
	}}
	local := localpolicy.Config{SchemaVersion: 1, Interfaces: []localpolicy.Interface{
		{Name: "lan0", Zone: localpolicy.LAN, Addresses: []string{"198.18.0.1"}},
		{Name: "lan2", Zone: localpolicy.LAN, Addresses: []string{"198.18.1.1"}},
		{Name: "wan0", Zone: localpolicy.WAN, Addresses: []string{"198.19.0.1"}},
	}, Services: []localpolicy.Service{}}
	localRevision, err := configpoc.Canonical(configpoc.Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &local})
	if err != nil {
		t.Fatal(err)
	}
	firewall, err := configpoc.CanonicalRouted(configpoc.Config{SchemaVersion: 6, DefaultAction: "deny", Routed: &policy})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := configpoc.NewRoutedActivationBundleV1(firewall, localRevision)
	if err != nil {
		t.Fatal(err)
	}
	work := configpoc.RoutedWorkReferenceV1{Work: strings.Repeat("c", 64), Lineage: "lineage", Generation: 1}
	return RoutedSelectedPreflightResultV4{
		Identity: networkexecutor.OwnedNamespaceIdentity{
			UID: 1003, GID: 1004, Namespace: 22, Host: 11,
			BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32),
		},
		Reference: configpoc.SelectionReferenceV2{
			Selection: strings.Repeat("d", 64), State: strings.Repeat("e", 64), WorkHash: work.Work, Lineage: work.Lineage, Mode: "active",
		},
		Work: work, Bundle: bundle, Resolution: "target",
	}
}

func TestRoutedDHCPServerBindingPlanV1UsesStableRegistryAssignments(t *testing.T) {
	selected := selectedDHCPServerBindingFixtureV1(t)
	plan, err := routedDHCPServerBindingPlanFromSelectedV1(selected, selected.Identity, selected.Work)
	if err != nil {
		t.Fatal(err)
	}
	keys := plan.subnetBindings()
	want := []RoutedDHCPSubnetBindingV1{
		{ScopeID: "branch", InterfaceID: "lan2", HardwareMAC: "02:00:00:00:01:02", Subnet: "198.18.1.0/24"},
		{ScopeID: "office", InterfaceID: "lan", HardwareMAC: "02:00:00:00:01:01", Subnet: "198.18.0.0/24"},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("unexpected selected identities: %+v", keys)
	}
	keys[0].HardwareMAC = "00:00:00:00:00:00"
	if !reflect.DeepEqual(plan.subnetBindings(), want) {
		t.Fatal("caller mutated plan through returned keys")
	}

	empty := routedDHCPSubnetRegistryV1{Version: 1, Entries: []routedDHCPSubnetEntryV1{}}
	first, _, _, err := allocateDHCPSubnetRegistryV1(empty, want[1:])
	if err != nil {
		t.Fatal(err)
	}
	registry, ids, changed, err := allocateDHCPSubnetRegistryV1(first, plan.subnetBindings())
	if err != nil || !changed || !reflect.DeepEqual(ids, []uint32{2, 1}) {
		t.Fatalf("historical office ID changed: IDs=%v, error=%v", ids, err)
	}
	_, repeat, changed, err := allocateDHCPSubnetRegistryV1(registry, plan.subnetBindings())
	if err != nil || changed || !reflect.DeepEqual(ids, repeat) {
		t.Fatalf("existing IDs changed: IDs=%v, error=%v", repeat, err)
	}
	bindings, err := plan.keaBindings(repeat)
	if err != nil {
		t.Fatal(err)
	}
	wantKea := []dhcpkea.Binding{
		{Interface: dhcpserver.Binding{InterfaceID: "lan2", Role: "lan", Address: netip.MustParsePrefix("198.18.1.1/24")}, Name: "lan2", SubnetID: 2},
		{Interface: dhcpserver.Binding{InterfaceID: "lan", Role: "lan", Address: netip.MustParsePrefix("198.18.0.1/24")}, Name: "lan0", SubnetID: 1},
	}
	if !reflect.DeepEqual(bindings, wantKea) {
		t.Fatalf("Kea bindings: %+v", bindings)
	}
	artifact, err := dhcpkea.Compile(*selected.Bundle.Firewall.Config.Routed.DHCPServer, bindings)
	if err != nil || !artifact.Enabled {
		t.Fatalf("Kea rejected selected bindings: %v", err)
	}
	for _, bad := range [][]uint32{nil, {2}, {2, 1, 3}, {0, 1}, {math.MaxUint32, 1}, {1, 1}} {
		if bindings, err := plan.keaBindings(bad); !errors.Is(err, ErrIdentity) || bindings != nil {
			t.Fatalf("invalid assignments accepted: IDs=%v, error=%v", bad, err)
		}
	}
}

func TestRoutedDHCPServerBindingPlanV1RejectsUnselectedInputs(t *testing.T) {
	for name, mutate := range map[string]func(*RoutedSelectedPreflightResultV4){
		"foreign namespace": func(r *RoutedSelectedPreflightResultV4) { r.Identity.Namespace++ },
		"stale work":        func(r *RoutedSelectedPreflightResultV4) { r.Work.Generation++ },
		"pending":           func(r *RoutedSelectedPreflightResultV4) { r.Reference.Mode = "pending" },
		"before resolution": func(r *RoutedSelectedPreflightResultV4) { r.Resolution = "before" },
		"disabled":          func(r *RoutedSelectedPreflightResultV4) { r.Bundle.Firewall.Config.Routed.DHCPServer.Enabled = false },
		"scope ID": func(r *RoutedSelectedPreflightResultV4) {
			r.Bundle.Firewall.Config.Routed.DHCPServer.Scopes[0].ID = "other"
		},
		"scope subnet": func(r *RoutedSelectedPreflightResultV4) {
			r.Bundle.Firewall.Config.Routed.DHCPServer.Scopes[0].Subnet = "198.18.1.1/24"
		},
		"scope on WAN": func(r *RoutedSelectedPreflightResultV4) {
			r.Bundle.Firewall.Config.Routed.DHCPServer.Scopes[0].InterfaceID = "wan"
		},
		"LAN role": func(r *RoutedSelectedPreflightResultV4) {
			r.Bundle.Firewall.Config.Routed.Network.Config.Interfaces[0].Role = networkplan.Management
		},
		"LAN MAC": func(r *RoutedSelectedPreflightResultV4) {
			r.Bundle.Firewall.Config.Routed.Network.Config.Interfaces[0].Binding.HardwareAddress = "02:00:00:00:01:09"
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := selectedDHCPServerBindingFixtureV1(t)
			identity, work := result.Identity, result.Work
			mutate(&result)
			if plan, err := routedDHCPServerBindingPlanFromSelectedV1(result, identity, work); !errors.Is(err, ErrIdentity) || plan != nil {
				t.Fatalf("modified selection accepted, error=%v", err)
			}
		})
	}
}
