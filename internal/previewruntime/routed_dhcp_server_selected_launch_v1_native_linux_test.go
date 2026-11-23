//go:build linux

package previewruntime

import (
	"context"
	"os"
	"testing"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

func nativeKeaSelectedFixtureV1(t *testing.T, root *os.Root, resources RoutedDHCPServerResourcesV1, services *RoutedDHCPServerServiceSetV1) (routedDHCPServerSelectedOptionsV1, configpoc.RoutedWorkReferenceV1) {
	t.Helper()
	selected := selectedDHCPServerBindingFixtureV1(t)
	selected.Identity.Namespace, selected.Identity.Host = resources.Metadata.GatewayNamespace, resources.Metadata.HostNamespace
	selected.Identity.RunID, selected.Identity.BootID = resources.Metadata.RunID, resources.Metadata.BootID
	firewall := selected.Bundle.Firewall.Config
	policy := *firewall.Routed
	net := policy.Network.Config
	net.Interfaces = nil
	for _, link := range policy.Network.Config.Interfaces {
		switch link.ID {
		case "lan":
			link.IPv4.Address = resources.Bindings[0].Interface.Address.String()
			net.Interfaces = append(net.Interfaces, link)
		case "wan":
			net.Interfaces = append(net.Interfaces, link)
		}
	}
	var err error
	policy.Network, err = networkplan.Canonical(net)
	if err != nil {
		t.Fatal("selected fixture network", err)
	}
	// This fixture starts a LAN daemon with forwarding closed. The lab TCP and
	// NAT rules use the original LAN prefix and belong to another fixture.
	policy.Rules, policy.NAT = nil, nil
	policy.DHCPServer = &resources.Config
	firewall.Routed = &policy
	revision, err := configpoc.CanonicalRouted(firewall)
	if err != nil {
		t.Fatal("selected fixture routed policy", err)
	}
	locals := selected.Bundle.LocalServices.Config
	local := *locals.LocalServices
	local.Interfaces = nil
	for _, iface := range locals.LocalServices.Interfaces {
		switch iface.Name {
		case "lan0":
			iface.Addresses = []string{resources.Bindings[0].Interface.Address.Addr().String()}
			local.Interfaces = append(local.Interfaces, iface)
		case "wan0":
			local.Interfaces = append(local.Interfaces, iface)
		}
	}
	locals.LocalServices = &local
	localRevision, err := configpoc.Canonical(locals)
	if err != nil {
		t.Fatal("selected fixture Local-In policy", err)
	}
	selected.Bundle, err = configpoc.NewRoutedActivationBundleV1(revision, localRevision)
	if err != nil {
		t.Fatal("selected fixture composite", err)
	}
	if err := root.Mkdir("work-runtime", 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := root.OpenRoot("work-runtime")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	registry, err := root.OpenFile(".", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return routedDHCPServerSelectedOptionsV1{
		metadata: resources.Metadata, identity: selected.Identity,
		gateway: resources.Gateway, host: resources.Host, hostMount: resources.HostMount,
		runtime: directory, registry: registry, leases: resources.Leases, services: services, leaseBudget: resources.LeaseBudgetBytes,
		readSelected: func(ctx context.Context, work configpoc.RoutedWorkReferenceV1) (RoutedSelectedPreflightResultV4, error) {
			if ctx.Err() != nil || work != selected.Work {
				return RoutedSelectedPreflightResultV4{}, ErrIdentity
			}
			return selected, nil
		},
	}, selected.Work
}
