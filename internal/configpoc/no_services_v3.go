package configpoc

import (
	"net/netip"

	"github.com/AsterG/andeiva/internal/localpolicy"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

// noServicesInventoryV3 derives only the inventory supported by the existing
// routed dependency profiles. It creates no service, listener or allow rule.
func noServicesInventoryV3(firewall Revision) (Revision, error) {
	fw, err := canonicalDomainRevisionV2(firewall.Config, true)
	if err != nil || fw.Hash != firewall.Hash {
		return Revision{}, ErrDenied
	}
	local := Config{SchemaVersion: 3, DefaultAction: "deny", LocalServices: &localpolicy.Config{SchemaVersion: 1}}
	if fw.Config.SchemaVersion == 4 {
		return Canonical(local)
	}
	if fw.Config.SchemaVersion != 6 || fw.Config.Routed == nil {
		return Revision{}, ErrDenied
	}
	n := fw.Config.Routed.Network
	if len(n.Config.Interfaces) != 2 {
		return Revision{}, ErrDenied
	}
	_, dhcpErr := networkexecutor.CanonicalLANBootstrapPlanV3(n)
	lan, wan := 0, 0
	for _, iface := range n.Config.Interfaces {
		zone := localpolicy.LAN
		switch iface.Role {
		case networkplan.LAN:
			lan++
		case networkplan.WAN:
			wan++
			zone = localpolicy.WAN
			if dhcpErr == nil {
				continue // No fabricated DHCP address or listener binding.
			}
		default:
			return Revision{}, ErrDenied
		}
		prefix, err := netip.ParsePrefix(iface.IPv4.Address)
		if err != nil || iface.IPv4.Mode != "static" {
			return Revision{}, ErrDenied
		}
		local.LocalServices.Interfaces = append(local.LocalServices.Interfaces, localpolicy.Interface{Name: iface.Binding.Name, Zone: zone, Addresses: []string{prefix.Addr().String()}})
	}
	if lan != 1 || wan != 1 {
		return Revision{}, ErrDenied
	}
	return Canonical(local)
}

func noServicesSourceV3(firewall, local Revision) bool {
	canonical, err := Canonical(local.Config)
	if err != nil || canonical.Hash != local.Hash || canonical.Config.SchemaVersion != 3 || canonical.Config.LocalServices == nil || len(canonical.Config.LocalServices.Services) != 0 {
		return false
	}
	expected, err := noServicesInventoryV3(firewall)
	return err == nil && (len(canonical.Config.LocalServices.Interfaces) == 0 || canonical.Hash == expected.Hash)
}

// RoutedNoServicesTransitionV3 checks a narrow metadata transition between
// authenticated bundles. Callers must still authenticate history, ownership,
// selected work and independent physical readback before any effect. Neither
// this predicate nor a matching hash is an access-recovery proof.
func RoutedNoServicesTransitionV3(previousFirewall, previousLocal, targetFirewall, targetLocal Revision) bool {
	if !noServicesSourceV3(previousFirewall, previousLocal) {
		return false
	}
	expected, err := noServicesInventoryV3(targetFirewall)
	actual, localErr := Canonical(targetLocal.Config)
	return err == nil && localErr == nil && actual.Hash == targetLocal.Hash && actual.Hash == expected.Hash
}

func noServicesCandidateV3(previousFirewall, previousLocal, targetFirewall Revision) (Revision, error) {
	// Existing service configurations keep their exact local revision. They
	// never receive this exception, including when every service is disabled.
	if previousLocal.Config.LocalServices == nil || len(previousLocal.Config.LocalServices.Services) != 0 || targetFirewall.Config.SchemaVersion != 6 {
		return clone(previousLocal), nil
	}
	derived, err := noServicesInventoryV3(targetFirewall)
	if err != nil {
		return Revision{}, err
	}
	if derived.Hash != previousLocal.Hash && !RoutedNoServicesTransitionV3(previousFirewall, previousLocal, targetFirewall, derived) {
		return Revision{}, ErrDenied
	}
	return derived, nil
}
