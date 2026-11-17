package configpoc

import "github.com/AsterG/andeiva/internal/networkexecutor"

// The complete canonical network revision is the approved Alpha boundary.
// An unchanged WAN link alone cannot preserve a snapshot containing the LAN.
// This classification authorizes neither an effect nor a replacement grant.
func routedDHCPConfigurationImpactV4(source v3RoutedDHCPWork, before, target v2Configuration) (string, error) {
	if !validV2Configuration(&before) || !validV2Configuration(&target) || before.Firewall.Running.Config.Routed == nil || before.Running.Config.Domains.Network == nil {
		return "", ErrRecovery
	}
	s, err := networkexecutor.CanonicalLeaseSelectedSnapshotV3(source.Snapshot)
	if err != nil || s.Desired.Hash != before.Firewall.Running.Config.Routed.Network.Hash || s.Desired.Hash != before.Running.Config.Domains.Network.Revision {
		return "", ErrRecovery
	}
	if target.Firewall.Running.Config.Routed == nil {
		return "replace", nil
	}
	n := target.Firewall.Running.Config.Routed.Network
	if target.Running.Config.Domains.Network == nil || target.Running.Config.Domains.Network.Revision != n.Hash {
		return "", ErrRecovery
	}
	if n.Hash == s.Desired.Hash {
		return "preserve", nil
	}
	return "replace", nil
}
