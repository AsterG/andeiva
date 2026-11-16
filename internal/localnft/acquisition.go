package localnft

import "github.com/AsterG/andeiva/internal/networkplan"

func acquisitionRule(selected *networkplan.Revision) (*networkplan.Revision, object, error) {
	if selected == nil {
		return nil, nil, nil
	}
	n, err := networkplan.Canonical(selected.Config)
	if err != nil || n.Hash != selected.Hash {
		return nil, nil, ErrPolicy
	}
	var admission object
	for _, link := range n.Config.Interfaces {
		if link.Role != networkplan.WAN || link.IPv4.Mode != "dhcp" {
			continue
		}
		if admission != nil {
			return nil, nil, ErrPolicy
		}
		// Acquisition remains enabled without a lease, including broadcast and
		// untracked replies. Lease/R2 controls forwarding independently.
		admission = rule("andeiva-dhcp-acquisition:v1", []object{
			match(meta("nfproto"), "ipv4"), match(meta("iifname"), link.Binding.Name),
			match(meta("l4proto"), "udp"), match(payload("udp", "sport"), uint16(67)),
			match(payload("udp", "dport"), uint16(68)), {"counter": nil}, {"accept": nil},
		})
	}
	return &n, admission, nil
}
