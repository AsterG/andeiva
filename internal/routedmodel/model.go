// Package routedmodel defines canonical routed IPv4 configuration contracts.
// It performs no I/O, policy application or runtime activation.
package routedmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"

	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/networkplan"
)

const MaxRules = 128

var ErrPolicy = errors.New("ANDEIVA_ROUTED_INVALID_POLICY")

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

type Ports struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}
type Path struct {
	FromZone      string `json:"from_zone"`
	ToZone        string `json:"to_zone"`
	FromInterface string `json:"from_interface"`
	ToInterface   string `json:"to_interface"`
}
type Rule struct {
	ID               string `json:"id"`
	Enabled          *bool  `json:"enabled"`
	Path             Path   `json:"path"`
	Action           string `json:"action"`
	Source           string `json:"source"`
	Destination      string `json:"destination"`
	Protocol         string `json:"protocol"`
	SourcePorts      Ports  `json:"source_ports"`
	DestinationPorts Ports  `json:"destination_ports"`
}
type Masquerade struct {
	ID     string `json:"id"`
	Path   Path   `json:"path"`
	Source string `json:"source"`
}

// IsEnabled is fail-closed for incomplete internal policies. Canonical requires
// an explicit state even for disabled rules, whose complete config is retained.
func (r Rule) IsEnabled() bool { return r.Enabled != nil && *r.Enabled }

type Policy struct {
	SchemaVersion int `json:"schema_version"`
	// LabOnly must be explicitly true; no production claim or implicit exception.
	LabOnly               bool                 `json:"lab_only"`
	RequireIdentification bool                 `json:"require_identification"`
	RequireInspection     bool                 `json:"require_inspection"`
	Network               networkplan.Revision `json:"network"`
	Rules                 []Rule               `json:"rules"`
	NAT                   []Masquerade         `json:"nat"`
	DHCPServer            *dhcpserver.Config   `json:"dhcp_server,omitempty"`
}
type Revision struct {
	Hash   string `json:"hash"`
	Policy Policy `json:"policy"`
}

func canonicalCIDR(value string) (string, bool) {
	if len(value) > 18 {
		return "", false
	}
	p, e := netip.ParsePrefix(value)
	if e != nil || !p.Addr().Is4() {
		return "", false
	}
	return p.Masked().String(), true
}

func Canonical(input Policy) (Revision, error) {
	if (input.SchemaVersion != 1 && input.SchemaVersion != 2) || (input.SchemaVersion == 1 && input.DHCPServer != nil) || (input.SchemaVersion == 2 && input.DHCPServer == nil) || !input.LabOnly || input.RequireIdentification || input.RequireInspection || len(input.Rules) > MaxRules || len(input.NAT) > 32 {
		return Revision{}, ErrPolicy
	}
	network, e := networkplan.Canonical(input.Network.Config)
	if e != nil || input.Network.Hash != network.Hash {
		return Revision{}, ErrPolicy
	}
	p := input
	p.Network = network
	if input.DHCPServer != nil {
		var bindings []dhcpserver.Binding
		for _, iface := range network.Config.Interfaces {
			if iface.Role != networkplan.LAN || iface.IPv4.Mode != "static" {
				continue
			}
			address, err := netip.ParsePrefix(iface.IPv4.Address)
			if err != nil {
				return Revision{}, ErrPolicy
			}
			bindings = append(bindings, dhcpserver.Binding{InterfaceID: iface.ID, Role: string(iface.Role), Address: address})
		}
		canonical, err := dhcpserver.Canonical(*input.DHCPServer, bindings)
		if err != nil {
			return Revision{}, ErrPolicy
		}
		p.DHCPServer = &canonical
	}
	p.Rules = slices.Clone(input.Rules)
	p.NAT = slices.Clone(input.NAT)
	interfaces := map[string]networkplan.Interface{}
	for _, i := range network.Config.Interfaces {
		interfaces[i.ID] = i
	}
	validPath := func(path Path) bool {
		a, aok := interfaces[path.FromInterface]
		b, bok := interfaces[path.ToInterface]
		return aok && bok && a.ID != b.ID && a.Zone == path.FromZone && b.Zone == path.ToZone && a.Role != networkplan.Management && b.Role != networkplan.Management
	}
	seen := map[string]bool{}
	marks := map[uint32]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if !idPattern.MatchString(r.ID) || seen[r.ID] || r.Enabled == nil || !validPath(r.Path) || (r.Action != "allow" && r.Action != "deny") || (r.Protocol != "tcp" && r.Protocol != "udp") || r.SourcePorts.From == 0 || r.SourcePorts.From > r.SourcePorts.To || r.DestinationPorts.From == 0 || r.DestinationPorts.From > r.DestinationPorts.To {
			return Revision{}, ErrPolicy
		}
		enabled := *r.Enabled
		r.Enabled = &enabled
		var ok bool
		if r.Source, ok = canonicalCIDR(r.Source); !ok {
			return Revision{}, ErrPolicy
		}
		if r.Destination, ok = canonicalCIDR(r.Destination); !ok {
			return Revision{}, ErrPolicy
		}
		seen[r.ID] = true
		mark := RuleMark(*r)
		if marks[mark] {
			return Revision{}, ErrPolicy
		}
		marks[mark] = true
	}
	seen = map[string]bool{}
	for i := range p.NAT {
		n := &p.NAT[i]
		a := interfaces[n.Path.FromInterface]
		b := interfaces[n.Path.ToInterface]
		if !idPattern.MatchString(n.ID) || seen[n.ID] || !validPath(n.Path) || a.Role != networkplan.LAN || b.Role != networkplan.WAN {
			return Revision{}, ErrPolicy
		}
		var ok bool
		if n.Source, ok = canonicalCIDR(n.Source); !ok {
			return Revision{}, ErrPolicy
		}
		subnet, _ := netip.ParsePrefix(a.IPv4.Address)
		source := netip.MustParsePrefix(n.Source)
		if a.IPv4.Mode != "static" || source.Bits() < subnet.Bits() || !subnet.Contains(source.Addr()) {
			return Revision{}, ErrPolicy
		}
		seen[n.ID] = true
	}
	encoded, _ := json.Marshal(p)
	hash := sha256.Sum256(encoded)
	return Revision{Hash: hex.EncodeToString(hash[:]), Policy: p}, nil
}

func RuleMark(r Rule) uint32 {
	data, _ := json.Marshal(r)
	sum := sha256.Sum256(data)
	// A mark is evidence of prior admission only. The entire current ordered
	// policy and original tuple are reevaluated before every reply admission.
	return 0xad000000 | uint32(sum[0])<<16 | uint32(sum[1])<<8 | uint32(sum[2])
}
