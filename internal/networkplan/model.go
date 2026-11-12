// Package networkplan validates routed IPv4 configuration without changing links.
package networkplan

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
)

const SchemaVersion = 1
const MaxInterfaces = 32
const MaxZones = 32

var ErrInvalid = errors.New("ANDEIVA_NETWORK_INVALID")
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

type Role string

const (
	WAN        Role = "wan"
	LAN        Role = "lan"
	Management Role = "management"
)

// Binding identifies an observed link, not an authentication identity. Its
// name/MAC must be rechecked against trusted inventory before effects. Kernel
// indexes are deliberately resolved at execution, since they may change on boot.
type Binding struct {
	Name            string `json:"name"`
	HardwareAddress string `json:"hardware_address"`
}

type IPv4 struct {
	Mode    string `json:"mode"`
	Address string `json:"address,omitempty"`
	Gateway string `json:"gateway,omitempty"`
}

type Interface struct {
	ID      string  `json:"id"`
	Binding Binding `json:"binding"`
	Role    Role    `json:"role"`
	Zone    string  `json:"zone"`
	IPv4    IPv4    `json:"ipv4"`
}

type Zone struct {
	ID   string `json:"id"`
	Kind Role   `json:"kind"`
}

type DefaultRoute struct {
	InterfaceID string `json:"interface_id"`
	Metric      uint32 `json:"metric"`
}

type DNS struct {
	Mode        string   `json:"mode"`
	InterfaceID string   `json:"interface_id,omitempty"`
	Servers     []string `json:"servers"`
}

type Config struct {
	SchemaVersion  int          `json:"schema_version"`
	Interfaces     []Interface  `json:"interfaces"`
	Zones          []Zone       `json:"zones"`
	DefaultRoute   DefaultRoute `json:"default_route"`
	DNS            DNS          `json:"dns"`
	IPv6Forwarding string       `json:"ipv6_forwarding"`
}

type Revision struct {
	Hash   string `json:"hash"`
	Config Config `json:"config"`
}

// Invalid reports a stable code and a bounded field path, without raw OS errors.
type Invalid struct {
	Code  string
	Field string
}

func (e *Invalid) Error() string { return e.Code }
func (e *Invalid) Unwrap() error { return ErrInvalid }

func invalid(code, field string) error {
	return &Invalid{Code: "ANDEIVA_NETWORK_" + code, Field: field}
}

func validRole(role Role) bool { return role == WAN || role == LAN || role == Management }

// Canonical preserves interface host bits, orders identity-keyed collections and
// validates only static facts. It does not establish DHCP, free addresses,
// listeners, reachability or permission to change a live management interface.
func Canonical(input Config) (Revision, error) {
	if input.SchemaVersion != SchemaVersion || input.IPv6Forwarding != "deny" {
		return Revision{}, invalid("SCHEMA", "schema_version/ipv6_forwarding")
	}
	if len(input.Interfaces) < 2 || len(input.Interfaces) > MaxInterfaces || len(input.Zones) < 2 || len(input.Zones) > MaxZones || len(input.DNS.Servers) > 4 {
		return Revision{}, invalid("LIMIT", "interfaces/zones")
	}
	config := input
	config.Interfaces = slices.Clone(input.Interfaces)
	config.Zones = slices.Clone(input.Zones)
	config.DNS.Servers = append([]string{}, input.DNS.Servers...)
	zones := make(map[string]Role, len(config.Zones))
	for _, zone := range config.Zones {
		if !identifier.MatchString(zone.ID) || !validRole(zone.Kind) {
			return Revision{}, invalid("ZONE", "zones")
		}
		if _, duplicate := zones[zone.ID]; duplicate {
			return Revision{}, invalid("DUPLICATE", "zones")
		}
		zones[zone.ID] = zone.Kind
	}
	ids := make(map[string]Interface, len(config.Interfaces))
	names, macs := map[string]bool{}, map[string]bool{}
	networks := make([]netip.Prefix, 0, len(config.Interfaces))
	wan, lan := false, false
	for i := range config.Interfaces {
		iface := &config.Interfaces[i]
		field := "interfaces[" + strconv.Itoa(i) + "]"
		if !identifier.MatchString(iface.ID) || !validRole(iface.Role) || zones[iface.Zone] != iface.Role {
			return Revision{}, invalid("INTERFACE", field)
		}
		if len(iface.Binding.HardwareAddress) > 64 || len(iface.IPv4.Address) > 18 || len(iface.IPv4.Gateway) > 15 {
			return Revision{}, invalid("LIMIT", field)
		}
		if !interfaceName.MatchString(iface.Binding.Name) || iface.Binding.Name == "lo" {
			return Revision{}, invalid("BINDING", field+".binding")
		}
		mac, err := net.ParseMAC(iface.Binding.HardwareAddress)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || slices.Equal(mac, make([]byte, 6)) {
			return Revision{}, invalid("BINDING", field+".binding.hardware_address")
		}
		iface.Binding.HardwareAddress = mac.String()
		if _, duplicate := ids[iface.ID]; duplicate || names[iface.Binding.Name] || macs[mac.String()] {
			return Revision{}, invalid("DUPLICATE", field+".binding")
		}
		switch iface.IPv4.Mode {
		case "dhcp":
			if iface.Role != WAN || iface.IPv4.Address != "" || iface.IPv4.Gateway != "" {
				return Revision{}, invalid("DHCP", field+".ipv4")
			}
		case "static":
			prefix, err := netip.ParsePrefix(iface.IPv4.Address)
			if err != nil || !usableIPv4(prefix.Addr()) || prefix.Bits() == 0 || !usableHost(prefix) {
				return Revision{}, invalid("ADDRESS", field+".ipv4.address")
			}
			iface.IPv4.Address = prefix.Addr().String() + "/" + strconv.Itoa(prefix.Bits())
			if iface.IPv4.Gateway != "" {
				gateway, err := netip.ParseAddr(iface.IPv4.Gateway)
				if iface.Role != WAN || err != nil || !usableIPv4(gateway) || !prefix.Contains(gateway) || gateway == prefix.Addr() || !usableHost(netip.PrefixFrom(gateway, prefix.Bits())) {
					return Revision{}, invalid("GATEWAY", field+".ipv4.gateway")
				}
				iface.IPv4.Gateway = gateway.String()
			}
			for _, existing := range networks {
				if existing.Overlaps(prefix) {
					return Revision{}, invalid("OVERLAP", field+".ipv4.address")
				}
			}
			networks = append(networks, prefix)
		default:
			return Revision{}, invalid("ADDRESS_MODE", field+".ipv4.mode")
		}
		wan = wan || iface.Role == WAN
		lan = lan || iface.Role == LAN
		ids[iface.ID] = *iface
		names[iface.Binding.Name], macs[mac.String()] = true, true
	}
	if !wan || !lan {
		return Revision{}, invalid("ROLES", "interfaces")
	}
	defaultInterface, found := ids[config.DefaultRoute.InterfaceID]
	if !found || defaultInterface.Role != WAN || config.DefaultRoute.Metric < 1 || config.DefaultRoute.Metric > 65535 || (defaultInterface.IPv4.Mode == "static" && defaultInterface.IPv4.Gateway == "") {
		return Revision{}, invalid("DEFAULT_ROUTE", "default_route")
	}
	switch config.DNS.Mode {
	case "dhcp":
		iface, found := ids[config.DNS.InterfaceID]
		if !found || iface.Role != WAN || iface.IPv4.Mode != "dhcp" || len(config.DNS.Servers) != 0 {
			return Revision{}, invalid("DNS", "dns")
		}
	case "static":
		if config.DNS.InterfaceID != "" || len(config.DNS.Servers) < 1 || len(config.DNS.Servers) > 4 {
			return Revision{}, invalid("DNS", "dns")
		}
		seen := map[netip.Addr]bool{}
		for i, value := range config.DNS.Servers {
			if len(value) > 15 {
				return Revision{}, invalid("DNS", "dns.servers")
			}
			address, err := netip.ParseAddr(value)
			if err != nil || !usableIPv4(address) || seen[address] {
				return Revision{}, invalid("DNS", "dns.servers")
			}
			seen[address] = true
			config.DNS.Servers[i] = address.String()
		}
	case "none":
		if len(config.DNS.Servers) != 0 || config.DNS.InterfaceID != "" {
			return Revision{}, invalid("DNS", "dns")
		}
	default:
		return Revision{}, invalid("DNS", "dns.mode")
	}
	slices.SortFunc(config.Interfaces, func(a, b Interface) int { return cmp.Compare(a.ID, b.ID) })
	slices.SortFunc(config.Zones, func(a, b Zone) int { return cmp.Compare(a.ID, b.ID) })
	encoded, err := json.Marshal(config)
	if err != nil {
		return Revision{}, ErrInvalid
	}
	hash := sha256.Sum256(encoded)
	return Revision{Hash: hex.EncodeToString(hash[:]), Config: config}, nil
}

func usableIPv4(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() && address != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func usableHost(prefix netip.Prefix) bool {
	if prefix.Bits() >= 31 {
		return true
	}
	address, first := prefix.Addr().As4(), prefix.Masked().Addr().As4()
	last := first
	for bit := prefix.Bits(); bit < 32; bit++ {
		last[bit/8] |= byte(1 << (7 - bit%8))
	}
	return address != first && address != last
}
