// Package dhcpserver defines bounded DHCPv4 service configuration. Validation
// does not start a listener, assign leases or authorize forwarding.
package dhcpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const MaxConfigBytes = 65536

var ErrInvalid = errors.New("ANDEIVA_DHCP_SERVER_INVALID")

type Config struct {
	SchemaVersion int     `json:"schema_version"`
	Enabled       bool    `json:"enabled"`
	Scopes        []Scope `json:"scopes"`
}

type Scope struct {
	ID            string        `json:"id"`
	InterfaceID   string        `json:"interface_id"`
	Subnet        string        `json:"subnet"`
	Router        string        `json:"router"`
	Pools         []Pool        `json:"pools"`
	Excluded      []string      `json:"excluded"`
	Reservations  []Reservation `json:"reservations"`
	DNS           []string      `json:"dns"`
	NTP           []string      `json:"ntp"`
	Domain        string        `json:"domain"`
	LeaseSeconds  uint32        `json:"lease_seconds"`
	RenewSeconds  uint32        `json:"renew_seconds"`
	RebindSeconds uint32        `json:"rebind_seconds"`
}

type Pool struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

type Reservation struct {
	MAC     string `json:"mac"`
	Address string `json:"address"`
}

// Binding is supplied by the trusted interface inventory and selected network
// configuration, never decoded from an administrative service request.
type Binding struct {
	InterfaceID string
	Role        string
	Address     netip.Prefix
}

func Decode(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 || len(raw) > MaxConfigBytes || !jsoncheck.UniqueControlFields(raw) {
		return c, ErrInvalid
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return c, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return Config{}, ErrInvalid
	}
	return c, nil
}

func (c Config) Validate(bindings []Binding) error {
	if c.SchemaVersion != 1 || len(c.Scopes) > 32 || len(bindings) > 64 || c.Enabled && len(c.Scopes) == 0 {
		return ErrInvalid
	}
	ids, interfaces := map[string]bool{}, map[string]bool{}
	var subnets []netip.Prefix
	var addresses uint64
	for _, s := range c.Scopes {
		if !identifier(s.ID) || ids[s.ID] || !identifier(s.InterfaceID) || interfaces[s.InterfaceID] {
			return ErrInvalid
		}
		ids[s.ID], interfaces[s.InterfaceID] = true, true
		if len(s.Subnet) > 18 {
			return ErrInvalid
		}
		p, err := netip.ParsePrefix(s.Subnet)
		if err != nil || !p.Addr().Is4() || p.Bits() < 1 || p.Bits() > 30 || p != p.Masked() || p.String() != s.Subnet {
			return ErrInvalid
		}
		for _, old := range subnets {
			if old.Overlaps(p) {
				return ErrInvalid
			}
		}
		subnets = append(subnets, p)
		router, ok := host(s.Router, p)
		if !ok {
			return ErrInvalid
		}
		matched := 0
		for _, b := range bindings {
			if b.InterfaceID == s.InterfaceID {
				if b.Role != "lan" || b.Address.Addr() != router || b.Address.Masked() != p {
					return ErrInvalid
				}
				matched++
			}
		}
		if matched != 1 || len(s.Pools) == 0 || len(s.Pools) > 32 || len(s.Excluded) > 256 || len(s.Reservations) > 256 || s.LeaseSeconds < 60 || s.LeaseSeconds > 604800 || s.RenewSeconds == 0 || s.RenewSeconds >= s.RebindSeconds || s.RebindSeconds >= s.LeaseSeconds || !domain(s.Domain) {
			return ErrInvalid
		}
		var ranges [][2]netip.Addr
		for _, pool := range s.Pools {
			first, a := host(pool.First, p)
			last, b := host(pool.Last, p)
			if !a || !b || first.Compare(last) > 0 {
				return ErrInvalid
			}
			for _, old := range ranges {
				if first.Compare(old[1]) <= 0 && last.Compare(old[0]) >= 0 {
					return ErrInvalid
				}
			}
			addresses += uint64(number(last)) - uint64(number(first)) + 1
			if addresses > 65536 {
				return ErrInvalid
			}
			ranges = append(ranges, [2]netip.Addr{first, last})
		}
		excluded, reserved, macs := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, value := range s.Excluded {
			if _, ok := host(value, p); !ok || excluded[value] {
				return ErrInvalid
			}
			excluded[value] = true
		}
		for _, r := range s.Reservations {
			if len(r.MAC) != 17 {
				return ErrInvalid
			}
			mac, err := net.ParseMAC(r.MAC)
			if err != nil || len(mac) != 6 || mac.String() != r.MAC || mac[0]&1 != 0 || r.MAC == "00:00:00:00:00:00" || macs[r.MAC] || reserved[r.Address] || excluded[r.Address] || r.Address == s.Router {
				return ErrInvalid
			}
			if _, ok := host(r.Address, p); !ok {
				return ErrInvalid
			}
			macs[r.MAC], reserved[r.Address] = true, true
		}
		for _, pool := range ranges {
			if router.Compare(pool[0]) >= 0 && router.Compare(pool[1]) <= 0 && !excluded[s.Router] {
				return ErrInvalid
			}
		}
		for _, values := range [][]string{s.DNS, s.NTP} {
			if len(values) > 4 {
				return ErrInvalid
			}
			seen := map[string]bool{}
			for _, value := range values {
				if len(value) > 15 {
					return ErrInvalid
				}
				a, err := netip.ParseAddr(value)
				if err != nil || !a.Is4() || !a.IsGlobalUnicast() || a.String() != value || seen[value] {
					return ErrInvalid
				}
				seen[value] = true
			}
		}
	}
	return nil
}

func number(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func host(value string, p netip.Prefix) (netip.Addr, bool) {
	if len(value) > 15 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(value)
	if err != nil || !a.Is4() || !a.IsGlobalUnicast() || a.String() != value || !p.Contains(a) {
		return a, false
	}
	n := number(a)
	return a, a != p.Addr() && n != number(p.Addr())|(^uint32(0)>>p.Bits())
}

func identifier(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func domain(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 253 || strings.ToLower(value) != value {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
