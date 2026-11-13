// Package dhcpclient supervises an experimental dhcpcd acquisition process.
// A lease event is not permission to configure an interface or permit traffic.
package dhcpclient

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

var (
	ErrScope       = errors.New("ANDEIVA_DHCP_SCOPE")
	ErrEvent       = errors.New("ANDEIVA_DHCP_EVENT")
	ErrUnavailable = errors.New("ANDEIVA_DHCP_UNAVAILABLE")
)

const MaxEventBytes = 4096

// Event contains only the supported IPv4 hook fields. BootNS is CLOCK_BOOTTIME
// at hook execution, not a fabricated DHCP acquisition timestamp.
type Event struct {
	Version   int      `json:"version"`
	Interface string   `json:"interface"`
	Reason    string   `json:"reason"`
	PID       int      `json:"pid"`
	BootNS    int64    `json:"boot_ns"`
	Address   string   `json:"address,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	Server    string   `json:"server,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Seconds   uint32   `json:"seconds,omitempty"`
}

func granting(reason string) bool {
	return reason == "BOUND" || reason == "RENEW" || reason == "REBIND" || reason == "REBOOT"
}

func ipv4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	return a, err == nil && a.Is4() && a.String() == s && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func (e Event) validate() error {
	if e.Version != 1 || !interfaceName(e.Interface) || e.PID <= 1 || e.BootNS <= 0 {
		return ErrEvent
	}
	if !granting(e.Reason) {
		switch e.Reason {
		case "PREINIT", "CARRIER", "NOCARRIER", "NOCARRIER_ROAMING", "EXPIRE", "NAK", "STOP", "STOPPED", "DEPARTED", "FAIL", "TIMEOUT":
		default:
			return ErrEvent
		}
		if e.Address != "" || e.Gateway != "" || e.Server != "" || len(e.DNS) != 0 || e.Seconds != 0 {
			return ErrEvent
		}
		return nil
	}
	p, err := netip.ParsePrefix(e.Address)
	a, ok := ipv4(p.Addr().String())
	if err != nil || !ok || p.String() != e.Address || p.Bits() < 1 || p.Bits() > 30 || a == p.Masked().Addr() || e.Seconds < 10 || e.Seconds > 7*24*3600 {
		return ErrEvent
	}
	// Reject the subnet broadcast without assuming an octet-aligned prefix.
	x := a.As4()
	b := p.Masked().Addr().As4()
	av := uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3])
	bv := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if av == bv|(^uint32(0)>>p.Bits()) {
		return ErrEvent
	}
	g, gok := ipv4(e.Gateway)
	_, sok := ipv4(e.Server)
	if !gok || !sok || !p.Contains(g) || g == a || g == p.Masked().Addr() || len(e.DNS) > 4 {
		return ErrEvent
	}
	gx := g.As4()
	gv := uint32(gx[0])<<24 | uint32(gx[1])<<16 | uint32(gx[2])<<8 | uint32(gx[3])
	if gv == bv|(^uint32(0)>>p.Bits()) {
		return ErrEvent
	}
	seen := map[string]bool{}
	for _, d := range e.DNS {
		if _, ok := ipv4(d); !ok || seen[d] {
			return ErrEvent
		}
		seen[d] = true
	}
	return nil
}

func interfaceName(s string) bool {
	if len(s) == 0 || len(s) > 15 || s == "lo" {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-' || c == '.')) {
			return false
		}
	}
	return true
}

// HookEvent accepts dhcpcd's environment, never evaluates it as shell input.
// Unsupported route options are refused rather than silently installed.
func HookEvent(env []string, bootNS int64) (Event, error) {
	if len(env) > 256 {
		return Event{}, ErrEvent
	}
	m := map[string]string{}
	size := 0
	for _, entry := range env {
		size += len(entry)
		k, v, ok := strings.Cut(entry, "=")
		if !ok || size > 64<<10 || strings.IndexByte(entry, 0) >= 0 {
			return Event{}, ErrEvent
		}
		if _, exists := m[k]; exists {
			return Event{}, ErrEvent
		}
		m[k] = v
	}
	pid, err := strconv.Atoi(m["pid"])
	if err != nil || strconv.Itoa(pid) != m["pid"] {
		return Event{}, ErrEvent
	}
	e := Event{Version: 1, Interface: m["interface"], Reason: m["reason"], PID: pid, BootNS: bootNS}
	if granting(e.Reason) {
		if m["protocol"] != "dhcp" || m["if_configured"] != "false" {
			return Event{}, ErrEvent
		}
		for _, key := range []string{"new_classless_static_routes", "new_ms_classless_static_routes", "new_static_routes"} {
			if m[key] != "" {
				return Event{}, ErrEvent
			}
		}
		n, err := strconv.ParseUint(m["new_dhcp_lease_time"], 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != m["new_dhcp_lease_time"] {
			return Event{}, ErrEvent
		}
		e.Address = m["new_ip_address"] + "/" + m["new_subnet_cidr"]
		e.Gateway = m["new_routers"]
		e.Server = m["new_dhcp_server_identifier"]
		e.DNS = strings.Fields(m["new_domain_name_servers"])
		e.Seconds = uint32(n)
	}
	if err := e.validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}
