// Package networkinventory observes network interfaces without configuring them.
package networkinventory

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	SchemaVersion = 1
	MaxInterfaces = 256
	MaxAddresses  = 256
	MaxNameBytes  = 256
)

var (
	ErrUnavailable = errors.New("network_inventory_unavailable")
	ErrLimit       = errors.New("network_inventory_limit")
	ErrObservation = errors.New("network_inventory_invalid_observation")
	ErrChanged     = errors.New("network_inventory_changed")
)

type Kind string

const (
	Unknown      Kind = "unknown"
	Loopback     Kind = "loopback"
	Virtual      Kind = "virtual"
	DeviceBacked Kind = "device-backed"
)

// Address retains a host address. Prefix is nil when the OS supplied no mask.
// A zone, when supplied, is not inferred from the interface name.
type Address struct {
	IP     netip.Addr
	Prefix *netip.Prefix
	Zone   string
}

// Running is the OS interface flag, not a measurement of physical carrier.
// DeviceBacked includes hardware presented by a hypervisor.
type Interface struct {
	Index           int
	Name            string
	MTU             int
	HardwareAddress string
	AdminUp         bool
	Running         bool
	PointToPoint    bool
	Multicast       bool
	Kind            Kind
	Addresses       []Address
}

type Snapshot struct {
	SchemaVersion int
	Interfaces    []Interface
}

type reader struct {
	interfaces func() ([]net.Interface, error)
	addresses  func(net.Interface) ([]net.Addr, error)
	kind       func(string) Kind
}

// Discover performs two complete observations and refuses observable changes.
// This is not an atomic kernel snapshot. Cancellation is checked between OS
// calls; the standard library does not make those calls context-cancellable.
func Discover(ctx context.Context) (Snapshot, error) {
	return (reader{
		interfaces: net.Interfaces,
		addresses:  func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() },
		kind:       interfaceKind,
	}).discover(ctx)
}

func (r reader) discover(ctx context.Context) (Snapshot, error) {
	first, err := r.observe(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	second, err := r.observe(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if !reflect.DeepEqual(first, second) {
		return Snapshot{}, ErrChanged
	}
	return second, nil
}

func (r reader) observe(ctx context.Context) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	observed, err := r.interfaces()
	if err != nil {
		return Snapshot{}, ErrUnavailable
	}
	if len(observed) > MaxInterfaces {
		return Snapshot{}, ErrLimit
	}
	result := Snapshot{SchemaVersion: SchemaVersion, Interfaces: make([]Interface, 0, len(observed))}
	indexes, names := make(map[int]bool, len(observed)), make(map[string]bool, len(observed))
	for _, iface := range observed {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		if iface.Index <= 0 || !validName(iface.Name) || iface.MTU < 0 || len(iface.HardwareAddr) > 64 || indexes[iface.Index] || names[iface.Name] {
			return Snapshot{}, ErrObservation
		}
		indexes[iface.Index], names[iface.Name] = true, true
		addresses, err := r.addresses(iface)
		if err != nil {
			return Snapshot{}, ErrUnavailable
		}
		if len(addresses) > MaxAddresses {
			return Snapshot{}, ErrLimit
		}
		item := Interface{
			Index: iface.Index, Name: iface.Name, MTU: iface.MTU,
			HardwareAddress: iface.HardwareAddr.String(),
			AdminUp:         iface.Flags&net.FlagUp != 0, Running: iface.Flags&net.FlagRunning != 0,
			PointToPoint: iface.Flags&net.FlagPointToPoint != 0, Multicast: iface.Flags&net.FlagMulticast != 0,
			Kind: Unknown, Addresses: make([]Address, 0, len(addresses)),
		}
		seen := make(map[addressKey]bool, len(addresses))
		for _, raw := range addresses {
			if err := ctx.Err(); err != nil {
				return Snapshot{}, err
			}
			address, err := parseAddress(raw)
			if err != nil {
				return Snapshot{}, err
			}
			key := keyFor(address)
			if !seen[key] {
				seen[key] = true
				item.Addresses = append(item.Addresses, address)
			}
		}
		slices.SortFunc(item.Addresses, compareAddress)
		if iface.Flags&net.FlagLoopback != 0 {
			item.Kind = Loopback
		} else {
			item.Kind = r.kind(iface.Name)
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	slices.SortFunc(result.Interfaces, func(a, b Interface) int {
		if a.Index < b.Index {
			return -1
		}
		if a.Index > b.Index {
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return result, nil
}

func validName(name string) bool {
	if name == "" || len(name) > MaxNameBytes || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsAny(name, "/\\") {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) == -1
}

func parseAddress(raw net.Addr) (Address, error) {
	var result Address
	switch address := raw.(type) {
	case *net.IPNet:
		if address == nil {
			return result, ErrObservation
		}
		ip, ok := netip.AddrFromSlice(address.IP)
		ones, bits := address.Mask.Size()
		if !ok || (bits != 32 && bits != 128) {
			return result, ErrObservation
		}
		if bits == 32 {
			ip = ip.Unmap()
		}
		if ip.BitLen() != bits {
			return result, ErrObservation
		}
		prefix := netip.PrefixFrom(ip, ones)
		result = Address{IP: ip, Prefix: &prefix}
	case *net.IPAddr:
		if address == nil {
			return result, ErrObservation
		}
		ip, ok := netip.AddrFromSlice(address.IP)
		if !ok || (address.Zone != "" && (!validName(address.Zone) || !ip.Is6() || ip.Is4In6())) {
			return result, ErrObservation
		}
		result = Address{IP: ip.Unmap(), Zone: address.Zone}
	default:
		return result, ErrObservation
	}
	return result, nil
}

type addressKey struct {
	ip   netip.Addr
	zone string
	bits int
}

func keyFor(address Address) addressKey {
	bits := -1
	if address.Prefix != nil {
		bits = address.Prefix.Bits()
	}
	return addressKey{address.IP, address.Zone, bits}
}

func compareAddress(a, b Address) int {
	if order := a.IP.Compare(b.IP); order != 0 {
		return order
	}
	if order := strings.Compare(a.Zone, b.Zone); order != 0 {
		return order
	}
	return keyFor(a).bits - keyFor(b).bits
}
