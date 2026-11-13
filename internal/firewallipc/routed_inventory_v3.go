package firewallipc

import (
	"bytes"
	"encoding/json"
	"math"
	"net"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

const RoutedInventoryCapabilityV3 = "routed_inventory.v1"
const RoutedInventoryLimitV3 = configpoc.RoutedArtifactLimit

type RoutedInventoryAddressV3 struct {
	IP     string  `json:"ip"`
	Prefix *string `json:"prefix"`
	Zone   string  `json:"zone"`
}
type RoutedInventoryInterfaceV3 struct {
	Index           int                        `json:"index"`
	Name            string                     `json:"name"`
	MTU             int                        `json:"mtu"`
	HardwareAddress string                     `json:"hardware_address"`
	AdminUp         bool                       `json:"admin_up"`
	Running         bool                       `json:"running"`
	PointToPoint    bool                       `json:"point_to_point"`
	Multicast       bool                       `json:"multicast"`
	Kind            networkinventory.Kind      `json:"kind"`
	Addresses       []RoutedInventoryAddressV3 `json:"addresses"`
}
type RoutedInventoryV3 struct {
	SchemaVersion int                          `json:"schema_version"`
	Interfaces    []RoutedInventoryInterfaceV3 `json:"interfaces"`
}

func inventoryNameV3(value string) bool {
	return value != "" && len(value) <= networkinventory.MaxNameBytes && utf8.ValidString(value) && value != "." && value != ".." && !strings.ContainsAny(value, "/\\") && strings.IndexFunc(value, unicode.IsControl) < 0
}

// Inventory is an observation, never an interface configuration or authority.
// Explicit wire types exclude incidental Go/runtime fields. Oversize snapshots
// fail as a whole; no interface/address is silently truncated.
func EncodeRoutedInventoryV3(snapshot networkinventory.Snapshot) (RoutedInventoryV3, error) {
	if snapshot.SchemaVersion != 1 || snapshot.Interfaces == nil || len(snapshot.Interfaces) > networkinventory.MaxInterfaces {
		return RoutedInventoryV3{}, ErrChannel
	}
	out := RoutedInventoryV3{SchemaVersion: snapshot.SchemaVersion, Interfaces: make([]RoutedInventoryInterfaceV3, 0, len(snapshot.Interfaces))}
	size := 128
	for _, item := range snapshot.Interfaces {
		if item.Addresses == nil || len(item.Addresses) > networkinventory.MaxAddresses {
			return RoutedInventoryV3{}, ErrChannel
		}
		size += 512 + 6*(len(item.Name)+len(item.HardwareAddress))
		if size > RoutedInventoryLimitV3 {
			return RoutedInventoryV3{}, ErrChannel
		}
		next := RoutedInventoryInterfaceV3{Index: item.Index, Name: item.Name, MTU: item.MTU, HardwareAddress: item.HardwareAddress, AdminUp: item.AdminUp, Running: item.Running, PointToPoint: item.PointToPoint, Multicast: item.Multicast, Kind: item.Kind, Addresses: make([]RoutedInventoryAddressV3, 0, len(item.Addresses))}
		for _, address := range item.Addresses {
			entry := RoutedInventoryAddressV3{IP: address.IP.String(), Zone: address.Zone}
			if address.Prefix != nil {
				value := address.Prefix.String()
				entry.Prefix = &value
			}
			prefixSize := 0
			if entry.Prefix != nil {
				prefixSize = len(*entry.Prefix)
			}
			size += 256 + 6*(len(entry.IP)+prefixSize+len(entry.Zone))
			if size > RoutedInventoryLimitV3 {
				return RoutedInventoryV3{}, ErrChannel
			}
			next.Addresses = append(next.Addresses, entry)
		}
		out.Interfaces = append(out.Interfaces, next)
	}
	if _, err := out.Snapshot(); err != nil {
		return RoutedInventoryV3{}, err
	}
	return out, nil
}
func (value RoutedInventoryV3) Snapshot() (networkinventory.Snapshot, error) {
	if value.SchemaVersion != 1 || value.Interfaces == nil || len(value.Interfaces) > networkinventory.MaxInterfaces {
		return networkinventory.Snapshot{}, ErrChannel
	}
	out := networkinventory.Snapshot{SchemaVersion: 1, Interfaces: make([]networkinventory.Interface, 0, len(value.Interfaces))}
	names, indexes := map[string]bool{}, map[int]bool{}
	// Conservative escaped-JSON accounting prevents a large observation from
	// allocating an unbounded intermediate frame before the final byte check.
	size := 128
	for _, item := range value.Interfaces {
		if item.Index <= 0 || indexes[item.Index] || !inventoryNameV3(item.Name) || names[item.Name] || item.MTU < 0 || item.MTU > math.MaxInt32 || item.Addresses == nil || len(item.Addresses) > networkinventory.MaxAddresses {
			return networkinventory.Snapshot{}, ErrChannel
		}
		indexes[item.Index], names[item.Name] = true, true
		if item.HardwareAddress != "" {
			mac, err := net.ParseMAC(item.HardwareAddress)
			if err != nil || len(mac) > 64 || mac.String() != item.HardwareAddress {
				return networkinventory.Snapshot{}, ErrChannel
			}
		}
		switch item.Kind {
		case networkinventory.Unknown, networkinventory.Loopback, networkinventory.Virtual, networkinventory.DeviceBacked:
		default:
			return networkinventory.Snapshot{}, ErrChannel
		}
		size += 512 + 6*len(item.Name) + 6*len(item.HardwareAddress)
		next := networkinventory.Interface{Index: item.Index, Name: item.Name, MTU: item.MTU, HardwareAddress: item.HardwareAddress, AdminUp: item.AdminUp, Running: item.Running, PointToPoint: item.PointToPoint, Multicast: item.Multicast, Kind: item.Kind, Addresses: make([]networkinventory.Address, 0, len(item.Addresses))}
		addresses := map[string]bool{}
		for _, address := range item.Addresses {
			ip, err := netip.ParseAddr(address.IP)
			if err != nil || !ip.IsValid() || ip.Is4In6() || ip.Zone() != "" || ip.String() != address.IP || (address.Zone != "" && !inventoryNameV3(address.Zone)) {
				return networkinventory.Snapshot{}, ErrChannel
			}
			entry := networkinventory.Address{IP: ip, Zone: address.Zone}
			prefixText := ""
			if address.Prefix != nil {
				prefixText = *address.Prefix
				prefix, e := netip.ParsePrefix(prefixText)
				if e != nil || !prefix.IsValid() || prefix.Addr() != ip || prefix.String() != prefixText {
					return networkinventory.Snapshot{}, ErrChannel
				}
				entry.Prefix = &prefix
			}
			key := address.IP + "\x00" + prefixText + "\x00" + address.Zone
			if addresses[key] {
				return networkinventory.Snapshot{}, ErrChannel
			}
			addresses[key] = true
			size += 256 + 6*(len(address.IP)+len(prefixText)+len(address.Zone))
			if size > RoutedInventoryLimitV3 {
				return networkinventory.Snapshot{}, ErrChannel
			}
			next.Addresses = append(next.Addresses, entry)
		}
		if size > RoutedInventoryLimitV3 {
			return networkinventory.Snapshot{}, ErrChannel
		}
		out.Interfaces = append(out.Interfaces, next)
	}
	return out, nil
}
func decodeRoutedInventoryV3(data []byte) (networkinventory.Snapshot, error) {
	var value RoutedInventoryV3
	if len(data) == 0 || len(data) > RoutedInventoryLimitV3 || exactRoutedV3(data, &value, []string{"schema_version", "interfaces"}) != nil || len(value.Interfaces) > networkinventory.MaxInterfaces {
		return networkinventory.Snapshot{}, ErrChannel
	}
	// Require all nested observation fields; zero values must not mask omissions.
	var raw struct {
		Interfaces []json.RawMessage `json:"interfaces"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return networkinventory.Snapshot{}, ErrChannel
	}
	for _, item := range raw.Interfaces {
		var nested struct {
			Addresses []json.RawMessage `json:"addresses"`
		}
		var wire RoutedInventoryInterfaceV3
		if !inventoryNonNullV3(item, "") || exactRoutedV3(item, &wire, []string{"index", "name", "mtu", "hardware_address", "admin_up", "running", "point_to_point", "multicast", "kind", "addresses"}) != nil || json.Unmarshal(item, &nested) != nil || len(nested.Addresses) > networkinventory.MaxAddresses {
			return networkinventory.Snapshot{}, ErrChannel
		}
		for _, address := range nested.Addresses {
			var entry RoutedInventoryAddressV3
			if !inventoryNonNullV3(address, "prefix") || exactRoutedV3(address, &entry, []string{"ip", "prefix", "zone"}) != nil {
				return networkinventory.Snapshot{}, ErrChannel
			}
		}
	}
	return value.Snapshot()
}

func inventoryNonNullV3(data []byte, nullable string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return false
	}
	for name, raw := range fields {
		if name != nullable && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
}
