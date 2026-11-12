package adminapi

import (
	"context"
	"math"
	"net"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AsterG/andeiva/internal/networkinventory"
)

type NetworkAddressV2 struct {
	IP     string  `json:"ip"`
	Prefix *string `json:"prefix"`
}
type NetworkInterfaceV2 struct {
	Name            string                `json:"name"`
	HardwareAddress string                `json:"hardware_address"`
	MTU             int                   `json:"mtu"`
	AdminUp         bool                  `json:"admin_up"`
	Running         bool                  `json:"running"`
	Kind            networkinventory.Kind `json:"kind"`
	Addresses       []NetworkAddressV2    `json:"addresses"`
}
type NetworkInterfacesV2 struct {
	SchemaVersion int                  `json:"schema_version"`
	Interfaces    []NetworkInterfaceV2 `json:"interfaces"`
}

func networkInterfaceNameV2(name string) bool {
	return name != "" && len(name) <= networkinventory.MaxNameBytes && utf8.ValidString(name) && name != "." && name != ".." && !strings.ContainsAny(name, "/\\") && strings.IndexFunc(name, unicode.IsControl) < 0
}
func networkInventoryDTOv2(snapshot networkinventory.Snapshot) (NetworkInterfacesV2, bool) {
	if snapshot.SchemaVersion != networkinventory.SchemaVersion || len(snapshot.Interfaces) > networkinventory.MaxInterfaces {
		return NetworkInterfacesV2{}, false
	}
	out := NetworkInterfacesV2{SchemaVersion: 1, Interfaces: make([]NetworkInterfaceV2, 0, len(snapshot.Interfaces))}
	names := map[string]bool{}
	for _, iface := range snapshot.Interfaces {
		if !networkInterfaceNameV2(iface.Name) || names[iface.Name] || iface.MTU < 0 || iface.MTU > math.MaxInt32 || len(iface.Addresses) > networkinventory.MaxAddresses {
			return NetworkInterfacesV2{}, false
		}
		names[iface.Name] = true
		if iface.HardwareAddress != "" {
			mac, err := net.ParseMAC(iface.HardwareAddress)
			if err != nil || len(mac) > 64 || mac.String() != iface.HardwareAddress {
				return NetworkInterfacesV2{}, false
			}
		}
		switch iface.Kind {
		case networkinventory.Unknown, networkinventory.Loopback, networkinventory.Virtual, networkinventory.DeviceBacked:
		default:
			return NetworkInterfacesV2{}, false
		}
		item := NetworkInterfaceV2{Name: iface.Name, HardwareAddress: iface.HardwareAddress, MTU: iface.MTU, AdminUp: iface.AdminUp, Running: iface.Running, Kind: iface.Kind, Addresses: make([]NetworkAddressV2, 0, len(iface.Addresses))}
		for _, address := range iface.Addresses {
			if !address.IP.IsValid() || address.IP.Is4In6() || address.IP.Zone() != "" {
				return NetworkInterfacesV2{}, false
			}
			entry := NetworkAddressV2{IP: address.IP.String()}
			if address.Prefix != nil {
				if !address.Prefix.IsValid() || address.Prefix.Addr() != address.IP {
					return NetworkInterfacesV2{}, false
				}
				value := address.Prefix.String()
				entry.Prefix = &value
			}
			item.Addresses = append(item.Addresses, entry)
		}
		out.Interfaces = append(out.Interfaces, item)
	}
	return out, true
}
func (h *handler) networkInterfacesV2(w http.ResponseWriter, r *http.Request, ctx context.Context, token string) {
	if r.Method != http.MethodGet {
		h.fail(w, 405, "ANDEIVA_METHOD_NOT_ALLOWED")
		return
	}
	binding, err := h.options.Auth.ResolveSession(token)
	if err != nil {
		h.fail(w, 403, "ANDEIVA_CONFIG_DENIED")
		return
	}
	if _, err = h.preparedOperations.Current(binding, "firewall"); err != nil {
		h.operationErrorV2(w, err)
		return
	}
	if h.options.NetworkInventory == nil {
		h.fail(w, 503, "ANDEIVA_NETWORK_INVENTORY_UNAVAILABLE")
		return
	}
	snapshot, err := h.options.NetworkInventory(ctx)
	if err != nil || ctx.Err() != nil {
		h.fail(w, 503, "ANDEIVA_NETWORK_INVENTORY_UNAVAILABLE")
		return
	}
	response, ok := networkInventoryDTOv2(snapshot)
	if !ok || ctx.Err() != nil {
		h.fail(w, 503, "ANDEIVA_NETWORK_INVENTORY_UNAVAILABLE")
		return
	}
	h.writeV2(w, 200, response)
}
