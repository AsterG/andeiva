package adminclient

import (
	"context"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AsterG/andeiva/internal/adminapi"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

func (c *Client) CurrentConfigurationV2(ctx context.Context) (adminapi.CurrentV2, error) {
	var out struct {
		SchemaVersion int                `json:"schema_version"`
		Current       adminapi.CurrentV2 `json:"current"`
	}
	err := c.callV2(ctx, http.MethodGet, "/api/v2/config/current", nil, &out, http.StatusOK)
	if err == nil && (out.SchemaVersion != 2 || !validCurrentV2(out.Current)) {
		err = ErrResponse
	}
	if err != nil {
		return adminapi.CurrentV2{}, err
	}
	return out.Current, nil
}

func validNetworkInterfacesV2(out adminapi.NetworkInterfacesV2) bool {
	if out.SchemaVersion != 1 || out.Interfaces == nil || len(out.Interfaces) > networkinventory.MaxInterfaces {
		return false
	}
	names := map[string]bool{}
	for _, iface := range out.Interfaces {
		if iface.Name == "" || len(iface.Name) > networkinventory.MaxNameBytes || !utf8.ValidString(iface.Name) || iface.Name == "." || iface.Name == ".." || strings.ContainsAny(iface.Name, "/\\") || strings.IndexFunc(iface.Name, unicode.IsControl) >= 0 || names[iface.Name] || iface.MTU < 0 || iface.MTU > math.MaxInt32 || iface.Addresses == nil || len(iface.Addresses) > networkinventory.MaxAddresses {
			return false
		}
		names[iface.Name] = true
		if iface.HardwareAddress != "" {
			mac, err := net.ParseMAC(iface.HardwareAddress)
			if err != nil || mac.String() != iface.HardwareAddress {
				return false
			}
		}
		switch iface.Kind {
		case networkinventory.Unknown, networkinventory.Loopback, networkinventory.Virtual, networkinventory.DeviceBacked:
		default:
			return false
		}
		seen := map[string]bool{}
		for _, entry := range iface.Addresses {
			address, err := netip.ParseAddr(entry.IP)
			if err != nil || address.Is4In6() || address.Zone() != "" || address.String() != entry.IP {
				return false
			}
			key := entry.IP
			if entry.Prefix != nil {
				prefix, err := netip.ParsePrefix(*entry.Prefix)
				if err != nil || prefix.Addr() != address || prefix.String() != *entry.Prefix {
					return false
				}
				key += "/" + *entry.Prefix
			}
			if seen[key] {
				return false
			}
			seen[key] = true
		}
	}
	return true
}

func (c *Client) NetworkInterfacesV2(ctx context.Context) (adminapi.NetworkInterfacesV2, error) {
	var out adminapi.NetworkInterfacesV2
	err := c.callV2(ctx, http.MethodGet, "/api/v2/network/interfaces", nil, &out, http.StatusOK)
	if err == nil && !validNetworkInterfacesV2(out) {
		err = ErrResponse
	}
	if err != nil {
		return adminapi.NetworkInterfacesV2{}, err
	}
	return out, nil
}
