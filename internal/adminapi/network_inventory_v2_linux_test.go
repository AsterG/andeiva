//go:build linux

package adminapi

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkinventory"
)

func TestRuntimeNetworkInventoryExplicitDTOAndPermissions(t *testing.T) {
	var calls atomic.Int32
	prefix := netip.MustParsePrefix("198.18.0.2/24")
	f := runtimeOperationsFixtureV2(t, func(ctx context.Context) (networkinventory.Snapshot, error) {
		calls.Add(1)
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 11*time.Second {
			t.Error("provider missing request bound")
		}
		return networkinventory.Snapshot{SchemaVersion: 1, Interfaces: []networkinventory.Interface{{Index: 747, Name: "lan0", HardwareAddress: "00:11:22:33:44:55", MTU: 1500, AdminUp: true, Running: true, Kind: networkinventory.DeviceBacked, Addresses: []networkinventory.Address{{IP: prefix.Addr(), Prefix: &prefix}, {IP: netip.MustParseAddr("fe80::1"), Zone: "hidden-zone"}}}}}, nil
	})
	status, body, _ := f.api.request(t, "GET", "/api/v2/network/interfaces", "", map[string]string{})
	if status != 401 || calls.Load() != 0 {
		t.Fatal("anonymous inventory observed", status)
	}
	f.headers["Authorization"] = "Bearer " + f.tokens["viewer"]
	var inventory NetworkInterfacesV2
	f.call(t, "GET", "/api/v2/network/interfaces", nil, 200, &inventory)
	if calls.Load() != 1 || len(inventory.Interfaces) != 1 || inventory.Interfaces[0].Addresses[0].Prefix == nil || *inventory.Interfaces[0].Addresses[0].Prefix != "198.18.0.2/24" || inventory.Interfaces[0].Addresses[1].Prefix != nil {
		t.Fatal("invented or omitted observed fields")
	}
	status, body, _ = f.api.request(t, "GET", "/api/v2/network/interfaces", "", f.headers)
	if status != 200 || strings.Contains(body, "747") || strings.Contains(body, "hidden-zone") || strings.Contains(body, "SchemaVersion") || strings.Contains(body, "namespace") || !strings.Contains(body, `"prefix":null`) {
		t.Fatal("raw/internal inventory escaped", body)
	}
	before := calls.Load()
	f.call(t, "POST", "/api/v2/network/interfaces", struct{}{}, 405, nil)
	if calls.Load() != before {
		t.Fatal("POST called provider")
	}
	var caps Capabilities
	f.call(t, "GET", "/api/v1/capabilities", nil, 200, &caps)
	if !caps.NetworkInventoryV2 {
		t.Fatal("inventory capability missing")
	}
}
func TestRuntimeNetworkInventoryUnavailableNoFallback(t *testing.T) {
	for _, mode := range []string{"missing", "error", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			var f *operationsFixtureV2
			if mode == "missing" {
				f = runtimeOperationsFixtureV2(t)
			} else {
				f = runtimeOperationsFixtureV2(t, func(context.Context) (networkinventory.Snapshot, error) {
					if mode == "error" {
						return networkinventory.Snapshot{}, errors.New("private kernel path")
					}
					return networkinventory.Snapshot{SchemaVersion: 1, Interfaces: []networkinventory.Interface{{Name: "../host", Kind: networkinventory.Unknown}}}, nil
				})
			}
			status, body, _ := f.api.request(t, "GET", "/api/v2/network/interfaces", "", f.headers)
			if status != 503 || !strings.Contains(body, "ANDEIVA_NETWORK_INVENTORY_UNAVAILABLE") || strings.Contains(body, "kernel") {
				t.Fatal("unsafe provider fallback/error", status, body)
			}
			if mode == "missing" {
				var caps Capabilities
				f.call(t, "GET", "/api/v1/capabilities", nil, 200, &caps)
				if caps.NetworkInventoryV2 {
					t.Fatal("unavailable provider advertised")
				}
			}
		})
	}
}
