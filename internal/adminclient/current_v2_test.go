package adminclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestCurrentAndInventoryV2UseVerifiedTransportWithoutDowngrade(t *testing.T) {
	operation, _ := wireFixtureV2(t)
	current := struct {
		SchemaVersion int `json:"schema_version"`
		Current       any `json:"current"`
	}{2, operation.Current}
	for _, mode := range []string{"current", "inventory", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			client, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet || r.TLS == nil || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
					t.Error("authenticated HTTPS required")
				}
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "current":
					if r.URL.Path != "/api/v2/config/current" {
						t.Error("unexpected path", r.URL.Path)
					}
					_ = json.NewEncoder(w).Encode(current)
				case "inventory":
					if r.URL.Path != "/api/v2/network/interfaces" {
						t.Error("unexpected path", r.URL.Path)
					}
					_, _ = w.Write([]byte(`{"schema_version":1,"interfaces":[{"name":"lan0","hardware_address":"02:00:00:00:00:01","mtu":1500,"admin_up":true,"running":false,"kind":"virtual","addresses":[{"ip":"192.0.2.1","prefix":"192.0.2.1/24"}]}]}`))
				case "unavailable":
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"code":"ANDEIVA_NOT_FOUND","request_id":"bounded-id"}`))
				}
			}))
			client.token = strings.Repeat("a", 64)
			if mode == "inventory" {
				out, err := client.NetworkInterfacesV2(context.Background())
				if err != nil || out.Interfaces[0].Addresses[0].IP != "192.0.2.1" || out.Interfaces[0].Running {
					t.Fatal("observation changed", err)
				}
			} else {
				out, err := client.CurrentConfigurationV2(context.Background())
				if mode == "current" && (err != nil || out.Global.Generation != operation.Current.Global.Generation) {
					t.Fatal("current unavailable", err)
				}
				if mode == "unavailable" && err == nil {
					t.Fatal("v2 refusal silently downgraded")
				}
			}
			if calls != 1 {
				t.Fatal("unexpected retry or downgrade", calls)
			}
		})
	}
}

func TestInventoryV2ClientRejectsMalformedOrPrivateData(t *testing.T) {
	for _, payload := range []string{
		`{"schema_version":1,"interfaces":null}`,
		`{"schema_version":1,"interfaces":[],"namespace":123}`,
		`{"schema_version":1,"interfaces":[{"name":"lan0","index":7,"hardware_address":"","mtu":1500,"admin_up":true,"running":true,"kind":"virtual","addresses":[]}]}`,
		`{"schema_version":1,"interfaces":[{"name":"lan0","hardware_address":"","mtu":1500,"admin_up":true,"running":true,"kind":"virtual","addresses":[{"ip":"192.0.2.1","prefix":"192.0.2.0/24"}]}]}`,
	} {
		client, _ := trustedClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(payload))
		}))
		client.token = strings.Repeat("a", 64)
		if _, err := client.NetworkInterfacesV2(context.Background()); !errors.Is(err, ErrResponse) {
			t.Fatal("invalid inventory accepted", err)
		}
	}
}
