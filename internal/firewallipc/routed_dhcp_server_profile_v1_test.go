package firewallipc

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRoutedDHCPServerProfileV1RequiresExactPeer(t *testing.T) {
	for _, advertised := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		client, helper := net.Pipe()
		go func() {
			defer helper.Close()
			var request RoutedHelloV3
			if json.NewDecoder(helper).Decode(&request) != nil || !request.HasCapability(RoutedDHCPServerCapabilityV1) {
				return
			}
			request.Run, request.Epoch = request.RuntimeRun, 1
			if !advertised {
				request.RequiredFeatures = request.RequiredFeatures[:len(request.RequiredFeatures)-1]
			}
			_ = json.NewEncoder(helper).Encode(request)
		}()
		routed, err := ConnectRoutedDHCPServerV1(ctx, client, strings.Repeat("a", 32), 42, false, true)
		cancel()
		if advertised != (err == nil && routed.DHCPServerEnabledV1()) {
			t.Fatal("unexpected helper profile", advertised, err)
		}
		if routed != nil {
			_ = routed.Close()
		}
	}

	hello := NewRoutedHelloV3(strings.Repeat("a", 32), 42)
	hello.RequiredFeatures = append(hello.RequiredFeatures, RoutedIntegrityCapabilityV3, RoutedInventoryCapabilityV3, RoutedDHCPCapabilityV3, RoutedDHCPServerCapabilityV1)
	raw, err := json.Marshal(hello)
	if _, err := DecodeRoutedHelloV3(raw, false); err == nil {
		t.Fatal("LAN profile without WAN renewal accepted")
	} else if err != ErrChannel {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
}
