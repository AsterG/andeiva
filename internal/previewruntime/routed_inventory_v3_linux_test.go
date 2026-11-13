//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/networkinventory"
)

func TestRoutedInventoryV3SessionNegotiationAndFreshRead(t *testing.T) {
	authority := &routedTransportAuthorityV3{}
	session, err := NewRoutedSessionV3(authority, routedTransportReaderV3{})
	if err != nil {
		t.Fatal(err)
	}
	// This fixture exercises only negotiated read-only inventory, not integrity
	// qualification. No attach/check or engine command is performed here.
	session.integrity = &routedIntegrityGateV3{}
	var calls atomic.Int32
	session.inventory = func(ctx context.Context) (networkinventory.Snapshot, error) {
		n := calls.Add(1)
		if n == 3 {
			return networkinventory.Snapshot{}, errors.New("observation changed")
		}
		return networkinventory.Snapshot{SchemaVersion: 1, Interfaces: []networkinventory.Interface{{Index: 2, Name: "gateway-lan", MTU: int(1500 + n), Kind: networkinventory.Virtual, Addresses: []networkinventory.Address{}}}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- session.ServeRoutedV3(ctx, b, strings.Repeat("a", 32)) }()
	client, err := firewallipc.ConnectRoutedInventoryV3(ctx, a, strings.Repeat("a", 32), 22)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.Inventory(ctx)
	if err != nil || len(first.Interfaces) != 1 || first.Interfaces[0].Name != "gateway-lan" {
		t.Fatal(first, err)
	}
	second, err := client.Inventory(ctx)
	if err != nil || second.Interfaces[0].MTU == first.Interfaces[0].MTU {
		t.Fatal("cached observation", second, err)
	}
	if _, err = client.Inventory(ctx); err == nil {
		t.Fatal("unavailable observation replaced with cached/host data")
	}
	if calls.Load() != 3 || authority.calls.Load() != 0 || client.IntegrityPublicationAllowedV1() {
		t.Fatal("inventory caused engine effects/readiness")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("controller leaked")
	}
}
func TestRoutedInventoryV3NoLegacyDowngradeOrHostFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	session, err := NewRoutedSessionV3(&routedTransportAuthorityV3{}, routedTransportReaderV3{})
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- session.ServeRoutedV3(ctx, b, strings.Repeat("a", 32)) }()
	if client, e := firewallipc.ConnectRoutedInventoryV3(ctx, a, strings.Repeat("a", 32), 22); e == nil {
		_ = client.Close()
		t.Fatal("new client downgraded to legacy helper")
	}
	<-done
	legacy, legacyDone, e := routedTransportConnectV3(t, ctx, session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = legacy.Inventory(ctx); e == nil {
		t.Fatal("legacy client sent inventory without negotiation")
	}
	_ = legacy.Close()
	<-legacyDone
	current, e := namespaceID("/proc/self/ns/net")
	if e != nil {
		t.Fatal(e)
	}
	m := Metadata{SchemaVersion: RoutedMetadataSchemaVersion, RunID: strings.Repeat("a", 32), BootID: "12345678-1234-1234-1234-123456789abc", HostNamespace: current, GatewayNamespace: current + 1}
	if _, e = routedInventoryProviderV3(m)(ctx); e == nil {
		t.Fatal("API host discovery used as gateway inventory")
	}
}

func TestRoutedInventoryV3AssemblyRefusesInjectedProvider(t *testing.T) {
	for _, mode := range []string{"missing-integrity", "injected-provider"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			routed, peer := routedUnixPairV3(t)
			legacy, legacyPeer := routedUnixPairV3(t)
			area := routedCoordinatorRoot(t)
			var calls atomic.Int32
			o := OperationsRuntimeOptionsV2{RoutedInventory: true, Store: area}
			integrity := mode != "missing-integrity"
			if mode == "injected-provider" {
				o.NetworkInventory = func(context.Context) (networkinventory.Snapshot, error) {
					calls.Add(1)
					return networkinventory.Snapshot{}, nil
				}
			}
			runtime, err := connectRoutedOperationsModeV3(ctx, Metadata{}, Identities{}, routed, legacy, 1, 1, networkexecutor.OwnedNamespaceIdentity{}, o, integrity)
			if err == nil || runtime != nil || calls.Load() != 0 {
				t.Fatal("untrusted inventory assembly admitted", err)
			}
			for _, conn := range []*net.UnixConn{peer, legacyPeer} {
				if conn.SetReadDeadline(time.Now().Add(time.Second)) != nil {
					t.Fatal("deadline")
				}
				var b [1]byte
				n, e := conn.Read(b[:])
				if n != 0 || e != io.EOF {
					t.Fatal("channel retained or handshake emitted", n, e)
				}
			}
			files, e := os.ReadDir(area.Name())
			if e != nil || len(files) != 0 {
				t.Fatal("failed assembly wrote store", files, e)
			}
		})
	}
}
