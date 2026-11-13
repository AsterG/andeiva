package firewallipc

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/AsterG/andeiva/internal/networkinventory"
)

func inventoryFixtureV3() networkinventory.Snapshot {
	p4 := netip.MustParsePrefix("192.0.2.1/24")
	p6 := netip.MustParsePrefix("2001:db8::1/64")
	return networkinventory.Snapshot{SchemaVersion: 1, Interfaces: []networkinventory.Interface{{Index: 2, Name: "lan0", MTU: 1500, HardwareAddress: "02:00:00:00:00:01", AdminUp: true, Running: true, Multicast: true, Kind: networkinventory.Virtual, Addresses: []networkinventory.Address{{IP: p4.Addr(), Prefix: &p4}, {IP: p6.Addr(), Prefix: &p6}}}}}
}
func TestRoutedInventoryV3TypedRoundTripAndBounds(t *testing.T) {
	original := inventoryFixtureV3()
	wire, err := EncodeRoutedInventoryV3(original)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := decodeRoutedInventoryV3(raw)
	if err != nil || !reflect.DeepEqual(original, actual) {
		t.Fatal(actual, err)
	}
	actual.Interfaces[0].Addresses[0].Prefix = nil
	if original.Interfaces[0].Addresses[0].Prefix == nil {
		t.Fatal("caller mutated observed snapshot")
	}
	for _, mutate := range []func(*RoutedInventoryV3){
		func(w *RoutedInventoryV3) { w.SchemaVersion = 2 }, func(w *RoutedInventoryV3) { w.Interfaces = nil },
		func(w *RoutedInventoryV3) { w.Interfaces[0].Index = 0 }, func(w *RoutedInventoryV3) { w.Interfaces[0].Name = "../host" }, func(w *RoutedInventoryV3) { w.Interfaces[0].Kind = "kernel-detail" },
		func(w *RoutedInventoryV3) { w.Interfaces[0].HardwareAddress = "02:00:00:00:00:FF" }, func(w *RoutedInventoryV3) { w.Interfaces[0].Addresses[0].IP = "::ffff:192.0.2.1" },
		func(w *RoutedInventoryV3) { p := "198.51.100.1/24"; w.Interfaces[0].Addresses[0].Prefix = &p }, func(w *RoutedInventoryV3) { w.Interfaces = append(w.Interfaces, w.Interfaces[0]) },
	} {
		var changed RoutedInventoryV3
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		if _, err = decodeRoutedInventoryV3(mustInventoryJSONV3(t, changed)); err == nil {
			t.Fatal("invalid observation accepted")
		}
	}
	missing := strings.Replace(string(raw), `"admin_up":true,`, "", 1)
	if _, err = decodeRoutedInventoryV3([]byte(missing)); err == nil {
		t.Fatal("missing false-compatible field accepted")
	}
	nullFlag := strings.Replace(string(raw), `"admin_up":true`, `"admin_up":null`, 1)
	if _, err = decodeRoutedInventoryV3([]byte(nullFlag)); err == nil {
		t.Fatal("unknown boolean interpreted as false")
	}
	unknown := strings.Replace(string(raw), `"kind":"virtual"`, `"kind":"virtual","command":"ip"`, 1)
	if _, err = decodeRoutedInventoryV3([]byte(unknown)); err == nil {
		t.Fatal("unknown nested control accepted")
	}
	if _, err = decodeRoutedInventoryV3([]byte(strings.Repeat(" ", RoutedInventoryLimitV3+1))); err == nil {
		t.Fatal("oversize accepted")
	}
	large := inventoryFixtureV3()
	large.Interfaces[0].Addresses = nil
	for i := 0; i < networkinventory.MaxAddresses; i++ {
		address := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)})
		large.Interfaces[0].Addresses = append(large.Interfaces[0].Addresses, networkinventory.Address{IP: address, Zone: strings.Repeat("z", 256)})
	}
	if partial, e := EncodeRoutedInventoryV3(large); e == nil || partial.SchemaVersion != 0 {
		t.Fatal("budgeted snapshot truncated or acknowledged")
	}
	tooLarge := inventoryFixtureV3()
	tooLarge.Interfaces = make([]networkinventory.Interface, networkinventory.MaxInterfaces+1)
	if _, err = EncodeRoutedInventoryV3(tooLarge); err == nil {
		t.Fatal("interface bound ignored")
	}
}
func mustInventoryJSONV3(t *testing.T, value any) []byte {
	t.Helper()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func TestRoutedInventoryV3CapabilityAndArgumentContract(t *testing.T) {
	hello := NewRoutedHelloV3(strings.Repeat("a", 32), 22)
	for _, features := range [][]string{hello.RequiredFeatures, append(append([]string{}, hello.RequiredFeatures...), RoutedIntegrityCapabilityV3), append(append([]string{}, hello.RequiredFeatures...), RoutedIntegrityCapabilityV3, RoutedInventoryCapabilityV3)} {
		hello.RequiredFeatures = features
		if _, err := DecodeRoutedHelloV3(mustInventoryJSONV3(t, hello), false); err != nil {
			t.Fatal("prior/new feature profile refused", err)
		}
	}
	hello = NewRoutedHelloV3(strings.Repeat("a", 32), 22)
	hello.RequiredFeatures = append(hello.RequiredFeatures, RoutedInventoryCapabilityV3)
	if _, err := DecodeRoutedHelloV3(mustInventoryJSONV3(t, hello), false); err == nil {
		t.Fatal("inventory without integrity accepted")
	}
	valid := routedWireV3(t, "inventory", struct{}{})
	if _, _, err := DecodeRoutedRequestV3(valid, strings.Repeat("a", 32), 22, 6); err != nil {
		t.Fatal(err)
	}
	withArguments := routedWireV3(t, "inventory", map[string]string{"namespace": "host"})
	if _, _, err := DecodeRoutedRequestV3(withArguments, strings.Repeat("a", 32), 22, 6); err == nil {
		t.Fatal("inventory namespace argument accepted")
	}
}

func BenchmarkRoutedInventoryV3Codec(b *testing.B) {
	snapshot := inventoryFixtureV3()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		value, e := EncodeRoutedInventoryV3(snapshot)
		if e != nil {
			b.Fatal(e)
		}
		raw, e := json.Marshal(value)
		if e != nil {
			b.Fatal(e)
		}
		if _, e = decodeRoutedInventoryV3(raw); e != nil {
			b.Fatal(e)
		}
	}
}
