package networkinventory

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func fixtureReader() reader {
	return reader{
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Index: 1, Name: "test0", MTU: 1500, Flags: net.FlagUp}}, nil
		},
		addresses: func(net.Interface) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.17"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		kind: func(string) Kind { return Unknown },
	}
}

func assertEmpty(t *testing.T, snapshot Snapshot, err, expected error) {
	t.Helper()
	if !errors.Is(err, expected) || !reflect.DeepEqual(snapshot, Snapshot{}) {
		t.Fatalf("got snapshot=%+v error=%v; want empty snapshot and %v", snapshot, err, expected)
	}
}

func TestStableObservedOrderAndHostAddresses(t *testing.T) {
	r := fixtureReader()
	r.interfaces = func() ([]net.Interface, error) {
		return []net.Interface{
			{Index: 8, Name: "uplink", MTU: 1500, HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 8}, Flags: net.FlagUp | net.FlagMulticast},
			{Index: 2, Name: "local", MTU: 65536, Flags: net.FlagLoopback | net.FlagRunning},
		}, nil
	}
	r.addresses = func(net.Interface) ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("2001:db8::27"), Mask: net.CIDRMask(64, 128)},
			&net.IPNet{IP: net.ParseIP("192.0.2.17"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("192.0.2.17"), Mask: net.CIDRMask(24, 32)},
		}, nil
	}
	snapshot, err := r.discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || len(snapshot.Interfaces) != 2 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	local, uplink := snapshot.Interfaces[0], snapshot.Interfaces[1]
	if local.Index != 2 || local.Kind != Loopback || local.AdminUp || !local.Running || !uplink.AdminUp || uplink.Running || !uplink.Multicast {
		t.Fatalf("flags or ordering lost: %+v", snapshot.Interfaces)
	}
	if uplink.HardwareAddress != "02:00:00:00:00:08" || uplink.Kind != Unknown || len(uplink.Addresses) != 2 {
		t.Fatalf("unexpected observed interface: %+v", uplink)
	}
	if got := uplink.Addresses[0].Prefix.String(); got != "192.0.2.17/24" {
		t.Fatalf("host address was masked or changed: %s", got)
	}
	if got := uplink.Addresses[1].Prefix.String(); got != "2001:db8::27/64" {
		t.Fatalf("IPv6 host address was masked or changed: %s", got)
	}
}

func TestAddressWithoutMaskRemainsExplicitlyUnknown(t *testing.T) {
	address, err := parseAddress(&net.IPAddr{IP: net.ParseIP("fe80::123"), Zone: "test0"})
	if err != nil || address.IP != netip.MustParseAddr("fe80::123") || address.Prefix != nil || address.Zone != "test0" {
		t.Fatalf("invented mask or lost zone: %+v %v", address, err)
	}
}

func TestAddressBoundaries(t *testing.T) {
	var nilNetwork *net.IPNet
	var nilAddress *net.IPAddr
	cases := map[string]net.Addr{
		"nil-interface": nil, "nil-network": nilNetwork, "nil-address": nilAddress,
		"unknown-type":        &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80},
		"bad-ip":              &net.IPNet{IP: net.IP{1, 2}, Mask: net.CIDRMask(24, 32)},
		"non-contiguous-mask": &net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.IPMask{255, 0, 255, 0}},
		"wrong-mask-family":   &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(24, 32)},
		"invalid-zone":        &net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "../../other"},
		"zone-on-v4":          &net.IPAddr{IP: net.IP{192, 0, 2, 1}, Zone: "test0"},
		"zone-on-mapped-v4":   &net.IPAddr{IP: net.ParseIP("192.0.2.1"), Zone: "test0"},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAddress(raw); !errors.Is(err, ErrObservation) {
				t.Fatalf("accepted invalid observation: %v", err)
			}
		})
	}
}

func TestNameAndInterfaceBoundaries(t *testing.T) {
	cases := map[string][]net.Interface{
		"duplicate-index":            {{Index: 1, Name: "a"}, {Index: 1, Name: "b"}},
		"duplicate-name":             {{Index: 1, Name: "a"}, {Index: 2, Name: "a"}},
		"zero-index":                 {{Index: 0, Name: "a"}},
		"negative-mtu":               {{Index: 1, Name: "a", MTU: -1}},
		"oversized-hardware-address": {{Index: 1, Name: "a", HardwareAddr: make(net.HardwareAddr, 65)}},
	}
	for _, name := range []string{"", ".", "..", "../test", "a/b", "a\\b", "a\x00b", "a\nb", "a\u202eb", "a\u2028b", "\xff", strings.Repeat("x", MaxNameBytes+1)} {
		cases["name-"+name] = []net.Interface{{Index: 1, Name: name}}
	}
	for name, ifaces := range cases {
		t.Run(name, func(t *testing.T) {
			r := fixtureReader()
			r.interfaces = func() ([]net.Interface, error) { return ifaces, nil }
			snapshot, err := r.discover(context.Background())
			assertEmpty(t, snapshot, err, ErrObservation)
		})
	}
}

func TestLimitsNeverReturnPartialSnapshot(t *testing.T) {
	for _, mode := range []string{"interfaces", "addresses"} {
		t.Run(mode, func(t *testing.T) {
			r := fixtureReader()
			if mode == "interfaces" {
				r.interfaces = func() ([]net.Interface, error) { return make([]net.Interface, MaxInterfaces+1), nil }
			} else {
				r.addresses = func(net.Interface) ([]net.Addr, error) { return make([]net.Addr, MaxAddresses+1), nil }
			}
			snapshot, err := r.discover(context.Background())
			assertEmpty(t, snapshot, err, ErrLimit)
		})
	}
}

func TestReadErrorsNeverReturnPartialSnapshot(t *testing.T) {
	for _, mode := range []string{"interfaces", "addresses"} {
		t.Run(mode, func(t *testing.T) {
			r := fixtureReader()
			if mode == "interfaces" {
				r.interfaces = func() ([]net.Interface, error) { return nil, errors.New("private detail") }
			} else {
				r.addresses = func(net.Interface) ([]net.Addr, error) { return nil, errors.New("private detail") }
			}
			snapshot, err := r.discover(context.Background())
			assertEmpty(t, snapshot, err, ErrUnavailable)
		})
	}
}

func TestCancellationBeforeAndBetweenOSCalls(t *testing.T) {
	for _, where := range []string{"before", "interfaces", "addresses", "kind"} {
		t.Run(where, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := fixtureReader()
			interfaces, addresses, kind := r.interfaces, r.addresses, r.kind
			r.interfaces = func() ([]net.Interface, error) {
				if where == "before" {
					t.Fatal("read after cancellation")
				}
				if where == "interfaces" {
					cancel()
				}
				return interfaces()
			}
			r.addresses = func(iface net.Interface) ([]net.Addr, error) {
				if where == "addresses" {
					cancel()
				}
				return addresses(iface)
			}
			r.kind = func(name string) Kind {
				if where == "kind" {
					cancel()
				}
				return kind(name)
			}
			if where == "before" {
				cancel()
			}
			snapshot, err := r.discover(ctx)
			assertEmpty(t, snapshot, err, context.Canceled)
		})
	}
}

func TestObservableChangesRefused(t *testing.T) {
	for _, field := range []string{"flags", "addresses", "kind"} {
		t.Run(field, func(t *testing.T) {
			r := fixtureReader()
			interfaces, addresses := r.interfaces, r.addresses
			calls := 0
			r.interfaces = func() ([]net.Interface, error) {
				calls++
				ifaces, err := interfaces()
				if field == "flags" && calls == 2 {
					ifaces[0].Flags |= net.FlagRunning
				}
				return ifaces, err
			}
			r.addresses = func(iface net.Interface) ([]net.Addr, error) {
				if field == "addresses" && calls == 2 {
					return nil, nil
				}
				return addresses(iface)
			}
			r.kind = func(string) Kind {
				if field == "kind" && calls == 2 {
					return Virtual
				}
				return Unknown
			}
			snapshot, err := r.discover(context.Background())
			assertEmpty(t, snapshot, err, ErrChanged)
		})
	}
}

func TestConcurrentIndependentReads(t *testing.T) {
	r := fixtureReader()
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if snapshot, err := r.discover(context.Background()); err != nil || len(snapshot.Interfaces) != 1 {
				t.Errorf("concurrent read failed: %+v %v", snapshot, err)
			}
		}()
	}
	wg.Wait()
}

func BenchmarkDiscoverSynthetic(b *testing.B) {
	r := fixtureReader()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.discover(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
