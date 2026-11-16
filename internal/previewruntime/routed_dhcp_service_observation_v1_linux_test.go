//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/AsterG/andeiva/internal/dhcpsockets"
	"github.com/AsterG/andeiva/internal/localobserve"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"golang.org/x/sys/unix"
)

// Explicit model inputs, not an acquired lease, production packet cardinality,
// service-origin proof or authorization to configure the host namespace.
func serviceSocketModelV1() (routedDHCPSocketCaptureV1, RoutedDHCPServiceCgroupIdentityV1, routedDHCPPacketProfileV1, RoutedDHCPOwnerFactV3) {
	c := routedDHCPSocketCaptureV1{
		tables:   []localobserve.Socket{{Protocol: "udp", Family: "ipv4", Address: "198.18.1.10", Port: 68, Inode: 77, UID: 0}},
		udp:      []dhcpsockets.Socket{{Address: netip.MustParseAddr("198.18.1.10"), Port: 68, Inode: 77, Cookie: 88, UID: 0, CreationCgroup: 99}},
		packet:   []dhcpsockets.PacketSocket{{Interface: 7, Type: unix.SOCK_RAW, Protocol: unix.ETH_P_ALL, Inode: 78, Cookie: 89, UID: 0, Flags: 3}},
		wanIndex: 7, addressOnWAN: true,
	}
	return c, RoutedDHCPServiceCgroupIdentityV1{Device: 3, Inode: 99}, qualifiedRoutedDHCPPacketProfileV1(), RoutedDHCPOwnerFactV3{Epoch: 1, Fact: networkexecutor.LeaseFact{Address: "198.18.1.10/24"}}
}

func TestRoutedDHCPServiceObservationExactAcquisitionOnly(t *testing.T) {
	c, id, p, f := serviceSocketModelV1()
	if err := matchRoutedDHCPSocketsV1(c, id, p, f, false); err != nil {
		t.Fatal(err)
	}
	// Kernel ifindex zero is acceptable only with an exact physically observed
	// WAN address. It must never be presented as bind-to-device evidence.
	c.udp[0].Interface = 7
	if err := matchRoutedDHCPSocketsV1(c, id, p, f, false); err != nil {
		t.Fatal(err)
	}
	if err := matchRoutedDHCPSocketsV1(c, id, p, f, true); err == nil {
		t.Fatal("UDP permitted before a lease")
	}
	c.tables = nil
	c.udp = nil
	if err := matchRoutedDHCPSocketsV1(c, id, p, RoutedDHCPOwnerFactV3{}, true); err != nil {
		t.Fatal("typed initial waiting raw inventory rejected", err)
	}
	if err := matchRoutedDHCPSocketsV1(c, id, routedDHCPPacketProfileV1{}, f, true); err == nil {
		t.Fatal("unqualified packet profile defaulted to allow")
	}
	c, id, p, f = serviceSocketModelV1()
	second := c.packet[0]
	second.Inode++
	second.Cookie++
	c.packet = append(c.packet, second)
	if matchRoutedDHCPSocketsV1(c, id, p, f, false) != nil {
		t.Fatal("bounded RAW/UDP transition rejected")
	}
	c.tables = nil
	c.udp = nil
	if matchRoutedDHCPSocketsV1(c, id, p, f, false) != nil {
		t.Fatal("BOUND before address application rejected")
	}
	c.packet = nil
	if matchRoutedDHCPSocketsV1(c, id, p, f, false) == nil {
		t.Fatal("leased phase without raw inventory accepted")
	}
	if matchRoutedDHCPSocketsV1(c, id, p, RoutedDHCPOwnerFactV3{}, true) != nil {
		t.Fatal("initial waiting before socket creation rejected")
	}
}

func TestRoutedDHCPServiceObservationRejectsForeignAndExtra(t *testing.T) {
	changes := map[string]func(*routedDHCPSocketCaptureV1){
		"foreign-cgroup":   func(c *routedDHCPSocketCaptureV1) { c.udp[0].CreationCgroup++ },
		"foreign-root-UDP": func(c *routedDHCPSocketCaptureV1) { c.udp[0].CreationCgroup = 1234 },
		"zero-cookie":      func(c *routedDHCPSocketCaptureV1) { c.udp[0].Cookie = 0 },
		"no-cookie":        func(c *routedDHCPSocketCaptureV1) { c.udp[0].Cookie = ^uint64(0) },
		"wrong-inode":      func(c *routedDHCPSocketCaptureV1) { c.udp[0].Inode++ },
		"wrong-UID":        func(c *routedDHCPSocketCaptureV1) { c.udp[0].UID = 100 },
		"table-UID":        func(c *routedDHCPSocketCaptureV1) { c.tables[0].UID = 100 },
		"wildcard": func(c *routedDHCPSocketCaptureV1) {
			c.udp[0].Address = netip.IPv4Unspecified()
			c.tables[0].Address = "0.0.0.0"
			c.tables[0].Wildcard = true
		},
		"wrong-port":          func(c *routedDHCPSocketCaptureV1) { c.udp[0].Port = 67; c.tables[0].Port = 67 },
		"no-physical-address": func(c *routedDHCPSocketCaptureV1) { c.addressOnWAN = false },
		"UDP-LAN":             func(c *routedDHCPSocketCaptureV1) { c.udp[0].Interface = 8 },
		"extra-TCP": func(c *routedDHCPSocketCaptureV1) {
			c.tables = append(c.tables, localobserve.Socket{Protocol: "tcp", Family: "ipv4", Port: 443, Inode: 79})
		},
		"extra-v6": func(c *routedDHCPSocketCaptureV1) {
			c.tables = append(c.tables, localobserve.Socket{Protocol: "udp", Family: "ipv6", Port: 68, Inode: 79})
		},
		"missing-table-row": func(c *routedDHCPSocketCaptureV1) { c.tables = nil },
		"missing-diag-row":  func(c *routedDHCPSocketCaptureV1) { c.udp = nil },
		"packet-unbound":    func(c *routedDHCPSocketCaptureV1) { c.packet[0].Interface = 0 },
		"packet-LAN":        func(c *routedDHCPSocketCaptureV1) { c.packet[0].Interface = 8 },
		"packet-type":       func(c *routedDHCPSocketCaptureV1) { c.packet[0].Type = unix.SOCK_DGRAM },
		"packet-protocol":   func(c *routedDHCPSocketCaptureV1) { c.packet[0].Protocol = unix.ETH_P_IPV6 },
		"packet-UID":        func(c *routedDHCPSocketCaptureV1) { c.packet[0].UID = 100 },
		"packet-flags":      func(c *routedDHCPSocketCaptureV1) { c.packet[0].Flags ^= 1 },
		"packet-extra":      func(c *routedDHCPSocketCaptureV1) { c.packet = append(c.packet, c.packet[0]) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			c, id, p, f := serviceSocketModelV1()
			change(&c)
			if matchRoutedDHCPSocketsV1(c, id, p, f, false) == nil {
				t.Fatal("unrelated resource accepted")
			}
		})
	}
}

func TestRoutedDHCPServiceObservationRejectsOldCookieAndUnstableCapture(t *testing.T) {
	for _, change := range []func(*routedDHCPSocketCaptureV1){
		func(c *routedDHCPSocketCaptureV1) { c.udp[0].Cookie++ },
		func(c *routedDHCPSocketCaptureV1) { c.packet[0].Cookie++ },
		func(c *routedDHCPSocketCaptureV1) { c.wanIndex++ },
	} {
		a, _, _, _ := serviceSocketModelV1()
		b, _, _, _ := serviceSocketModelV1()
		change(&b)
		if sameRoutedDHCPSocketsV1(a, b) {
			t.Fatal("unstable observation accepted")
		}
	}
	a, _, _, _ := serviceSocketModelV1()
	b, _, _, _ := serviceSocketModelV1()
	b.packet = nil
	if !sameRoutedDHCPSocketsV1(a, b) {
		t.Fatal("sequential captures pretended to require atomic socket presence")
	}
}

func TestRoutedDHCPServiceObservationFactBoundary(t *testing.T) {
	b, _ := routedDeferredFixtureV4(t)
	wan := b.Desired.Config.Interfaces[0].Binding
	f := RoutedDHCPOwnerFactV3{Epoch: 1, Fact: networkexecutor.LeaseFact{Owner: b.Owner, Sequence: 1, DesiredHash: b.Desired.Hash, WAN: wan, Address: "198.18.1.10/24", DeadlineBootNS: 200}}
	if !validRoutedDHCPServiceFactV1(f, b, wan, 100) {
		t.Fatal("valid model fact rejected")
	}
	for _, change := range []func(*RoutedDHCPOwnerFactV3){
		func(x *RoutedDHCPOwnerFactV3) { x.Epoch = 0 }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.Sequence = 0 }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.Revoked = true },
		func(x *RoutedDHCPOwnerFactV3) { x.Fact.Owner.PID++ }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.Owner.StartTicks++ }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.Owner.Namespace++ },
		func(x *RoutedDHCPOwnerFactV3) { x.Fact.Owner.Incarnation = "foreign" }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.DesiredHash = "foreign" }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.WAN.Name = "foreign" },
		func(x *RoutedDHCPOwnerFactV3) { x.Fact.DeadlineBootNS = 100 }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.Address = "0.0.0.0/0" }, func(x *RoutedDHCPOwnerFactV3) { x.Fact.Address = "::1/128" },
	} {
		x := f
		change(&x)
		if validRoutedDHCPServiceFactV1(x, b, wan, 100) {
			t.Fatal("invalid/expired/foreign fact accepted")
		}
	}
}

func TestRoutedDHCPServiceReleaseRetainsPinsUntilDrainedAndEmpty(t *testing.T) {
	for _, kind := range []string{"success", "live", "identity", "late-identity", "tcp", "udp", "packet", "capture-error", "cancel-before", "cancel-after-capture", "close-error"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel-before" {
				cancel()
			}
			checks, captures, closed := 0, 0, 0
			failure := errors.New("injected I/O failure")
			err := releaseRoutedDHCPSocketPinsV1(ctx, func() error {
				checks++
				if kind == "identity" || kind == "late-identity" && checks == 4 {
					return failure
				}
				return nil
			}, func() bool { return kind != "live" }, func() (routedDHCPSocketCaptureV1, error) {
				captures++
				var c routedDHCPSocketCaptureV1
				switch kind {
				case "tcp":
					c.tables = []localobserve.Socket{{Protocol: "tcp", Inode: 1}}
				case "udp":
					c.udp = []dhcpsockets.Socket{{Inode: 1}}
				case "packet":
					c.packet = []dhcpsockets.PacketSocket{{Inode: 1}}
				case "capture-error":
					return c, failure
				case "cancel-after-capture":
					if captures == 2 {
						cancel()
					}
				}
				return c, nil
			}, func() error {
				closed++
				if kind == "close-error" {
					return failure
				}
				return nil
			})
			if kind == "success" {
				if err != nil || captures != 2 || closed != 1 {
					t.Fatal("missing physical absence boundary", captures, closed, err)
				}
			} else {
				if err == nil {
					t.Fatal("uncertainty accepted")
				}
				if kind != "close-error" && closed != 0 {
					t.Fatal("pins released before complete physical absence")
				}
			}
		})
	}
}

func TestRoutedDHCPServiceObservationRejectsUntrustedOrClosedPins(t *testing.T) {
	if _, e := newRoutedDHCPServiceObservationV1(context.Background(), nil, RoutedDHCPServiceCgroupIdentityV1{}, RoutedDHCPDeferredBindingV4{}, nil, routedDHCPPacketProfileV1{}); e == nil {
		t.Fatal("missing source accepted")
	}
	f, e := os.Open("/sys/fs/cgroup")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	id, e := routedDHCPServiceDirectoryV1(f)
	if e != nil {
		t.Fatal(e)
	}
	s := &routedDHCPServiceObservationV1{pin: f, identity: id}
	if s.validate(context.Background(), true) == nil {
		t.Fatal("cgroupfs alone became live authority")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.validate(ctx, false) == nil {
		t.Fatal("cancelled scope accepted")
	}
	if s.producerExited() {
		t.Fatal("missing producer pin counted as drained")
	}
	fd, e := unix.PidfdOpen(os.Getpid(), 0)
	if e != nil {
		t.Fatal(e)
	}
	s.producer = os.NewFile(uintptr(fd), "test-current-producer")
	if s.producerExited() {
		t.Fatal("live producer counted as drained")
	}
	_ = s.producer.Close()
	if s.producerExited() {
		t.Fatal("closed producer pin counted as drained")
	}
}
