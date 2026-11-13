package previewruntime

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpclient"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
)

func routedOwnerFixtureV3(t testing.TB) (RoutedDHCPOwnerBindingV3, routedDHCPOwnerLeaseV3) {
	t.Helper()
	n, err := networkplan.Canonical(networkplan.Config{SchemaVersion: 1, IPv6Forwarding: "deny", Interfaces: []networkplan.Interface{
		{ID: "lan", Role: networkplan.LAN, Zone: "inside", Binding: networkplan.Binding{Name: "lan0", HardwareAddress: "02:00:00:00:01:01"}, IPv4: networkplan.IPv4{Mode: "static", Address: "198.18.0.1/24"}},
		{ID: "wan", Role: networkplan.WAN, Zone: "outside", Binding: networkplan.Binding{Name: "wan0", HardwareAddress: "02:00:00:00:02:01"}, IPv4: networkplan.IPv4{Mode: "dhcp"}},
	}, Zones: []networkplan.Zone{{ID: "inside", Kind: networkplan.LAN}, {ID: "outside", Kind: networkplan.WAN}}, DefaultRoute: networkplan.DefaultRoute{InterfaceID: "wan", Metric: 10}, DNS: networkplan.DNS{Mode: "none", Servers: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	b := RoutedDHCPOwnerBindingV3{Version: 3, RolePID: 40, RoleStartTicks: 123, MountNamespace: 300, HostMountNamespace: 100, Desired: n, Owner: networkexecutor.LeaseOwner{Namespace: 200, BootID: "12345678-1234-1234-1234-123456789abc", RunID: strings.Repeat("a", 32), Incarnation: strings.Repeat("b", 32), PID: 50, StartTicks: 124}}
	l := routedDHCPOwnerLeaseV3{Event: dhcpclient.Event{Version: 1, Interface: "wan0", Reason: "BOUND", PID: 50, BootNS: int64(10 * time.Second), Address: "198.19.0.10/24", Gateway: "198.19.0.1", Server: "198.19.0.1", DNS: []string{"198.19.0.1"}, Seconds: 120}, Epoch: 1, DeadlineBootNS: int64(125 * time.Second)}
	return b, l
}

func TestRoutedDHCPOwnerV3SameLeaseNeverExtendsOrChangesIdentity(t *testing.T) {
	b, l := routedOwnerFixtureV3(t)
	s := routedDHCPOwnerFactsV3{binding: b}
	first, err := s.accept(l, int64(11*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Duration{12 * time.Second, 40 * time.Second, 124 * time.Second} {
		again, err := s.accept(l, int64(now))
		if err != nil || again != first {
			t.Fatal("poll extended or changed grant", err)
		}
	}
	if _, err = s.accept(l, l.DeadlineBootNS); err == nil || s.active {
		t.Fatal("expired grant remained available")
	}
	if _, err = s.accept(l, int64(11*time.Second)); err == nil {
		t.Fatal("clock rollback revived expired epoch")
	}
	l.Epoch++
	l.Event.BootNS = int64(130 * time.Second)
	l.Event.Reason = "RENEW"
	l.DeadlineBootNS = int64(240 * time.Second)
	next, err := s.accept(l, int64(131*time.Second))
	if err != nil || next.Epoch == first.Epoch || next.Fact.Sequence <= first.Fact.Sequence || next.Fact.DeadlineBootNS != l.DeadlineBootNS {
		t.Fatal("fresh confirmed epoch rejected", err)
	}
}

func TestRoutedDHCPOwnerV3RejectsMalformedReplayAndRevivedGrants(t *testing.T) {
	for name, change := range map[string]func(*routedDHCPOwnerLeaseV3){
		"cached-timeout":    func(l *routedDHCPOwnerLeaseV3) { l.Event.Reason = "TIMEOUT" },
		"foreign-pid":       func(l *routedDHCPOwnerLeaseV3) { l.Event.PID++ },
		"foreign-interface": func(l *routedDHCPOwnerLeaseV3) { l.Event.Interface = "lan0" },
		"zero-epoch":        func(l *routedDHCPOwnerLeaseV3) { l.Epoch = 0 },
		"future-hook":       func(l *routedDHCPOwnerLeaseV3) { l.Event.BootNS = int64(12 * time.Second) },
		"extended-deadline": func(l *routedDHCPOwnerLeaseV3) { l.DeadlineBootNS = l.Event.BootNS + int64(121*time.Second) },
		"foreign-gateway":   func(l *routedDHCPOwnerLeaseV3) { l.Event.Gateway = "203.0.113.1" },
		"broadcast":         func(l *routedDHCPOwnerLeaseV3) { l.Event.Address = "198.19.0.255/24" },
		"zero-server":       func(l *routedDHCPOwnerLeaseV3) { l.Event.Server = "0.0.0.0" },
		"invalid-dns":       func(l *routedDHCPOwnerLeaseV3) { l.Event.DNS = []string{"127.0.0.1"} },
	} {
		t.Run(name, func(t *testing.T) {
			b, l := routedOwnerFixtureV3(t)
			change(&l)
			s := routedDHCPOwnerFactsV3{binding: b}
			if _, err := s.accept(l, int64(11*time.Second)); err == nil {
				t.Fatal("invalid grant accepted")
			}
		})
	}
	b, l := routedOwnerFixtureV3(t)
	s := routedDHCPOwnerFactsV3{binding: b}
	if _, err := s.accept(l, int64(11*time.Second)); err != nil {
		t.Fatal(err)
	}
	changed := l
	changed.DeadlineBootNS--
	if _, err := s.accept(changed, int64(12*time.Second)); err == nil {
		t.Fatal("same epoch changed contents")
	}
	_ = s.revoke()
	if _, err := s.accept(l, int64(12*time.Second)); err == nil {
		t.Fatal("unavailable epoch resurrected")
	}
	s.sequence = math.MaxUint64
	l.Epoch++
	l.Event.BootNS++
	if _, err := s.accept(l, int64(12*time.Second)); err == nil {
		t.Fatal("sequence wrapped")
	}
}

func TestRoutedDHCPOwnerV3StrictFramesAndBindings(t *testing.T) {
	for _, raw := range []string{`{"version":3,"version":3}`, `{"unknown":true}`, `{} {}`, strings.Repeat(" ", routedDHCPOwnerFrameV3+1), `{"sequence":18446744073709551616}`, `{"sequence":-1}`} {
		var q routedDHCPOwnerRequestV3
		if routedDHCPOwnerDecodeV3([]byte(raw), &q) == nil {
			t.Fatal("invalid bounded frame accepted")
		}
	}
	b, _ := routedOwnerFixtureV3(t)
	for _, mutate := range []func(*RoutedDHCPOwnerBindingV3){func(x *RoutedDHCPOwnerBindingV3) { x.MountNamespace = x.HostMountNamespace }, func(x *RoutedDHCPOwnerBindingV3) { x.Owner.StartTicks = 0 }, func(x *RoutedDHCPOwnerBindingV3) { x.Owner.PID = uint32(x.RolePID) }, func(x *RoutedDHCPOwnerBindingV3) { x.Desired.Hash = strings.Repeat("f", 64) }, func(x *RoutedDHCPOwnerBindingV3) { x.Owner.Incarnation = "caller" }} {
		x := b
		mutate(&x)
		if routedDHCPOwnerBindingValidV3(x) {
			t.Fatal("unbound owner accepted")
		}
	}
	detached, err := jsonOwnerBindingV3(b)
	if err != nil {
		t.Fatal(err)
	}
	detached.Desired.Config.Interfaces[0].Binding.Name = "foreign"
	if b.Desired.Config.Interfaces[0].Binding.Name == "foreign" {
		t.Fatal("binding aliases caller")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RoutedDHCPOwnerBindingV3
	if routedDHCPOwnerDecodeV3(raw, &decoded) != nil || !routedDHCPOwnerBindingValidV3(decoded) {
		t.Fatal("valid binding rejected")
	}
}
