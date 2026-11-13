package previewruntime

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/networkplan"
)

func routedDeferredFixtureV4(t testing.TB) (RoutedDHCPDeferredBindingV4, routedDHCPOwnerLeaseV3) {
	b, l := routedOwnerFixtureV3(t)
	b.Owner.PID = uint32(b.RolePID)
	b.Owner.StartTicks = b.RoleStartTicks
	return RoutedDHCPDeferredBindingV4{Version: 4, MountNamespace: b.MountNamespace, HostMountNamespace: b.HostMountNamespace, Owner: b.Owner, Desired: b.Desired}, l
}
func TestRoutedDHCPDeferredV4BindingRejectsCrossProfileAndNonDHCP(t *testing.T) {
	b, _ := routedDeferredFixtureV4(t)
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var v4 RoutedDHCPDeferredBindingV4
	if routedDHCPOwnerDecodeV3(raw, &v4) != nil || v4.Owner != b.Owner {
		t.Fatal("v4 roundtrip failed")
	}
	var v3 RoutedDHCPOwnerBindingV3
	if routedDHCPOwnerDecodeV3(raw, &v3) == nil {
		t.Fatal("v4 accepted as v3")
	}
	old, _ := routedOwnerFixtureV3(t)
	raw, err = json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if routedDHCPOwnerDecodeV3(raw, &v4) == nil {
		t.Fatal("v3 accepted as v4")
	}
	for _, change := range []func(*RoutedDHCPDeferredBindingV4){
		func(x *RoutedDHCPDeferredBindingV4) { x.Version = 3 }, func(x *RoutedDHCPDeferredBindingV4) { x.Owner.StartTicks = 0 }, func(x *RoutedDHCPDeferredBindingV4) { x.Owner.Incarnation = "caller" }, func(x *RoutedDHCPDeferredBindingV4) { x.MountNamespace = x.HostMountNamespace }, func(x *RoutedDHCPDeferredBindingV4) { x.Desired.Hash = strings.Repeat("a", 64) },
	} {
		x, _ := cloneRoutedDHCPDeferredBindingV4(b)
		change(&x)
		if routedDHCPDeferredBindingValidV4(x) {
			t.Fatal("invalid binding accepted")
		}
	}
	x, _ := cloneRoutedDHCPDeferredBindingV4(b)
	for i := range x.Desired.Config.Interfaces {
		if x.Desired.Config.Interfaces[i].Role == networkplan.WAN {
			x.Desired.Config.Interfaces[i].IPv4 = networkplan.IPv4{Mode: "static", Address: "198.19.0.10/24", Gateway: "198.19.0.1"}
		}
	}
	x.Desired, err = networkplan.Canonical(x.Desired.Config)
	if err != nil {
		t.Fatal(err)
	}
	if routedDHCPDeferredBindingValidV4(x) {
		t.Fatal("static plan created DHCP authority")
	}
	x.Desired = networkplan.Revision{}
	if routedDHCPDeferredBindingValidV4(x) {
		t.Fatal("empty plan created DHCP authority")
	}
}

func TestRoutedDHCPDeferredV4ProducerAndAcquisitionAreDistinct(t *testing.T) {
	b, l := routedDeferredFixtureV4(t)
	state := routedDHCPOwnerFactsV3{}
	first, err := state.acceptBound(l, int64(11*time.Second), routedDHCPDeferredBindingValidV4(b), b.Owner, b.Desired, l.Event.PID)
	if err != nil || first.Fact.Owner.PID == uint32(l.Event.PID) || first.Fact.Owner != b.Owner {
		t.Fatal("producer provenance replaced by child", err)
	}
	again, err := state.acceptBound(l, int64(12*time.Second), true, b.Owner, b.Desired, l.Event.PID)
	if err != nil || again != first {
		t.Fatal("RPC poll altered lease", err)
	}
	l.Event.PID = int(b.Owner.PID)
	if _, err = state.acceptBound(l, int64(12*time.Second), true, b.Owner, b.Desired, 50); err == nil {
		t.Fatal("producer PID accepted as DHCP event PID")
	}
}
