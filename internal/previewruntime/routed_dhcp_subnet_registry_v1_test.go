package previewruntime

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

func subnetBindingFixtureV1() RoutedDHCPSubnetBindingV1 {
	return RoutedDHCPSubnetBindingV1{"office", "lan", "02:00:00:00:00:01", "192.0.2.0/24"}
}

func TestDHCPSubnetRegistryV1StableOperationalIdentity(t *testing.T) {
	a := subnetBindingFixtureV1()
	b := a
	b.ScopeID = "branch"
	empty := routedDHCPSubnetRegistryV1{Version: 1, Entries: []routedDHCPSubnetEntryV1{}}
	r, ids, changed, e := allocateDHCPSubnetRegistryV1(empty, []RoutedDHCPSubnetBindingV1{a, b})
	if e != nil || !changed || !reflect.DeepEqual(ids, []uint32{2, 1}) {
		t.Fatal(ids, e)
	}
	other, _, _, e := allocateDHCPSubnetRegistryV1(empty, []RoutedDHCPSubnetBindingV1{b, a})
	if e != nil || !reflect.DeepEqual(r, other) {
		t.Fatal("input order changed allocation")
	}
	for _, keys := range [][]RoutedDHCPSubnetBindingV1{nil, {a}, {b, a}, {a, a}} {
		next, _, changed, e := allocateDHCPSubnetRegistryV1(r, keys)
		if e != nil || changed || !reflect.DeepEqual(r, next) {
			t.Fatal("disable/re-enable removed or reassigned mapping", e)
		}
	}
	for _, mutate := range []func(*RoutedDHCPSubnetBindingV1){func(b *RoutedDHCPSubnetBindingV1) { b.Subnet = "198.51.100.0/24" }, func(b *RoutedDHCPSubnetBindingV1) { b.InterfaceID = "lan2" }, func(b *RoutedDHCPSubnetBindingV1) { b.HardwareMAC = "02:00:00:00:00:02" }} {
		b := a
		mutate(&b)
		next, ids, changed, e := allocateDHCPSubnetRegistryV1(r, []RoutedDHCPSubnetBindingV1{b})
		if e != nil || !changed || ids[0] != 3 || len(next.Entries) != 3 {
			t.Fatal("new physical identity reused ID", e)
		}
	}
	// Pools, ports, router options and lease times are deliberately absent
	// from the immutable key; changing them cannot alter this lookup.
}

func TestDHCPSubnetRegistryV1StrictDecodeAndQuota(t *testing.T) {
	b := subnetBindingFixtureV1()
	r := routedDHCPSubnetRegistryV1{Version: 1, HighWater: 1, Entries: []routedDHCPSubnetEntryV1{{b, 1}}}
	raw, _ := json.Marshal(r)
	for _, bad := range [][]byte{nil, []byte(`{"version":1,"version":1,"entries":[]}`), []byte(`{"version":1,"high_water":0,"entries":[],"extra":1}`), append(append([]byte{}, raw...), raw...), []byte(strings.Repeat(" ", routedDHCPSubnetRegistryBytesV1+1))} {
		if _, e := decodeDHCPSubnetRegistryV1(bad); e == nil {
			t.Fatal("invalid registry accepted")
		}
	}
	for _, mutate := range []func(*routedDHCPSubnetRegistryV1){func(r *routedDHCPSubnetRegistryV1) { r.Version = 2 }, func(r *routedDHCPSubnetRegistryV1) { r.HighWater = 0 }, func(r *routedDHCPSubnetRegistryV1) { r.Entries[0].ID = 0 }, func(r *routedDHCPSubnetRegistryV1) { r.Entries[0].Binding.Subnet = "192.0.2.1/24" }, func(r *routedDHCPSubnetRegistryV1) { r.Entries[0].Binding.HardwareMAC = "ff:ff:ff:ff:ff:ff" }, func(r *routedDHCPSubnetRegistryV1) { r.Entries = append(r.Entries, r.Entries[0]) }} {
		var next routedDHCPSubnetRegistryV1
		_ = json.Unmarshal(raw, &next)
		mutate(&next)
		bad, _ := json.Marshal(next)
		if _, e := decodeDHCPSubnetRegistryV1(bad); e == nil {
			t.Fatal("invalid mapping accepted")
		}
	}
	r.Entries = nil
	for i := 1; i <= routedDHCPSubnetRegistryEntriesV1; i++ {
		b := b
		b.ScopeID = fmt.Sprintf("s-%d", i)
		r.Entries = append(r.Entries, routedDHCPSubnetEntryV1{b, uint32(i)})
	}
	r.HighWater = routedDHCPSubnetRegistryEntriesV1
	if _, ids, changed, e := allocateDHCPSubnetRegistryV1(r, []RoutedDHCPSubnetBindingV1{r.Entries[0].Binding}); e != nil || changed || ids[0] != 1 {
		t.Fatal("full registry lost existing lookup", e)
	}
	if _, ids, _, e := allocateDHCPSubnetRegistryV1(r, []RoutedDHCPSubnetBindingV1{b}); !errors.Is(e, ErrRoutedDHCPSubnetRegistryFullV1) || ids != nil {
		t.Fatal("entry bound ignored")
	}
	r.Entries = []routedDHCPSubnetEntryV1{{b, math.MaxUint32}}
	r.HighWater = math.MaxUint32
	newKey := b
	newKey.ScopeID = "new"
	if _, _, _, e := allocateDHCPSubnetRegistryV1(r, []RoutedDHCPSubnetBindingV1{newKey}); !errors.Is(e, ErrRoutedDHCPSubnetRegistryFullV1) {
		t.Fatal("uint32 ID wrapped")
	}
}
