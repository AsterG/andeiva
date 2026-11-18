//go:build linux

package previewruntime

import (
	"reflect"
	"testing"
)

func TestRoutedDHCPListenerAssociationV4GrantProgress(t *testing.T) {
	before := RoutedDHCPOwnerFactV3{Epoch: 1, Fact: dhcpRuntimeSnapshotV3(t).Fact()}
	after := before
	after.Epoch++
	after.Fact.Sequence++
	after.Fact.DeadlineBootNS++
	zero := routedDHCPServicePhaseV1{}
	if !sameRoutedDHCPListenerAssociationV4(before, zero, before, zero) || !sameRoutedDHCPListenerAssociationV4(before, zero, after, zero) {
		t.Fatal("unchanged association rejected authenticated source progress")
	}
	shorter := after
	shorter.Fact.DeadlineBootNS = before.Fact.DeadlineBootNS - 1
	if !sameRoutedDHCPListenerAssociationV4(before, zero, shorter, zero) {
		t.Fatal("listener comparison required authority extension")
	}
	saved := after
	cases := map[string]func(*RoutedDHCPOwnerFactV3){
		"owner":     func(f *RoutedDHCPOwnerFactV3) { f.Fact.Owner.PID++ },
		"desired":   func(f *RoutedDHCPOwnerFactV3) { f.Fact.DesiredHash += "changed" },
		"wan":       func(f *RoutedDHCPOwnerFactV3) { f.Fact.WAN.Name += "changed" },
		"address":   func(f *RoutedDHCPOwnerFactV3) { f.Fact.Address = "198.18.1.11/24" },
		"gateway":   func(f *RoutedDHCPOwnerFactV3) { f.Fact.Gateway = "198.18.1.2" },
		"revoked":   func(f *RoutedDHCPOwnerFactV3) { f.Fact.Revoked = true },
		"epochOnly": func(f *RoutedDHCPOwnerFactV3) { f.Fact.Sequence = before.Fact.Sequence },
		"seqOnly":   func(f *RoutedDHCPOwnerFactV3) { f.Epoch = before.Epoch },
		"replay":    func(f *RoutedDHCPOwnerFactV3) { f.Epoch = 0 },
		"zeroSeq":   func(f *RoutedDHCPOwnerFactV3) { f.Fact.Sequence = 0 },
		"deadline":  func(f *RoutedDHCPOwnerFactV3) { f.Fact.DeadlineBootNS = 0 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			bad := after
			change(&bad)
			if sameRoutedDHCPListenerAssociationV4(before, zero, bad, zero) {
				t.Fatal("changed association or nonmonotonic source accepted")
			}
		})
	}
	for _, phase := range []routedDHCPServicePhaseV1{{initialWaiting: true}, {noLeaseEpoch: 1}, {marginEpoch: 1}} {
		if !sameRoutedDHCPListenerAssociationV4(before, phase, before, phase) || sameRoutedDHCPListenerAssociationV4(before, phase, after, phase) || sameRoutedDHCPListenerAssociationV4(before, phase, after, zero) || sameRoutedDHCPListenerAssociationV4(before, zero, after, phase) {
			t.Fatal("non-grant phase changed its original exact-match requirement")
		}
	}
	if !reflect.DeepEqual(after, saved) {
		t.Fatal("listener comparison adopted or mutated source authority")
	}
}
