//go:build linux

package previewruntime

import (
	"os"
	"strings"
	"testing"
)

func TestRoutedDHCPServerExactCgroupSetV1(t *testing.T) {
	parent := RoutedDHCPServiceCgroupIdentityV1{Device: 1, Inode: 2}
	wan := RoutedDHCPServerCgroupPinV1{Role: "wan", Name: "dhcp-" + strings.Repeat("a", 32), Identity: RoutedDHCPServiceCgroupIdentityV1{Device: 1, Inode: 3}}
	lan := RoutedDHCPServerCgroupPinV1{Role: "lan", Name: "dhcp-server-" + strings.Repeat("b", 32), Identity: RoutedDHCPServiceCgroupIdentityV1{Device: 1, Inode: 4}}
	for _, count := range []int{0, 1, 2} {
		pins := []RoutedDHCPServerCgroupPinV1{wan, lan}[:count]
		var names []string
		for _, pin := range pins {
			names = append(names, pin.Name)
		}
		if err := routedDHCPServerExactChildrenV1(names, pins, parent, func(name string) (RoutedDHCPServiceCgroupIdentityV1, error) {
			for _, pin := range pins {
				if pin.Name == name {
					return pin.Identity, nil
				}
			}
			return RoutedDHCPServiceCgroupIdentityV1{}, ErrIdentity
		}); err != nil {
			t.Fatal("exact set rejected", count, err)
		}
	}
	for _, change := range []string{"unknown", "missing", "same prefix", "duplicate", "replaced inode", "foreign device", "same inode", "same role", "parent as leaf", "bad role", "lookup error"} {
		t.Run(change, func(t *testing.T) {
			pins := []RoutedDHCPServerCgroupPinV1{wan, lan}
			names := []string{wan.Name, lan.Name}
			observed := map[string]RoutedDHCPServiceCgroupIdentityV1{wan.Name: wan.Identity, lan.Name: lan.Identity}
			switch change {
			case "unknown":
				names = append(names, "foreign")
			case "missing":
				names = names[:1]
			case "same prefix":
				names[1] += "-old"
			case "duplicate":
				names[1] = names[0]
			case "replaced inode":
				observed[lan.Name] = RoutedDHCPServiceCgroupIdentityV1{Device: 1, Inode: 5}
			case "foreign device":
				pins[1].Identity.Device = 2
			case "same inode":
				pins[1].Identity = wan.Identity
			case "same role":
				pins[1].Role = "wan"
			case "parent as leaf":
				pins[1].Identity = parent
			case "bad role":
				pins[1].Role = "arbitrary"
			}
			err := routedDHCPServerExactChildrenV1(names, pins, parent, func(name string) (RoutedDHCPServiceCgroupIdentityV1, error) {
				if change == "lookup error" {
					return RoutedDHCPServiceCgroupIdentityV1{}, ErrIdentity
				}
				return observed[name], nil
			})
			if err == nil {
				t.Fatal("ambiguous/unowned child accepted")
			}
		})
	}
}

func TestRoutedDHCPServerCgroupRejectsUnpinnedAndNonCgroupV1(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if validateRoutedDHCPServerCgroupPinsV1(nil, nil) == nil || validateRoutedDHCPServerCgroupPinsV1(file, nil) == nil {
		t.Fatal("ordinary file accepted as cgroup parent")
	}
	for _, role := range []string{"wan", "lan"} {
		for _, incarnation := range []string{"", "../escape", strings.Repeat("A", 32), strings.Repeat("b", 31)} {
			if _, err := routedDHCPServerCgroupNameV1(role, incarnation); err == nil {
				t.Fatal("noncanonical incarnation")
			}
		}
	}
}
