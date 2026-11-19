//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"slices"
	"testing"
)

func selectedDHCPServerLinksFixtureV1(t *testing.T) (routedDHCPServerBindingPlanV1, []routedDHCPServerObservedLinkV1) {
	t.Helper()
	selected := selectedDHCPServerBindingFixtureV1(t)
	plan, err := routedDHCPServerBindingPlanFromSelectedV1(selected, selected.Identity, selected.Work)
	if err != nil {
		t.Fatal(err)
	}
	address := func(local, name, scope string, bits int) routedDHCPServerObservedAddressV1 {
		return routedDHCPServerObservedAddressV1{
			Family: "inet", Local: local, Bits: &bits, Scope: scope, Label: name,
			Valid: math.MaxUint32, Preferred: math.MaxUint32,
		}
	}
	return plan, []routedDHCPServerObservedLinkV1{
		{Index: 1, Name: "lo", MAC: "00:00:00:00:00:00", Flags: []string{"LOOPBACK", "UP"}, Addresses: []routedDHCPServerObservedAddressV1{address("127.0.0.1", "lo", "host", 8)}},
		{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", Flags: []string{"UP"}, Addresses: []routedDHCPServerObservedAddressV1{address("198.18.0.1", "lan0", "global", 24)}},
		{Index: 3, Name: "wan0", MAC: "02:00:00:00:02:01", Flags: []string{"UP"}, Addresses: []routedDHCPServerObservedAddressV1{address("198.19.0.1", "wan0", "global", 24)}},
		{Index: 4, Name: "lan2", MAC: "02:00:00:00:01:02", Flags: []string{"UP"}, Addresses: []routedDHCPServerObservedAddressV1{address("198.18.1.1", "lan2", "global", 24)}},
	}
}

func TestRoutedDHCPServerSelectedLinksV1StableOrderWithStaticWAN(t *testing.T) {
	plan, links := selectedDHCPServerLinksFixtureV1(t)
	ipv6Bits := 64
	links[1].Addresses = append(links[1].Addresses, routedDHCPServerObservedAddressV1{
		Family: "inet6", Local: "fe80::1", Bits: &ipv6Bits, Scope: "link", Valid: math.MaxUint32, Preferred: math.MaxUint32,
	})
	read := func() []routedDHCPServerSelectedLinkV1 {
		t.Helper()
		data, err := json.Marshal(links)
		if err != nil {
			t.Fatal(err)
		}
		observed, err := matchRoutedDHCPServerSelectedLinksV1(data, plan)
		if err != nil {
			t.Fatal(err)
		}
		return observed
	}
	want := []routedDHCPServerSelectedLinkV1{
		{Index: 4, Name: "lan2", MAC: "02:00:00:00:01:02", Address: netip.MustParsePrefix("198.18.1.1/24")},
		{Index: 2, Name: "lan0", MAC: "02:00:00:00:01:01", Address: netip.MustParsePrefix("198.18.0.1/24")},
	}
	if got := read(); !slices.Equal(got, want) {
		t.Fatalf("selected LAN identities = %v, want %v", got, want)
	}
	links[2].Addresses[0].Local = "198.19.0.3"
	slices.Reverse(links)
	if got := read(); !slices.Equal(got, want) {
		t.Fatalf("WAN address or link order affected selected LAN identities: %v", got)
	}
	links[0].Index++
	if got := read(); slices.Equal(got, want) {
		t.Fatal("a replacement interface retained the old launch identity")
	}
}

func TestRoutedDHCPServerSelectedLinksV1RejectsMismatchedInventory(t *testing.T) {
	for name, change := range map[string]func([]routedDHCPServerObservedLinkV1){
		"LAN absent":          func(links []routedDHCPServerObservedLinkV1) { links[1].Name = "other" },
		"LAN down":            func(links []routedDHCPServerObservedLinkV1) { links[1].Flags = nil },
		"wrong MAC":           func(links []routedDHCPServerObservedLinkV1) { links[1].MAC = "02:00:00:00:02:04" },
		"wrong prefix":        func(links []routedDHCPServerObservedLinkV1) { *links[1].Addresses[0].Bits = 25 },
		"missing prefix":      func(links []routedDHCPServerObservedLinkV1) { links[1].Addresses[0].Bits = nil },
		"wrong label":         func(links []routedDHCPServerObservedLinkV1) { links[1].Addresses[0].Label = "lan0:1" },
		"wrong scope":         func(links []routedDHCPServerObservedLinkV1) { links[1].Addresses[0].Scope = "link" },
		"temporary IPv4":      func(links []routedDHCPServerObservedLinkV1) { links[1].Addresses[0].Preferred = 5 },
		"selected IPv4 gone":  func(links []routedDHCPServerObservedLinkV1) { links[1].Addresses = nil },
		"duplicate index":     func(links []routedDHCPServerObservedLinkV1) { links[2].Index = links[1].Index },
		"duplicate name":      func(links []routedDHCPServerObservedLinkV1) { links[2].Name = links[1].Name },
		"duplicate MAC":       func(links []routedDHCPServerObservedLinkV1) { links[2].MAC = links[1].MAC },
		"duplicate IP on WAN": func(links []routedDHCPServerObservedLinkV1) { links[2].Addresses[0].Local = "198.18.0.1" },
		"same IP wrong family": func(links []routedDHCPServerObservedLinkV1) {
			links[2].Addresses[0].Local, links[2].Addresses[0].Family = "198.18.0.1", "inet6"
		},
		"extra IPv4 on LAN": func(links []routedDHCPServerObservedLinkV1) {
			alias := links[1].Addresses[0]
			alias.Local = "198.18.0.2"
			links[1].Addresses = append(links[1].Addresses, alias)
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan, links := selectedDHCPServerLinksFixtureV1(t)
			change(links)
			data, err := json.Marshal(links)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := matchRoutedDHCPServerSelectedLinksV1(data, plan); got != nil || !errors.Is(err, ErrIdentity) {
				t.Fatalf("mismatched inventory passed: %v, %v", got, err)
			}
		})
	}
}

func TestRoutedDHCPServerSelectedLinksV1RejectsUnavailablePins(t *testing.T) {
	plan, _ := selectedDHCPServerLinksFixtureV1(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := readRoutedDHCPServerSelectedLinksV1(ctx, Metadata{}, nil, nil, plan); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cancelled read passed: %v, %v", got, err)
	}
	if got, err := readRoutedDHCPServerSelectedLinksV1(context.Background(), Metadata{}, nil, nil, plan); got != nil || !errors.Is(err, ErrIdentity) {
		t.Fatalf("unpinned read passed: %v, %v", got, err)
	}
}
