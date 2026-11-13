package localpolicy

import (
	"errors"
	"net/netip"
	"slices"
)

const MaxNeighborInterfaces = 2
const MaxNeighborAddresses = 4

var ErrNeighborInventory = errors.New("local_nft_policy_invalid")

type NeighborLink struct {
	Interface      string   `json:"interface"`
	LocalAddresses []string `json:"local_addresses"`
	PeerAddresses  []string `json:"peer_addresses"`
}

func CanonicalNeighborInventory(c Config, links []NeighborLink) ([]NeighborLink, error) {
	if len(links) > MaxNeighborInterfaces {
		return nil, ErrNeighborInventory
	}
	result := make([]NeighborLink, 0, len(links))
	seen := map[string]bool{}
	for _, link := range links {
		if seen[link.Interface] || len(link.LocalAddresses) == 0 || len(link.LocalAddresses) > MaxNeighborAddresses || len(link.PeerAddresses) == 0 || len(link.PeerAddresses) > MaxNeighborAddresses {
			return nil, ErrNeighborInventory
		}
		seen[link.Interface] = true
		var inventory []string
		for _, i := range c.Interfaces {
			if i.Name == link.Interface {
				inventory = i.Addresses
			}
		}
		if inventory == nil {
			return nil, ErrNeighborInventory
		}
		local, err := CanonicalNeighborAddresses(link.LocalAddresses)
		if err != nil {
			return nil, err
		}
		peers, err := CanonicalNeighborAddresses(link.PeerAddresses)
		if err != nil {
			return nil, err
		}
		for _, a := range local {
			if !slices.Contains(inventory, a) || slices.Contains(peers, a) {
				return nil, ErrNeighborInventory
			}
		}
		result = append(result, NeighborLink{link.Interface, local, peers})
	}
	slices.SortFunc(result, func(a, b NeighborLink) int {
		if a.Interface < b.Interface {
			return -1
		}
		if a.Interface > b.Interface {
			return 1
		}
		return 0
	})
	return result, nil
}

func CanonicalNeighborAddresses(values []string) ([]string, error) {
	result := slices.Clone(values)
	for _, text := range result {
		a, err := netip.ParseAddr(text)
		if err != nil || !a.Is6() || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.Zone() != "" || a.String() != text {
			return nil, ErrNeighborInventory
		}
	}
	slices.Sort(result)
	if len(slices.Compact(slices.Clone(result))) != len(result) {
		return nil, ErrNeighborInventory
	}
	return result, nil
}
