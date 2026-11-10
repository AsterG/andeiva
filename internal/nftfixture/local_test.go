package nftfixture

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

func TestLocalProbeIsFixedToAdjacentGateway(t *testing.T) {
	for _, side := range []string{"source", "sink"} {
		for _, family := range []string{"ipv4", "ipv6"} {
			for _, origin := range []string{"primary", "alternate"} {
				for _, protocol := range []string{"tcp", "udp"} {
					p := LocalProbe{side, family, origin, protocol, 18080}
					source, destination, network, err := localProbeAddresses(p)
					if err != nil || source == destination || netip.MustParseAddr(source).Is4() != (family == "ipv4") || network != protocol+map[string]string{"ipv4": "4", "ipv6": "6"}[family] {
						t.Fatal(p, source, destination, network, err)
					}
					args, err := localProbeArgs(p, 42)
					if err != nil {
						t.Fatal(err)
					}
					got, host, err := parseLocalProbe(args)
					if err != nil || got != p || host != 42 {
						t.Fatal("roundtrip", got, host, err)
					}
				}
			}
		}
	}
	base := LocalProbe{"source", "ipv4", "primary", "tcp", 18080}
	for name, mutate := range map[string]func(*LocalProbe){
		"side": func(p *LocalProbe) { p.Side = "gateway" }, "address": func(p *LocalProbe) { p.Side = "192.168.18.254" },
		"family": func(p *LocalProbe) { p.Family = "ipv4;id" }, "origin": func(p *LocalProbe) { p.Origin = "198.18.1.4" },
		"protocol": func(p *LocalProbe) { p.Protocol = "icmp" }, "host_ssh": func(p *LocalProbe) { p.Port = 22 }, "other_port": func(p *LocalProbe) { p.Port = 8443 },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if _, err := localProbeArgs(p, 42); err == nil {
				t.Fatal("expanded probe accepted")
			}
		})
	}
	args, _ := localProbeArgs(base, 42)
	for _, change := range []struct {
		index int
		value string
	}{{0, "sh"}, {1, "exec"}, {6, "018080"}, {6, "65536"}, {7, "0"}, {7, "042"}, {7, "bad"}} {
		copy := append([]string{}, args...)
		copy[change.index] = change.value
		if _, _, err := parseLocalProbe(copy); err == nil {
			t.Fatal("malformed arguments accepted", copy)
		}
		if handled, code := HandleRole(copy); copy[0] == "--nft-fixture" && (!handled || code != 2) {
			t.Fatal("role parser", copy, handled, code)
		}
	}
}

func TestLocalInventoryAndNeighborsAreIndependentCanonicalValues(t *testing.T) {
	first, second := LocalInventory(), LocalInventory()
	first[0].Addresses[0] = "wrong"
	first[0].Name = "wrong"
	if !reflect.DeepEqual(second, LocalInventory()) {
		t.Fatal("inventory aliases")
	}
	peers := LocalNeighbors()
	peers[0].PeerAddresses[0] = "wrong"
	if reflect.DeepEqual(peers, LocalNeighbors()) {
		t.Fatal("neighbor aliases")
	}
	c := localpolicy.Config{SchemaVersion: 1, Interfaces: LocalInventory(), Services: []localpolicy.Service{}}
	if _, err := localnft.CompileWithNeighbors(c, LocalNeighbors()); err != nil {
		t.Fatal("profile incompatible with compiler", err)
	}
	seen := map[string]bool{}
	for _, i := range c.Interfaces {
		for _, address := range i.Addresses {
			if seen[address] {
				t.Fatal("duplicate local inventory address", address)
			}
			seen[address] = true
		}
	}
	for _, p := range LocalNeighbors() {
		if len(p.LocalAddresses) != 2 || len(p.PeerAddresses) != 3 {
			t.Fatal("wrong ND profile", p)
		}
	}
}
