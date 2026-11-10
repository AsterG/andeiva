package nftfixture

import (
	"errors"
	"net"
	"strconv"

	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

// LocalProbe chooses only fixed, directly connected laboratory endpoints.
// Alternate origins test a denied CIDR without requiring a fourth namespace.
type LocalProbe struct {
	Side     string `json:"side"`
	Family   string `json:"family"`
	Origin   string `json:"origin"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type localLink struct{ role, dev, gateway, address4, alternate4, gateway4, address6, alternate6, gateway6, linkLocal, gatewayLinkLocal string }

func localLinks() []localLink {
	return []localLink{
		{"source", "srcpeer", "src0", "198.18.1.2", "198.18.1.3", "198.18.1.1", "fd42:616e:6465:1::2", "fd42:616e:6465:1::3", "fd42:616e:6465:1::1", "fe80::2", "fe80::1"},
		{"sink", "dstpeer", "dst0", "198.18.2.2", "198.18.2.3", "198.18.2.1", "fd42:616e:6465:2::2", "fd42:616e:6465:2::3", "fd42:616e:6465:2::1", "fe80::6", "fe80::5"},
	}
}

// LocalInventory returns a fresh copy of the fixed local-only gateway inventory.
// Both links are laboratory LANs. This says nothing about host WAN/LAN interfaces.
func LocalInventory() []localpolicy.Interface {
	result := []localpolicy.Interface{}
	for _, link := range localLinks() {
		result = append(result, localpolicy.Interface{Name: link.gateway, Zone: localpolicy.LAN, Addresses: []string{link.gateway4, link.gateway6, link.gatewayLinkLocal}})
	}
	return result
}

func LocalNeighbors() []localnft.NeighborLink {
	result := []localnft.NeighborLink{}
	for _, link := range localLinks() {
		result = append(result, localnft.NeighborLink{Interface: link.gateway, LocalAddresses: []string{link.gateway6, link.gatewayLinkLocal}, PeerAddresses: []string{link.address6, link.alternate6, link.linkLocal}})
	}
	return result
}

func localProbeAddresses(p LocalProbe) (source, destination, network string, err error) {
	if !validProbe(p.Protocol, p.Port) || (p.Family != "ipv4" && p.Family != "ipv6") || (p.Origin != "primary" && p.Origin != "alternate") {
		return "", "", "", errors.New("ANDEIVA_NFT_LOCAL_PROBE_INVALID")
	}
	for _, link := range localLinks() {
		if link.role != p.Side {
			continue
		}
		source, destination, network = link.address4, link.gateway4, p.Protocol+"4"
		if p.Origin == "alternate" {
			source = link.alternate4
		}
		if p.Family == "ipv6" {
			source, destination, network = link.address6, link.gateway6, p.Protocol+"6"
			if p.Origin == "alternate" {
				source = link.alternate6
			}
		}
		return
	}
	return "", "", "", errors.New("ANDEIVA_NFT_LOCAL_PROBE_INVALID")
}

func localProbeArgs(p LocalProbe, host uint64) ([]string, error) {
	if _, _, _, err := localProbeAddresses(p); err != nil || host == 0 {
		return nil, errors.New("ANDEIVA_NFT_LOCAL_PROBE_INVALID")
	}
	return []string{"--nft-fixture", "probe-gateway", p.Side, p.Family, p.Origin, p.Protocol, strconv.Itoa(p.Port), strconv.FormatUint(host, 10)}, nil
}

func parseLocalProbe(args []string) (LocalProbe, uint64, error) {
	if len(args) != 8 || args[0] != "--nft-fixture" || args[1] != "probe-gateway" {
		return LocalProbe{}, 0, errors.New("ANDEIVA_NFT_LOCAL_PROBE_INVALID")
	}
	port, err := strconv.Atoi(args[6])
	if err != nil || strconv.Itoa(port) != args[6] {
		return LocalProbe{}, 0, errors.New("ANDEIVA_NFT_LOCAL_PROBE_INVALID")
	}
	host, err := strconv.ParseUint(args[7], 10, 64)
	if err != nil || host == 0 || strconv.FormatUint(host, 10) != args[7] {
		return LocalProbe{}, 0, errors.New("ANDEIVA_NFT_LOCAL_PROBE_INVALID")
	}
	p := LocalProbe{args[2], args[3], args[4], args[5], port}
	if _, _, _, err := localProbeAddresses(p); err != nil {
		return LocalProbe{}, 0, err
	}
	return p, host, nil
}

func probeGateway(p LocalProbe) (bool, error) {
	source, destination, network, err := localProbeAddresses(p)
	if err != nil {
		return false, err
	}
	var local net.Addr = &net.TCPAddr{IP: net.ParseIP(source)}
	if p.Protocol == "udp" {
		local = &net.UDPAddr{IP: net.ParseIP(source)}
	}
	return exchangeProbe(network, net.JoinHostPort(destination, strconv.Itoa(p.Port)), local)
}

func localEchoAddresses() []listenAddress {
	addresses := []listenAddress{}
	for _, link := range localLinks() {
		addresses = append(addresses, listenAddress{link.gateway4, "4"}, listenAddress{link.gateway6, "6"})
	}
	return addresses
}
