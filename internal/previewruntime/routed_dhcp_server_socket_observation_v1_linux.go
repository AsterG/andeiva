//go:build linux

package previewruntime

import (
	"cmp"
	"math"
	"net/netip"
	"slices"

	"github.com/AsterG/andeiva/internal/dhcpsockets"
	"golang.org/x/sys/unix"
)

// A binding comes from the selected static LAN and independent physical L3
// readback. ifindex alone is not a sufficient association across transitions.
type routedDHCPServerSocketBindingV1 struct {
	index   uint32
	address netip.Addr
}

type routedDHCPServerSocketFactsV1 struct {
	udp    []dhcpsockets.Socket
	packet []dhcpsockets.PacketSocket
}

// splitRoutedDHCPServerSocketsV1 runs on complete paired namespace inventory.
// The caller proves the live engine, LAN pins and selected Work before and
// after observation. AF_PACKET requires a matching actual engine descriptor.
func splitRoutedDHCPServerSocketsV1(c routedDHCPSocketCaptureV1, id RoutedDHCPServiceCgroupIdentityV1, uid uint32, bindings []routedDHCPServerSocketBindingV1, holders []uint64) (routedDHCPSocketCaptureV1, routedDHCPServerSocketFactsV1, error) {
	if id.Device == 0 || id.Inode == 0 || uid == 0 || len(bindings) == 0 || len(bindings) > 32 ||
		len(holders) == 0 || len(holders) > 256 || !slices.IsSorted(holders) {
		return routedDHCPSocketCaptureV1{}, routedDHCPServerSocketFactsV1{}, ErrIdentity
	}
	addresses := make(map[netip.Addr]uint32, len(bindings))
	indices := make(map[uint32]bool, len(bindings))
	for _, b := range bindings {
		if b.index == 0 || b.index == c.wanIndex || !b.address.Is4() || !b.address.IsGlobalUnicast() ||
			addresses[b.address] != 0 || indices[b.index] {
			return routedDHCPSocketCaptureV1{}, routedDHCPServerSocketFactsV1{}, ErrIdentity
		}
		addresses[b.address], indices[b.index] = b.index, true
	}
	others := routedDHCPSocketCaptureV1{wanIndex: c.wanIndex, addressOnWAN: c.addressOnWAN}
	var facts routedDHCPServerSocketFactsV1
	udpByInode := make(map[uint64]dhcpsockets.Socket, len(bindings))
	seenUDP := make(map[netip.Addr]bool, len(bindings))
	for _, socket := range c.udp {
		if socket.UID != uid && socket.CreationCgroup != id.Inode {
			others.udp = append(others.udp, socket)
			continue
		}
		index := addresses[socket.Address]
		_, owned := slices.BinarySearch(holders, uint64(socket.Inode))
		if socket.UID != uid || socket.CreationCgroup != id.Inode || socket.Port != 67 ||
			index == 0 || (socket.Interface != 0 && socket.Interface != index) || socket.Inode == 0 ||
			!owned || socket.Cookie == 0 || socket.Cookie == math.MaxUint64 || seenUDP[socket.Address] || udpByInode[uint64(socket.Inode)].Inode != 0 {
			return routedDHCPSocketCaptureV1{}, routedDHCPServerSocketFactsV1{}, ErrUnavailable
		}
		seenUDP[socket.Address] = true
		udpByInode[uint64(socket.Inode)] = socket
		facts.udp = append(facts.udp, socket)
	}
	for _, row := range c.tables {
		socket, linked := udpByInode[row.Inode]
		if !linked && row.UID != uid {
			others.tables = append(others.tables, row)
			continue
		}
		if !linked || row.Protocol != "udp" || row.Family != "ipv4" || row.Port != 67 ||
			row.Address != socket.Address.String() || row.UID != uid || row.Wildcard || row.Mapped {
			return routedDHCPSocketCaptureV1{}, routedDHCPServerSocketFactsV1{}, ErrUnavailable
		}
		delete(udpByInode, row.Inode)
	}

	const packetRunning = 0x1 // PDI_RUNNING, Linux packet_diag UAPI.
	seenPacket := make(map[uint32]bool, len(bindings))
	for _, packet := range c.packet {
		if packet.UID != uid {
			others.packet = append(others.packet, packet)
			continue
		}
		_, owned := slices.BinarySearch(holders, uint64(packet.Inode))
		if !indices[packet.Interface] || seenPacket[packet.Interface] || packet.Type != unix.SOCK_RAW ||
			packet.Protocol != unix.ETH_P_ALL || packet.Flags != packetRunning ||
			!owned || packet.Cookie == 0 || packet.Cookie == math.MaxUint64 || packet.Inode == 0 {
			return routedDHCPSocketCaptureV1{}, routedDHCPServerSocketFactsV1{}, ErrUnavailable
		}
		seenPacket[packet.Interface] = true
		facts.packet = append(facts.packet, packet)
	}
	if len(udpByInode) != 0 || len(facts.udp) != len(bindings) || len(facts.packet) != len(bindings) {
		return routedDHCPSocketCaptureV1{}, routedDHCPServerSocketFactsV1{}, ErrUnavailable
	}
	slices.SortFunc(facts.udp, func(a, b dhcpsockets.Socket) int { return a.Address.Compare(b.Address) })
	slices.SortFunc(facts.packet, func(a, b dhcpsockets.PacketSocket) int { return cmp.Compare(a.Interface, b.Interface) })
	return others, facts, nil
}
