//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"

	"github.com/AsterG/andeiva/internal/dhcpsockets"
	"github.com/AsterG/andeiva/internal/localobserve"
	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

// Root-selected qualification profile, never an administrative request. Zero
// denies activation. Packet diagnostics provide no creation-cgroup attribute;
// this inventory relies on the maintained service's exclusive raw-socket TCB.
type routedDHCPPacketProfileV1 struct {
	Version  int
	UID      uint32
	Type     uint8
	Protocol uint16
	Maximum  uint8
	Flags    uint32
}

func (p routedDHCPPacketProfileV1) valid() bool {
	return p == qualifiedRoutedDHCPPacketProfileV1()
}

// Maintained-engine source and isolated acquisition/renewal readback establish
// this bounded profile. It is not packet cgroup, holder or BPF-filter proof.
func qualifiedRoutedDHCPPacketProfileV1() routedDHCPPacketProfileV1 {
	return routedDHCPPacketProfileV1{Version: 1, UID: 0, Type: unix.SOCK_RAW, Protocol: unix.ETH_P_ALL, Maximum: 2, Flags: 3}
}

type routedDHCPServiceObservationV1 struct {
	pin       *os.File
	identity  RoutedDHCPServiceCgroupIdentityV1
	binding   RoutedDHCPDeferredBindingV4
	producer  *os.File // Independent pin survives reader EOF/Close until drainage.
	current   func(context.Context) (RoutedDHCPOwnerFactV3, error)
	packet    routedDHCPPacketProfileV1
	wan       networkplan.Binding
	activated bool
	retiring  bool
}

type routedDHCPSocketCaptureV1 struct {
	tables       []localobserve.Socket
	udp          []dhcpsockets.Socket
	packet       []dhcpsockets.PacketSocket
	wanIndex     uint32
	addressOnWAN bool
}

func newRoutedDHCPServiceObservationV1(ctx context.Context, pin *os.File, id RoutedDHCPServiceCgroupIdentityV1, b RoutedDHCPDeferredBindingV4, reader *RoutedDHCPDeferredReaderV4, packet routedDHCPPacketProfileV1) (*routedDHCPServiceObservationV1, error) {
	if reader == nil || reader.reader == nil || !packet.valid() {
		return nil, ErrIdentity
	}
	b, err := cloneRoutedDHCPDeferredBindingV4(b)
	if err != nil {
		return nil, err
	}
	producer := reader.reader.files.RolePIDFD
	if !routedDHCPOwnerPIDFDAliveV3(producer, int(b.Owner.PID)) {
		return nil, ErrIdentity
	}
	fd, err := unix.FcntlInt(producer.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrIdentity
	}
	s := &routedDHCPServiceObservationV1{pin: pin, identity: id, binding: b, producer: os.NewFile(uintptr(fd), "retained-service-producer"), current: reader.Current, packet: packet}
	for _, link := range b.Desired.Config.Interfaces {
		if link.Role == networkplan.WAN {
			s.wan = link.Binding
		}
	}
	if s.wan.Name == "" || s.validate(ctx, true) != nil {
		_ = s.producer.Close()
		return nil, ErrIdentity
	}
	return s, nil
}

func (s *routedDHCPServiceObservationV1) validate(ctx context.Context, live bool) error {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	id, err := routedDHCPServiceDirectoryV1(s.pin)
	if err != nil || id != s.identity || !routedDHCPServiceBootstrapValidV1(1, id) {
		return ErrIdentity
	}
	if !live {
		return nil
	}
	pid := int(s.binding.Owner.PID)
	if s.retiring || !routedDHCPOwnerPIDFDAliveV3(s.producer, pid) {
		return ErrUnavailable
	}
	start, _, err := routedDHCPOwnerProcessV3(pid)
	group, e := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(pid)+"/cgroup", 4096)
	name, nerr := routedDHCPServiceNameV1(s.binding.Owner.Incarnation)
	if err != nil || e != nil || nerr != nil || start != s.binding.Owner.StartTicks || string(group) != "0::"+routedSupervisorCgroupV3+"/"+name+"\n" {
		return ErrIdentity
	}
	// Parent traversal is permitted; child controls remain root-only (0700).
	// Do not require a privilege change to read files below the retained pin.
	parent, e := routedDHCPServiceParentV1()
	if e != nil {
		return e
	}
	defer parent.Close()
	if e = routedDHCPServiceTreeV1(parent, name, id); e != nil {
		return e
	}
	if ctx.Err() != nil || !routedDHCPOwnerPIDFDAliveV3(s.producer, pid) {
		return ErrUnavailable
	}
	return nil
}

func (s *routedDHCPServiceObservationV1) fact(ctx context.Context) (RoutedDHCPOwnerFactV3, bool, error) {
	if s == nil || !s.activated || s.validate(ctx, true) != nil {
		return RoutedDHCPOwnerFactV3{}, false, ErrUnavailable
	}
	f, err := s.current(ctx)
	if err == errRoutedDHCPInitialWaitingV1 && ctx.Err() == nil && s.validate(ctx, true) == nil {
		return RoutedDHCPOwnerFactV3{}, true, nil
	}
	if err != nil || s.validate(ctx, true) != nil {
		return RoutedDHCPOwnerFactV3{}, false, ErrUnavailable
	}
	now, e := routedDHCPOwnerBootNowV3()
	if e != nil || !validRoutedDHCPServiceFactV1(f, s.binding, s.wan, now) || ctx.Err() != nil {
		return RoutedDHCPOwnerFactV3{}, false, ErrUnavailable
	}
	return f, false, nil
}

func validRoutedDHCPServiceFactV1(f RoutedDHCPOwnerFactV3, b RoutedDHCPDeferredBindingV4, wan networkplan.Binding, now int64) bool {
	p, e := netip.ParsePrefix(f.Fact.Address)
	return now > 0 && f.Epoch != 0 && f.Fact.Sequence != 0 && !f.Fact.Revoked && f.Fact.Owner == b.Owner && f.Fact.DesiredHash == b.Desired.Hash && f.Fact.WAN == wan && f.Fact.DeadlineBootNS > now && e == nil && p.Addr().Is4() && !p.Addr().IsUnspecified()
}

// This resolves physical interface/address association. An inet_diag ifindex
// of zero is not SO_BINDTODEVICE proof: a UDP exception instead requires its
// exact leased address to be present only on the selected WAN, before/after.
func routedDHCPPhysicalWANV1(ctx context.Context, wan networkplan.Binding, address string) (uint32, bool, error) {
	if ctx == nil || ctx.Err() != nil {
		return 0, false, ErrUnavailable
	}
	links, err := net.Interfaces()
	if err != nil || len(links) > networkplan.MaxInterfaces {
		return 0, false, ErrUnavailable
	}
	var expected netip.Prefix
	if address != "" {
		expected, err = netip.ParsePrefix(address)
		if err != nil || !expected.Addr().Is4() {
			return 0, false, ErrIdentity
		}
	}
	var index uint32
	matches := 0
	onWAN := false
	for _, link := range links {
		if link.Index <= 0 || uint64(link.Index) > math.MaxUint32 {
			return 0, false, ErrIdentity
		}
		selected := link.Name == wan.Name && link.HardwareAddr.String() == wan.HardwareAddress
		if link.Name == wan.Name && !selected {
			return 0, false, ErrIdentity
		}
		if selected {
			if index != 0 {
				return 0, false, ErrIdentity
			}
			index = uint32(link.Index)
		}
		if !expected.IsValid() {
			continue
		}
		addresses, e := link.Addrs()
		if e != nil || len(addresses) > 64 {
			return 0, false, ErrUnavailable
		}
		for _, raw := range addresses {
			p, e := netip.ParsePrefix(raw.String())
			if e != nil {
				return 0, false, ErrIdentity
			}
			if p.Addr() == expected.Addr() {
				matches++
				onWAN = selected && p == expected
			}
		}
	}
	if ctx.Err() != nil || index == 0 || matches > 1 {
		return 0, false, ErrUnavailable
	}
	return index, matches == 1 && onWAN, nil
}

func matchRoutedDHCPSocketsV1(c routedDHCPSocketCaptureV1, id RoutedDHCPServiceCgroupIdentityV1, profile routedDHCPPacketProfileV1, f RoutedDHCPOwnerFactV3, waiting bool) error {
	if !profile.valid() || id.Inode == 0 || id.Device == 0 || c.wanIndex == 0 || len(c.tables) > 1 || len(c.udp) != len(c.tables) || len(c.packet) > int(profile.Maximum) {
		return ErrUnavailable
	}
	if waiting && len(c.udp) != 0 {
		return ErrUnavailable
	}
	if !waiting && (f.Epoch == 0 || len(c.packet) == 0) {
		return ErrUnavailable
	}
	if len(c.udp) == 1 {
		p, e := netip.ParsePrefix(f.Fact.Address)
		if e != nil || !c.addressOnWAN {
			return ErrUnavailable
		}
		u, t := c.udp[0], c.tables[0]
		if t.Protocol != "udp" || t.Family != "ipv4" || t.Wildcard || t.Mapped || t.Port != 68 || t.UID != 0 || t.Address != p.Addr().String() || t.Inode != uint64(u.Inode) || u.Inode == 0 || u.Address != p.Addr() || u.Port != 68 || u.UID != 0 || u.CreationCgroup != id.Inode || u.Cookie == 0 || u.Cookie == math.MaxUint64 || (u.Interface != 0 && u.Interface != c.wanIndex) {
			return ErrUnavailable
		}
	}
	seenInodes := map[uint32]bool{}
	seenCookies := map[uint64]bool{}
	for _, p := range c.packet {
		if p.Interface != c.wanIndex || p.Type != profile.Type || p.Protocol != profile.Protocol || p.UID != profile.UID || p.Flags != profile.Flags || p.Inode == 0 || p.Cookie == 0 || p.Cookie == math.MaxUint64 || seenInodes[p.Inode] || seenCookies[p.Cookie] {
			return ErrUnavailable
		}
		seenInodes[p.Inode], seenCookies[p.Cookie] = true, true
	}
	return nil
}

func sameRoutedDHCPSocketsV1(a, b routedDHCPSocketCaptureV1) bool {
	// Captures are sequential, not atomic. Legitimate acquisition sockets may
	// appear/disappear; every capture is independently checked in full. A
	// retained inode must not silently change its cookie or other attributes.
	if a.wanIndex != b.wanIndex {
		return false
	}
	for _, x := range a.udp {
		for _, y := range b.udp {
			if x.Inode == y.Inode && x != y {
				return false
			}
		}
	}
	for _, x := range a.packet {
		for _, y := range b.packet {
			if x.Inode == y.Inode && x != y {
				return false
			}
		}
	}
	return true
}

func (s *routedDHCPServiceObservationV1) producerExited() bool {
	if s == nil || s.producer == nil {
		return false
	}
	fd := s.producer.Fd()
	if fd > math.MaxInt32 {
		return false
	}
	p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, e := unix.Poll(p, 0)
	return e == nil && n == 1 && p[0].Revents&unix.POLLIN != 0 && p[0].Revents&unix.POLLNVAL == 0
}

func (s *routedDHCPServiceObservationV1) closePins() error {
	return errors.Join(s.pin.Close(), s.producer.Close())
}

// Small I/O seam for testing the irreversible pin-release boundary. None of
// these callbacks may grant lease/R2 authority or call the controller/writer.
func releaseRoutedDHCPSocketPinsV1(ctx context.Context, verify func() error, exited func() bool, capture func() (routedDHCPSocketCaptureV1, error), closePins func() error) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	for range 2 {
		if verify() != nil || !exited() || ctx.Err() != nil {
			return ErrUnavailable
		}
		c, err := capture()
		if err != nil || len(c.tables) != 0 || len(c.udp) != 0 || len(c.packet) != 0 || verify() != nil || !exited() || ctx.Err() != nil {
			return ErrUnavailable
		}
	}
	return closePins()
}
