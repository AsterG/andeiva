package previewruntime

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Closure-only evidence from the authenticated V4 producer. Address is solely
// a physical listener-association hint, never lease/forwarding authority.
type routedDHCPMarginClosedV4 struct {
	epoch   uint64
	address string
}
type routedDHCPMarginClosedWireV4 struct {
	Version         int    `json:"version"`
	ObservedEpoch   uint64 `json:"observed_epoch"`
	ListenerAddress string `json:"listener_address"`
}

func (routedDHCPMarginClosedV4) Error() string { return "WAN lease margin insufficient" }
func routedDHCPMarginV4(err error) (routedDHCPMarginClosedV4, bool) {
	var closed routedDHCPMarginClosedV4
	if !errors.As(err, &closed) || closed.epoch == 0 {
		return closed, false
	}
	p, e := netip.ParsePrefix(closed.address)
	valid := e == nil && p.String() == closed.address && p.Addr().Is4() && !p.Addr().IsUnspecified() && !p.Addr().IsMulticast() && !p.Addr().IsLoopback() && p.Bits() > 0 && p.Bits() < 31
	if valid {
		raw := p.Addr().As4()
		mask := uint32(1)<<uint(32-p.Bits()) - 1
		host := binary.BigEndian.Uint32(raw[:]) & mask
		valid = host != 0 && host != mask
	}
	return closed, valid
}
