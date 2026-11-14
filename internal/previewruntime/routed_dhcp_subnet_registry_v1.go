package previewruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"sort"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const (
	routedDHCPSubnetRegistryNameV1    = "scope-bindings.v1.json"
	routedDHCPSubnetRegistryPendingV1 = "scope-bindings.v1.pending"
	routedDHCPSubnetRegistryEntriesV1 = 4096
	routedDHCPSubnetRegistryBytesV1   = 1 << 20
)

var ErrRoutedDHCPSubnetRegistryV1 = errors.New("ANDEIVA_DHCP_SUBNET_REGISTRY_UNAVAILABLE")
var ErrRoutedDHCPSubnetRegistryFullV1 = errors.New("ANDEIVA_DHCP_SUBNET_REGISTRY_FULL")

// RoutedDHCPSubnetBindingV1 is operational identity supplied by trusted selected
// LAN inventory. It is not an administrative DTO or permission to start DHCP.
type RoutedDHCPSubnetBindingV1 struct {
	ScopeID     string `json:"scope_id"`
	InterfaceID string `json:"interface_id"`
	HardwareMAC string `json:"hardware_mac"`
	Subnet      string `json:"subnet"`
}

type routedDHCPSubnetEntryV1 struct {
	Binding RoutedDHCPSubnetBindingV1 `json:"binding"`
	ID      uint32                    `json:"id"`
}

type routedDHCPSubnetRegistryV1 struct {
	Version   int                       `json:"version"`
	HighWater uint32                    `json:"high_water"`
	Entries   []routedDHCPSubnetEntryV1 `json:"entries"`
}

func validDHCPSubnetBindingV1(b RoutedDHCPSubnetBindingV1) bool {
	id := func(s string) bool {
		if len(s) == 0 || len(s) > 64 {
			return false
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return false
			}
		}
		return true
	}
	m, err := net.ParseMAC(b.HardwareMAC)
	if !id(b.ScopeID) || !id(b.InterfaceID) || err != nil || len(m) != 6 || m.String() != b.HardwareMAC || m[0]&1 != 0 || b.HardwareMAC == "00:00:00:00:00:00" {
		return false
	}
	p, err := netip.ParsePrefix(b.Subnet)
	return err == nil && p.Addr().Is4() && p.Bits() >= 1 && p.Bits() <= 30 && p == p.Masked() && p.String() == b.Subnet
}

func decodeDHCPSubnetRegistryV1(raw []byte) (routedDHCPSubnetRegistryV1, error) {
	var r routedDHCPSubnetRegistryV1
	if len(raw) == 0 || len(raw) > routedDHCPSubnetRegistryBytesV1 || !jsoncheck.UniqueControlFields(raw) {
		return r, ErrRoutedDHCPSubnetRegistryV1
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Version != 1 || r.Entries == nil || len(r.Entries) > routedDHCPSubnetRegistryEntriesV1 {
		return r, ErrRoutedDHCPSubnetRegistryV1
	}
	keys := map[RoutedDHCPSubnetBindingV1]bool{}
	var last uint32
	for _, e := range r.Entries {
		if !validDHCPSubnetBindingV1(e.Binding) || keys[e.Binding] || e.ID == 0 || e.ID <= last {
			return r, ErrRoutedDHCPSubnetRegistryV1
		}
		keys[e.Binding] = true
		last = e.ID
	}
	if last != r.HighWater {
		return r, ErrRoutedDHCPSubnetRegistryV1
	}
	return r, nil
}

func allocateDHCPSubnetRegistryV1(r routedDHCPSubnetRegistryV1, bindings []RoutedDHCPSubnetBindingV1) (routedDHCPSubnetRegistryV1, []uint32, bool, error) {
	if len(bindings) > 32 {
		return r, nil, false, ErrRoutedDHCPSubnetRegistryV1
	}
	known := make(map[RoutedDHCPSubnetBindingV1]uint32, len(r.Entries))
	for _, e := range r.Entries {
		known[e.Binding] = e.ID
	}
	missing := map[RoutedDHCPSubnetBindingV1]bool{}
	for _, b := range bindings {
		if !validDHCPSubnetBindingV1(b) {
			return r, nil, false, ErrRoutedDHCPSubnetRegistryV1
		}
		if known[b] == 0 {
			missing[b] = true
		}
	}
	if len(r.Entries)+len(missing) > routedDHCPSubnetRegistryEntriesV1 || uint64(r.HighWater)+uint64(len(missing)) > math.MaxUint32 {
		return r, nil, false, ErrRoutedDHCPSubnetRegistryFullV1
	}
	ordered := make([]RoutedDHCPSubnetBindingV1, 0, len(missing))
	for b := range missing {
		ordered = append(ordered, b)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.ScopeID != b.ScopeID {
			return a.ScopeID < b.ScopeID
		}
		if a.InterfaceID != b.InterfaceID {
			return a.InterfaceID < b.InterfaceID
		}
		if a.HardwareMAC != b.HardwareMAC {
			return a.HardwareMAC < b.HardwareMAC
		}
		return a.Subnet < b.Subnet
	})
	for _, b := range ordered {
		r.HighWater++
		known[b] = r.HighWater
		r.Entries = append(r.Entries, routedDHCPSubnetEntryV1{b, r.HighWater})
	}
	ids := make([]uint32, len(bindings))
	for i, b := range bindings {
		ids[i] = known[b]
	}
	return r, ids, len(ordered) > 0, nil
}
