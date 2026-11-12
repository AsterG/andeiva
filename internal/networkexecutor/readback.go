package networkexecutor

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"github.com/AsterG/andeiva/internal/networkplan"
)

const maxOutput = 256 * 1024

type address struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Bits      int    `json:"prefixlen"`
	Broadcast string `json:"broadcast,omitempty"`
	Scope     string `json:"scope"`
	Label     string `json:"label,omitempty"`
	Valid     uint64 `json:"valid_life_time"`
	Preferred uint64 `json:"preferred_life_time"`
}
type link struct {
	Index     int       `json:"ifindex"`
	Name      string    `json:"ifname"`
	MAC       string    `json:"address"`
	MTU       int       `json:"mtu"`
	Flags     []string  `json:"flags"`
	Addresses []address `json:"addr_info"`
}
type route struct {
	Destination string   `json:"dst"`
	Device      string   `json:"dev"`
	Gateway     string   `json:"gateway,omitempty"`
	Protocol    string   `json:"protocol"`
	Scope       string   `json:"scope,omitempty"`
	Source      string   `json:"prefsrc,omitempty"`
	Table       string   `json:"table,omitempty"`
	Type        string   `json:"type,omitempty"`
	Metric      uint32   `json:"metric,omitempty"`
	Flags       []string `json:"flags,omitempty"`
}
type observation struct {
	Links  []link
	Routes []route
}

func decode(data []byte, target any, strict bool) error {
	if len(data) == 0 || len(data) > maxOutput || !jsoncheck.UniqueFields(data) {
		return ErrObservation
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if strict {
		d.DisallowUnknownFields()
	}
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return ErrObservation
	}
	return nil
}
func (e *Executor) observe(ctx context.Context) (observation, error) {
	var o observation
	data, err := e.execute(ctx, operation{kind: "addresses"})
	if err != nil {
		return o, err
	}
	// Link records contain kernel/hardware-dependent read-only fields. Address
	// records are separately decoded strictly, so dynamic/peer flags cannot hide.
	var raw []struct {
		Info []json.RawMessage `json:"addr_info"`
	}
	if decode(data, &o.Links, false) != nil || decode(data, &raw, false) != nil || len(o.Links) > networkinventory.MaxInterfaces {
		return o, ErrObservation
	}
	for i := range o.Links {
		l := &o.Links[i]
		if len(l.Addresses) > networkinventory.MaxAddresses || len(l.Name) > networkinventory.MaxNameBytes {
			return o, ErrObservation
		}
		for j := range l.Addresses {
			if decode(raw[i].Info[j], &l.Addresses[j], true) != nil {
				return o, ErrObservation
			}
		}
		slices.Sort(l.Flags)
		slices.SortFunc(l.Addresses, func(a, b address) int { return strings.Compare(a.Local, b.Local) })
	}
	slices.SortFunc(o.Links, func(a, b link) int { return strings.Compare(a.Name, b.Name) })
	data, err = e.execute(ctx, operation{kind: "routes"})
	if err != nil {
		return o, err
	}
	if decode(data, &o.Routes, true) != nil || len(o.Routes) > 256 {
		return o, ErrObservation
	}
	for i := range o.Routes {
		r := &o.Routes[i]
		if r.Table == "" {
			r.Table = "main"
		}
		if r.Type == "" {
			r.Type = "unicast"
		}
		if r.Scope == "" {
			r.Scope = "global"
		}
		if len(r.Flags) != 0 {
			return o, ErrObservation
		}
		r.Flags = nil
	}
	sortRoutes(o.Routes)
	return o, nil
}
func sortRoutes(r []route) {
	slices.SortFunc(r, func(a, b route) int { x, _ := json.Marshal(a); y, _ := json.Marshal(b); return bytes.Compare(x, y) })
}
func (o observation) inventory() networkinventory.Snapshot {
	s := networkinventory.Snapshot{SchemaVersion: networkinventory.SchemaVersion}
	for _, l := range o.Links {
		s.Interfaces = append(s.Interfaces, networkinventory.Interface{Index: l.Index, Name: l.Name, HardwareAddress: l.MAC, PointToPoint: slices.Contains(l.Flags, "POINTOPOINT"), Kind: networkinventory.Virtual})
	}
	return s
}
func (o observation) empty() bool {
	if len(o.Routes) != 0 {
		return false
	}
	for _, l := range o.Links {
		if len(l.Addresses) != 0 {
			return false
		}
	}
	return true
}
func sameLinks(a, b observation) bool {
	if len(a.Links) != len(b.Links) {
		return false
	}
	for i := range a.Links {
		x, y := a.Links[i], b.Links[i]
		x.Addresses = nil
		y.Addresses = nil
		if !reflect.DeepEqual(x, y) {
			return false
		}
	}
	return true
}
func (o observation) contains(op operation) bool {
	if op.kind == "address-add" {
		for _, l := range o.Links {
			if l.Name == op.name {
				for _, a := range l.Addresses {
					if a.Local+"/"+strconv.Itoa(a.Bits) == op.address {
						return true
					}
				}
			}
		}
		return false
	}
	for _, r := range o.Routes {
		if r.Destination == "default" && r.Device == op.name && r.Gateway == op.gateway && r.Metric == op.metric && r.Protocol == "static" && r.Table == "main" && r.Type == "unicast" && r.Scope == "global" {
			return true
		}
	}
	return false
}
func (o observation) matches(rev networkplan.Revision, baseline observation) bool {
	if !sameLinks(o, baseline) {
		return false
	}
	desired := map[string]networkplan.Interface{}
	expected := []route{}
	for _, i := range rev.Config.Interfaces {
		desired[i.Binding.Name] = i
		p := netip.MustParsePrefix(i.IPv4.Address)
		// Only ordinary broadcast subnets are supported by this first fixture.
		if p.Bits() > 30 {
			return false
		}
		ip := p.Addr().String()
		network := p.Masked().String()
		b := p.Masked().Addr().As4()
		hostBits := uint32(1) << (32 - p.Bits())
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		v += hostBits - 1
		binary.BigEndian.PutUint32(b[:], v)
		broadcast := netip.AddrFrom4(b).String()
		expected = append(expected, route{Destination: network, Device: i.Binding.Name, Protocol: "kernel", Scope: "link", Source: ip, Table: "main", Type: "unicast"}, route{Destination: ip, Device: i.Binding.Name, Protocol: "kernel", Scope: "host", Source: ip, Table: "local", Type: "local"})
		// ip address add without an explicit broadcast does not request broadcast
		// routes; accept them only as the exact kernel-derived subnet endpoints.
		for _, r := range o.Routes {
			if r.Device == i.Binding.Name && r.Type == "broadcast" && (r.Destination == p.Masked().Addr().String() || r.Destination == broadcast) {
				expected = append(expected, route{Destination: r.Destination, Device: i.Binding.Name, Protocol: "kernel", Scope: "link", Source: ip, Table: "local", Type: "broadcast"})
			}
		}
		if i.ID == rev.Config.DefaultRoute.InterfaceID {
			expected = append(expected, route{Destination: "default", Device: i.Binding.Name, Gateway: i.IPv4.Gateway, Protocol: "static", Scope: "global", Table: "main", Type: "unicast", Metric: rev.Config.DefaultRoute.Metric})
		}
	}
	for _, l := range o.Links {
		i, ok := desired[l.Name]
		if !ok {
			if len(l.Addresses) != 0 {
				return false
			}
			continue
		}
		if len(l.Addresses) != 1 {
			return false
		}
		a := l.Addresses[0]
		if a.Family != "inet" || a.Local+"/"+strconv.Itoa(a.Bits) != i.IPv4.Address || a.Scope != "global" || a.Label != l.Name || a.Valid != 4294967295 || a.Preferred != 4294967295 {
			return false
		}
	}
	sortRoutes(expected)
	return reflect.DeepEqual(o.Routes, expected)
}
