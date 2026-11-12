package networkexecutor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
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

// These typed records contain only the IPv4/L2 facts actually observed by the
// executor. IPv6 and administrative ownership are not asserted by this snapshot.
type SnapshotAddress = address
type SnapshotLink = link
type SnapshotRoute = route

const MaxPreparedSnapshot = 16 << 10

// PreparedSnapshot is a node-local exact empty-IPv4 baseline. Its ifindexes are
// witnesses for this retained namespace lifetime, never binding authority on boot.
type PreparedSnapshot struct {
	Version  int             `json:"version"`
	PlanHash string          `json:"plan_hash"`
	Links    []SnapshotLink  `json:"links"`
	Routes   []SnapshotRoute `json:"routes"`
	Hash     string          `json:"hash"`
}

func (s PreparedSnapshot) observation() observation {
	return observation{Links: s.Links, Routes: s.Routes}
}

// CanonicalPreparedSnapshot validates, detaches and orders a bounded snapshot.
// Only initially empty IPv4 state is supported; no foreign route is adopted.
func CanonicalPreparedSnapshot(input PreparedSnapshot) (PreparedSnapshot, error) {
	if len(input.Links) < 2 || len(input.Links) > 3 || len(input.Routes) != 0 || len(input.PlanHash) != 64 || len(input.Hash) != 64 {
		return PreparedSnapshot{}, ErrScope
	}
	for _, l := range input.Links {
		if len(l.Name) > 15 || len(l.MAC) != 17 || len(l.Flags) > 8 || len(l.Addresses) != 0 {
			return PreparedSnapshot{}, ErrScope
		}
		for _, flag := range l.Flags {
			if len(flag) > 16 {
				return PreparedSnapshot{}, ErrScope
			}
		}
	}
	data, err := json.Marshal(input)
	if err != nil || len(data) > MaxPreparedSnapshot {
		return PreparedSnapshot{}, ErrScope
	}
	var s PreparedSnapshot
	if json.Unmarshal(data, &s) != nil || s.Version != 1 || len(s.PlanHash) != 64 || s.PlanHash != strings.ToLower(s.PlanHash) || len(s.Links) < 2 || len(s.Links) > 3 || len(s.Routes) != 0 {
		return PreparedSnapshot{}, ErrScope
	}
	if _, err := hex.DecodeString(s.PlanHash); err != nil {
		return PreparedSnapshot{}, ErrScope
	}
	names, indexes := map[string]bool{}, map[int]bool{}
	managed := 0
	for i := range s.Links {
		l := &s.Links[i]
		mac, err := net.ParseMAC(l.MAC)
		if !linkName.MatchString(l.Name) || l.Index <= 0 || l.MTU < 68 || l.MTU > 65535 || names[l.Name] || indexes[l.Index] || err != nil || len(mac) != 6 || mac.String() != l.MAC || len(l.Addresses) != 0 || len(l.Flags) > 8 {
			return PreparedSnapshot{}, ErrScope
		}
		names[l.Name], indexes[l.Index] = true, true
		flags := map[string]bool{}
		for _, flag := range l.Flags {
			if flags[flag] || (flag != "UP" && flag != "LOWER_UP" && flag != "BROADCAST" && flag != "MULTICAST" && flag != "LOOPBACK") {
				return PreparedSnapshot{}, ErrUnsupported
			}
			flags[flag] = true
		}
		if l.Name == "lo" {
			if !flags["LOOPBACK"] || l.MAC != "00:00:00:00:00:00" {
				return PreparedSnapshot{}, ErrScope
			}
		} else {
			managed++
			if flags["LOOPBACK"] || l.MAC == "00:00:00:00:00:00" || !flags["UP"] {
				return PreparedSnapshot{}, ErrUnsupported
			}
		}
		slices.Sort(l.Flags)
		l.Flags = append([]string{}, l.Flags...)
		l.Addresses = []address{}
	}
	if managed != 2 {
		return PreparedSnapshot{}, ErrUnsupported
	}
	slices.SortFunc(s.Links, func(a, b link) int { return strings.Compare(a.Name, b.Name) })
	s.Routes = []route{}
	want := s.Hash
	s.Hash = ""
	data, err = json.Marshal(s)
	if err != nil || len(data) > MaxPreparedSnapshot {
		return PreparedSnapshot{}, ErrScope
	}
	digest := sha256.Sum256(data)
	s.Hash = hex.EncodeToString(digest[:])
	if want != s.Hash {
		return PreparedSnapshot{}, ErrScope
	}
	return s, nil
}

// PreparedSnapshotBytes returns canonical detached bytes, including its verified
// semantic hash. Root's object store applies its own contextual object envelope.
func PreparedSnapshotBytes(s PreparedSnapshot) ([]byte, error) {
	s, err := CanonicalPreparedSnapshot(s)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

// Prepare reads twice without effects and binds only the two supported planned
// links plus optional loopback. All other links, addresses and routes are refused.
func (e *Executor) Prepare(ctx context.Context, revision networkplan.Revision) (PreparedSnapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ready(ctx); err != nil {
		return PreparedSnapshot{}, err
	}
	if e.active != nil {
		return PreparedSnapshot{}, ErrBusy
	}
	r, err := networkplan.Canonical(revision.Config)
	if err != nil || r.Hash != revision.Hash || len(r.Config.Interfaces) != 2 || r.Config.DNS.Mode != "none" {
		return PreparedSnapshot{}, ErrUnsupported
	}
	for _, i := range r.Config.Interfaces {
		if i.IPv4.Mode != "static" || netip.MustParsePrefix(i.IPv4.Address).Bits() > 30 {
			return PreparedSnapshot{}, ErrUnsupported
		}
	}
	first, err := e.observe(ctx)
	if err != nil {
		return PreparedSnapshot{}, err
	}
	second, err := e.observe(ctx)
	if err != nil || !reflect.DeepEqual(first, second) {
		return PreparedSnapshot{}, ErrObservation
	}
	if !first.empty() {
		return PreparedSnapshot{}, ErrUnsupported
	}
	if _, err := networkplan.Bind(r, first.inventory()); err != nil {
		return PreparedSnapshot{}, ErrScope
	}
	names := map[string]bool{}
	for _, i := range r.Config.Interfaces {
		names[i.Binding.Name] = true
	}
	for _, l := range first.Links {
		if l.Name != "lo" && !names[l.Name] {
			return PreparedSnapshot{}, ErrScope
		}
	}
	s := PreparedSnapshot{Version: 1, PlanHash: r.Hash, Links: first.Links, Routes: first.Routes}
	data, _ := json.Marshal(s)
	digest := sha256.Sum256(data)
	s.Hash = hex.EncodeToString(digest[:])
	return CanonicalPreparedSnapshot(s)
}

// VerifyPrepared independently checks the actual baseline; it neither applies nor
// adopts resources. Active target state must be checked through Verify instead.
func (e *Executor) VerifyPrepared(ctx context.Context, prepared PreparedSnapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ready(ctx); err != nil {
		return err
	}
	s, err := CanonicalPreparedSnapshot(prepared)
	if err != nil {
		return err
	}
	actual, err := e.observe(ctx)
	if err != nil || !reflect.DeepEqual(actual, s.observation()) {
		return ErrObservation
	}
	return nil
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
	links, err := e.readLinks(ctx)
	if err != nil {
		return o, err
	}
	o.Links = links
	data, err := e.execute(ctx, operation{kind: "addresses"})
	if err != nil {
		return o, err
	}
	// The IPv4 address selector omits link MACs and interfaces without IPv4.
	// Identity therefore comes from separate stable L2 observations, never from
	// caller data or assumptions about the shape of the IPv4 address response.
	var addresses []link
	var raw []struct {
		Info []json.RawMessage `json:"addr_info"`
	}
	if decode(data, &addresses, false) != nil || decode(data, &raw, false) != nil || len(addresses) > networkinventory.MaxInterfaces {
		return o, ErrObservation
	}
	byName := make(map[string]int, len(links))
	for i, l := range links {
		byName[l.Name] = i
	}
	seen := make(map[int]bool, len(addresses))
	for i := range addresses {
		l := &addresses[i]
		index, found := byName[l.Name]
		if !found || seen[index] || l.Index != links[index].Index || l.MTU != links[index].MTU || (l.MAC != "" && l.MAC != links[index].MAC) {
			return o, ErrObservation
		}
		seen[index] = true
		slices.Sort(l.Flags)
		if !slices.Equal(l.Flags, links[index].Flags) {
			return o, ErrObservation
		}
		if len(l.Addresses) > networkinventory.MaxAddresses {
			return o, ErrObservation
		}
		for j := range l.Addresses {
			if decode(raw[i].Info[j], &l.Addresses[j], true) != nil || l.Addresses[j].Family != "inet" {
				return o, ErrObservation
			}
		}
		slices.SortFunc(l.Addresses, func(a, b address) int { return strings.Compare(a.Local, b.Local) })
		o.Links[index].Addresses = append([]address{}, l.Addresses...)
	}
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
	finalLinks, err := e.readLinks(ctx)
	if err != nil {
		return o, err
	}
	if !sameLinks(o, observation{Links: finalLinks}) {
		return o, ErrObservation
	}
	return o, nil
}

func (e *Executor) readLinks(ctx context.Context) ([]link, error) {
	data, err := e.execute(ctx, operation{kind: "links"})
	if err != nil {
		return nil, err
	}
	var links []link
	if decode(data, &links, false) != nil || len(links) > networkinventory.MaxInterfaces {
		return nil, ErrObservation
	}
	names, indexes := map[string]bool{}, map[int]bool{}
	for i := range links {
		l := &links[i]
		if l.Name == "" || len(l.Name) > networkinventory.MaxNameBytes || l.Index <= 0 || names[l.Name] || indexes[l.Index] {
			return nil, ErrObservation
		}
		names[l.Name], indexes[l.Index] = true, true
		slices.Sort(l.Flags)
		l.Addresses = []address{}
	}
	slices.SortFunc(links, func(a, b link) int { return strings.Compare(a.Name, b.Name) })
	return links, nil
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
