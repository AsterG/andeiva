package localpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
)

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

const maxDocument = 256 << 10

func invalid(field string) error { return fmt.Errorf("%w: %s", ErrPolicy, field) }
func validZone(z Zone) bool      { return z == LAN || z == WAN || z == Other }

// Decode rejects unknown fields, oversized documents and concatenated values.
func Decode(data []byte) (Revision, error) {
	if len(data) > maxDocument {
		return Revision{}, invalid("document_size")
	}
	if !uniqueFields(data) {
		return Revision{}, invalid("document_fields")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var c Config
	if err := d.Decode(&c); err != nil {
		return Revision{}, invalid("document")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Revision{}, invalid("trailing_document")
	}
	return Canonical(c)
}

// Canonical returns an independent, ordered copy and a revision bound to every
// declaration, including disabled modules and deployment requirements.
func Canonical(input Config) (Revision, error) {
	data, err := json.Marshal(input)
	if err != nil || len(data) > maxDocument {
		return Revision{}, invalid("document_size")
	}
	var c Config
	if json.Unmarshal(data, &c) != nil {
		return Revision{}, invalid("document")
	}
	if err := validate(&c); err != nil {
		return Revision{}, err
	}
	sort.Slice(c.Interfaces, func(i, j int) bool { return c.Interfaces[i].Name < c.Interfaces[j].Name })
	sort.Slice(c.Services, func(i, j int) bool { return c.Services[i].ID < c.Services[j].ID })
	if c.Interfaces == nil {
		c.Interfaces = []Interface{}
	}
	if c.Services == nil {
		c.Services = []Service{}
	}
	data, err = json.Marshal(c)
	if err != nil {
		return Revision{}, invalid("document")
	}
	sum := sha256.Sum256(data)
	return Revision{hex.EncodeToString(sum[:]), c}, nil
}

func localAddress(text string) (netip.Addr, error) {
	a, err := netip.ParseAddr(text)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, invalid("local_address")
	}
	return a, nil
}

func validate(c *Config) error {
	if c.SchemaVersion != SchemaVersion {
		return invalid("schema_version")
	}
	if len(c.Interfaces) > 32 || len(c.Services) > MaxServices {
		return invalid("capacity")
	}
	inventory := map[string]Interface{}
	addresses := map[string]bool{}
	for i := range c.Interfaces {
		iface := &c.Interfaces[i]
		if !interfaceName.MatchString(iface.Name) || !validZone(iface.Zone) || len(iface.Addresses) == 0 || len(iface.Addresses) > 16 {
			return invalid("interface")
		}
		if _, exists := inventory[iface.Name]; exists {
			return invalid("duplicate_interface")
		}
		for j, text := range iface.Addresses {
			a, err := localAddress(text)
			if err != nil {
				return err
			}
			if addresses[a.String()] {
				return invalid("duplicate_local_address")
			}
			addresses[a.String()] = true
			iface.Addresses[j] = a.String()
		}
		slices.Sort(iface.Addresses)
		inventory[iface.Name] = *iface
	}
	services := map[string]*Service{}
	ruleCount, listenerCount := 0, 0
	for i := range c.Services {
		s := &c.Services[i]
		if !identifier.MatchString(s.ID) || !identifier.MatchString(s.Owner) {
			return invalid("identity")
		}
		if _, exists := services[s.ID]; exists {
			return invalid("duplicate_service")
		}
		services[s.ID] = s
		if err := validateService(s, inventory); err != nil {
			return err
		}
		if s.Enabled {
			for _, b := range s.Bindings {
				ruleCount += len(b.Sources) * len(s.Endpoints)
			}
			for _, e := range s.Endpoints {
				listenerCount += (int(e.LastPort) - int(e.FirstPort) + 1) * len(s.Bindings)
			}
		}
		if ruleCount > MaxRules || listenerCount > maxListeners {
			return invalid("rule_capacity")
		}
	}
	if err := dependencies(services); err != nil {
		return err
	}
	for i, a := range c.Services {
		if !a.Enabled {
			continue
		}
		for _, b := range c.Services[i+1:] {
			if !b.Enabled {
				continue
			}
			for _, ab := range a.Bindings {
				for _, bb := range b.Bindings {
					if ab.Interface != bb.Interface || ab.LocalAddress != bb.LocalAddress {
						continue
					}
					for _, ae := range a.Endpoints {
						for _, be := range b.Endpoints {
							if overlap(ae, be) {
								return invalid("listener_conflict")
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func validateService(s *Service, inventory map[string]Interface) error {
	switch s.Kind {
	case ManagementHTTPS, ManagementSSH, ManagementAPI, VPN, DNS, DHCP, NTP, CaptivePortal, ReverseProxy, WAF:
	default:
		return invalid("kind")
	}
	if s.Authentication != Authenticated && s.Authentication != ProtocolAuthentication && s.Authentication != NoAuthentication {
		return invalid("authentication")
	}
	if management(s.Kind) && (s.Authentication != Authenticated || !s.Lifecycle.ConfirmedManagementChanges) {
		return invalid("management_protection")
	}
	if !s.Lifecycle.VerifyListeners || !s.Lifecycle.VerifyRules || !s.Lifecycle.RevertOnFailure {
		return invalid("lifecycle")
	}
	if len(s.CompatibleZones) == 0 || len(s.CompatibleZones) > 3 {
		return invalid("compatible_zones")
	}
	slices.Sort(s.CompatibleZones)
	for i, z := range s.CompatibleZones {
		if !validZone(z) || (i > 0 && s.CompatibleZones[i-1] == z) {
			return invalid("compatible_zones")
		}
	}
	if len(s.Endpoints) == 0 || len(s.Endpoints) > 16 || len(s.Bindings) == 0 || len(s.Bindings) > 16 || len(s.DependsOn) > MaxServices {
		return invalid("service_capacity")
	}
	for i, e := range s.Endpoints {
		if (e.Protocol != TCP && e.Protocol != UDP) || e.FirstPort == 0 || e.LastPort < e.FirstPort {
			return invalid("endpoint")
		}
		if management(s.Kind) && e.Protocol != TCP {
			return invalid("management_protocol")
		}
		for _, other := range s.Endpoints[:i] {
			if overlap(e, other) {
				return invalid("overlapping_endpoints")
			}
		}
	}
	sort.Slice(s.Endpoints, func(i, j int) bool {
		a, b := s.Endpoints[i], s.Endpoints[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.FirstPort < b.FirstPort
	})
	bindings := map[string]bool{}
	for i := range s.Bindings {
		b := &s.Bindings[i]
		iface, ok := inventory[b.Interface]
		if !ok || b.Zone != iface.Zone || !slices.Contains(s.CompatibleZones, b.Zone) {
			return invalid("binding_interface_zone")
		}
		if (b.Zone == WAN) != b.WANOptIn {
			return invalid("wan_opt_in")
		}
		a, err := localAddress(b.LocalAddress)
		if err != nil {
			return err
		}
		b.LocalAddress = a.String()
		if !slices.Contains(iface.Addresses, b.LocalAddress) {
			return invalid("address_not_local")
		}
		key := b.Interface + "/" + b.LocalAddress
		if bindings[key] {
			return invalid("duplicate_binding")
		}
		bindings[key] = true
		if len(b.Sources) == 0 || len(b.Sources) > 64 {
			return invalid("sources")
		}
		prefixes := []netip.Prefix{}
		for j, text := range b.Sources {
			p, err := netip.ParsePrefix(text)
			if err != nil || p.Addr().Is4In6() || p.Addr().Is4() != a.Is4() || p.Bits() == 0 || p != p.Masked() || p.Addr().IsMulticast() {
				return invalid("source_prefix")
			}
			for _, previous := range prefixes {
				if p.Overlaps(previous) {
					return invalid("overlapping_sources")
				}
			}
			prefixes = append(prefixes, p)
			b.Sources[j] = p.String()
		}
		slices.Sort(b.Sources)
	}
	sort.Slice(s.Bindings, func(i, j int) bool {
		a, b := s.Bindings[i], s.Bindings[j]
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		return a.LocalAddress < b.LocalAddress
	})
	if s.DependsOn == nil {
		s.DependsOn = []string{}
	}
	slices.Sort(s.DependsOn)
	for i, id := range s.DependsOn {
		if !identifier.MatchString(id) || id == s.ID || (i > 0 && s.DependsOn[i-1] == id) {
			return invalid("dependency")
		}
	}
	return nil
}

func overlap(a, b Endpoint) bool {
	return a.Protocol == b.Protocol && a.FirstPort <= b.LastPort && b.FirstPort <= a.LastPort
}

func dependencies(services map[string]*Service) error {
	state := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 1 {
			return invalid("dependency_cycle")
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, dep := range services[id].DependsOn {
			d, ok := services[dep]
			if !ok {
				return invalid("missing_dependency")
			}
			if services[id].Enabled && !d.Enabled {
				return invalid("disabled_dependency")
			}
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	ids := make([]string, 0, len(services))
	for id := range services {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}
