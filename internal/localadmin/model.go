// Package localadmin admits authenticated local-service operations to the single
// configuration coordinator. It contains no transport or privileged operations.
package localadmin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"time"

	"github.com/AsterG/andeiva/internal/configpoc"
	"github.com/AsterG/andeiva/internal/firewalladmin"
	"github.com/AsterG/andeiva/internal/localnft"
	"github.com/AsterG/andeiva/internal/localpolicy"
)

// Context must be built by the authenticated server adapter, never decoded from
// caller JSON or headers. EndpointID identifies the actual receiving listener.
type Context struct {
	Principal   configpoc.Principal
	Surface     configpoc.Surface
	SessionHash string
	EndpointID  string
}

type Request struct {
	Transaction    configpoc.Request `json:"transaction"`
	RecoveryProof  string            `json:"recovery_proof,omitempty"`
	EndpointProofs []string          `json:"endpoint_proofs,omitempty"`
}

type ProofRequest struct {
	Generation uint64 `json:"generation"`
	Target     string `json:"target"`
	Lease      string `json:"lease"`
}

type Proof struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ObservedState is supplied only by a trusted runtime collector which verifies
// actual rule expressions and listener ownership in the owned namespace.
type ObservedState struct {
	Hash  string                  `json:"hash"`
	Local localpolicy.Observation `json:"local"`
}

type EffectiveObserver interface {
	Observe(context.Context) (ObservedState, error)
}

type Options struct {
	RunID              string
	RecoveryEndpointID string
	Inventory          []localpolicy.Interface
	Authority          firewalladmin.LeaseAuthority
	Observer           EffectiveObserver
}

type Effective struct {
	Hash             string                      `json:"hash"`
	Phase            string                      `json:"phase"`
	RecoveryRequired bool                        `json:"recovery_required"`
	Rules            []localpolicy.EffectiveRule `json:"rules"`
	Listeners        []localpolicy.Listener      `json:"listeners"`
}

type Status struct {
	Snapshot  configpoc.Snapshot `json:"snapshot"`
	Effective Effective          `json:"effective"`
}

type Filter struct {
	Service   string `json:"service,omitempty"`
	Interface string `json:"interface,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Port      uint16 `json:"port,omitempty"`
	Source    string `json:"source,omitempty"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func validHex(s string, size int) bool {
	if len(s) != size*2 {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == size && hex.EncodeToString(b) == s
}

func validContext(c Context) bool {
	return identifier.MatchString(c.Principal.ID) && c.Principal.ID != "system" &&
		(c.Principal.Role == configpoc.RoleAdmin || c.Principal.Role == configpoc.RoleViewer) &&
		(c.Surface == configpoc.Web || c.Surface == configpoc.CLI || c.Surface == configpoc.API) &&
		validHex(c.SessionHash, 32) && (identifier.MatchString(c.EndpointID) || validBindingID(c.EndpointID))
}

func validBindingID(id string) bool {
	return len(id) == 72 && id[:8] == "binding-" && validHex(id[8:], 32)
}

func BindingEndpointID(l localpolicy.Listener) string {
	b, _ := json.Marshal(l)
	h := sha256.Sum256(b)
	return "binding-" + hex.EncodeToString(h[:])
}

func copyValue[T any](v T) T {
	b, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}

func validateProfile(c configpoc.Config, inventory []localpolicy.Interface) error {
	r, err := configpoc.Canonical(c)
	if err != nil || len(r.Config.Rules) != 0 || r.Config.DefaultAction != "deny" {
		return configpoc.ErrInvalid
	}
	if r.Config.SchemaVersion != 3 {
		return nil
	}
	l := *r.Config.LocalServices
	if localnft.ValidateManaged(l) != nil {
		return configpoc.ErrInvalid
	}
	a, _ := json.Marshal(l.Interfaces)
	b, _ := json.Marshal(inventory)
	if string(a) != string(b) {
		return configpoc.ErrInvalid
	}
	for _, service := range l.Services {
		if service.Owner != "management" ||
			(service.ID == "https" && service.Kind != localpolicy.ManagementHTTPS) ||
			(service.ID == "ssh" && service.Kind != localpolicy.ManagementSSH) ||
			(service.ID != "https" && service.ID != "ssh") {
			return configpoc.ErrInvalid
		}
	}
	return nil
}

func expectedListeners(c configpoc.Config) []localpolicy.Listener {
	result := []localpolicy.Listener{}
	if c.LocalServices == nil {
		return result
	}
	for _, s := range c.LocalServices.Services {
		if !s.Enabled {
			continue
		}
		for _, b := range s.Bindings {
			e := s.Endpoints[0]
			result = append(result, localpolicy.Listener{Owner: s.Owner, Service: s.ID, Interface: b.Interface, LocalAddress: b.LocalAddress, Protocol: e.Protocol, Port: e.FirstPort})
		}
	}
	return result
}

func validateFilter(f Filter, inventory []localpolicy.Interface) error {
	if f.Service != "" && f.Service != "https" && f.Service != "ssh" {
		return configpoc.ErrInvalid
	}
	if f.Protocol != "" && f.Protocol != "tcp" && f.Protocol != "udp" {
		return configpoc.ErrInvalid
	}
	if f.Interface != "" && !slices.ContainsFunc(inventory, func(i localpolicy.Interface) bool { return i.Name == f.Interface }) {
		return configpoc.ErrInvalid
	}
	if f.Source != "" {
		p, err := netip.ParsePrefix(f.Source)
		if err != nil || p != p.Masked() || p.String() != f.Source || p.Addr().Is4In6() {
			return configpoc.ErrInvalid
		}
	}
	return nil
}

// FilterEffective performs exact matching. A source filter applies to rules;
// listeners have no source-prefix observation and are omitted for that filter.
func FilterEffective(e Effective, f Filter, inventory []localpolicy.Interface) (Effective, error) {
	if err := validateFilter(f, inventory); err != nil {
		return Effective{}, err
	}
	out := Effective{Hash: e.Hash, Phase: e.Phase, RecoveryRequired: e.RecoveryRequired, Rules: []localpolicy.EffectiveRule{}, Listeners: []localpolicy.Listener{}}
	for _, r := range e.Rules {
		if (f.Service == "" || r.Service == f.Service) && (f.Interface == "" || r.Interface == f.Interface) &&
			(f.Protocol == "" || string(r.Endpoint.Protocol) == f.Protocol) && (f.Port == 0 || f.Port >= r.Endpoint.FirstPort && f.Port <= r.Endpoint.LastPort) &&
			(f.Source == "" || r.Source == f.Source) {
			out.Rules = append(out.Rules, r)
		}
	}
	for _, l := range e.Listeners {
		if f.Source == "" && (f.Service == "" || l.Service == f.Service) && (f.Interface == "" || l.Interface == f.Interface) &&
			(f.Protocol == "" || string(l.Protocol) == f.Protocol) && (f.Port == 0 || l.Port == f.Port) {
			out.Listeners = append(out.Listeners, l)
		}
	}
	return out, nil
}
