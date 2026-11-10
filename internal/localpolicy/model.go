// Package localpolicy validates and compiles isolated local-service declarations.
// It performs no I/O, starts no listeners and does not apply firewall rules.
package localpolicy

import "errors"

const (
	SchemaVersion   = 1
	CompilerVersion = "andeiva.local.poc.v1"
	TableName       = "andeiva_local_poc"
	InputPriority   = 10
	MaxServices     = 64
	MaxRules        = 4096
)

var ErrPolicy = errors.New("local_policy_invalid")

type Zone string

const (
	LAN   Zone = "lan"
	WAN   Zone = "wan"
	Other Zone = "other"
)

type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

type Kind string

const (
	ManagementHTTPS Kind = "management_https"
	ManagementSSH   Kind = "management_ssh"
	ManagementAPI   Kind = "management_api"
	VPN             Kind = "vpn"
	DNS             Kind = "dns"
	DHCP            Kind = "dhcp"
	NTP             Kind = "ntp"
	CaptivePortal   Kind = "captive_portal"
	ReverseProxy    Kind = "reverse_proxy"
	WAF             Kind = "waf"
)

type Authentication string

const (
	Authenticated          Authentication = "required"
	ProtocolAuthentication Authentication = "protocol"
	NoAuthentication       Authentication = "none"
)

// Interface is supplied by trusted inventory, not inferred from an address.
// Changes to this inventory require the same authorization as service bindings.
type Interface struct {
	Name      string   `json:"name"`
	Zone      Zone     `json:"zone"`
	Addresses []string `json:"addresses"`
}

type Endpoint struct {
	Protocol  Protocol `json:"protocol"`
	FirstPort uint16   `json:"first_port"`
	LastPort  uint16   `json:"last_port"`
}

// Binding requires an exact interface and local address. Wildcards are excluded
// from this first compiler so a listener cannot silently expose other interfaces.
type Binding struct {
	Interface    string   `json:"interface"`
	Zone         Zone     `json:"zone"`
	LocalAddress string   `json:"local_address"`
	Sources      []string `json:"sources"`
	WANOptIn     bool     `json:"wan_opt_in"`
}

// Lifecycle records required deployment conditions, not evidence they occurred.
type Lifecycle struct {
	VerifyListeners            bool `json:"verify_listeners"`
	VerifyRules                bool `json:"verify_rules"`
	RevertOnFailure            bool `json:"revert_on_failure"`
	ConfirmedManagementChanges bool `json:"confirmed_management_changes"`
}

type Service struct {
	ID              string         `json:"id"`
	Owner           string         `json:"owner"`
	Kind            Kind           `json:"kind"`
	Enabled         bool           `json:"enabled"`
	CompatibleZones []Zone         `json:"compatible_zones"`
	Authentication  Authentication `json:"authentication"`
	DependsOn       []string       `json:"depends_on"`
	Endpoints       []Endpoint     `json:"endpoints"`
	Bindings        []Binding      `json:"bindings"`
	Lifecycle       Lifecycle      `json:"lifecycle"`
}

type Config struct {
	SchemaVersion int         `json:"schema_version"`
	Interfaces    []Interface `json:"interfaces"`
	Services      []Service   `json:"services"`
}

type Revision struct {
	Hash   string `json:"hash"`
	Config Config `json:"config"`
}

// EffectiveRule is generated, never accepted as editable policy input.
// It describes intended rules; kernel observation is a separate future adapter.
type EffectiveRule struct {
	ID           string   `json:"id"`
	Revision     string   `json:"revision"`
	Owner        string   `json:"owner"`
	Service      string   `json:"service"`
	Management   bool     `json:"management"`
	Interface    string   `json:"interface"`
	Zone         Zone     `json:"zone"`
	Family       string   `json:"family"`
	LocalAddress string   `json:"local_address"`
	Source       string   `json:"source"`
	Endpoint     Endpoint `json:"endpoint"`
	Action       string   `json:"action"`
	Origin       string   `json:"origin"`
}

type Artifact struct {
	Revision Revision        `json:"revision"`
	Rules    []EffectiveRule `json:"rules"`
	Digest   string          `json:"digest"`
	Create   []byte          `json:"create"`
}

func management(k Kind) bool {
	return k == ManagementHTTPS || k == ManagementSSH || k == ManagementAPI
}

// DefaultManagement declares HTTPS on an explicit LAN address and explicit
// sources. It neither enables access to an entire LAN nor starts the service.
func DefaultManagement(owner, id string, lan Interface, local string, sources []string) (Service, error) {
	if lan.Zone != LAN {
		return Service{}, ErrPolicy
	}
	s := Service{ID: id, Owner: owner, Kind: ManagementHTTPS, Enabled: true,
		CompatibleZones: []Zone{LAN, WAN, Other}, Authentication: Authenticated,
		Endpoints: []Endpoint{{TCP, 443, 443}},
		Bindings:  []Binding{{Interface: lan.Name, Zone: LAN, LocalAddress: local, Sources: append([]string(nil), sources...)}},
		Lifecycle: Lifecycle{true, true, true, true}}
	r, err := Canonical(Config{SchemaVersion: SchemaVersion, Interfaces: []Interface{lan}, Services: []Service{s}})
	if err != nil {
		return Service{}, err
	}
	return r.Config.Services[0], nil
}
