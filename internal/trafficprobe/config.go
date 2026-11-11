// Package trafficprobe provides bounded, explicitly targeted laboratory probes.
// It does not configure networking or determine a firewall policy verdict.
package trafficprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Mode string

const (
	TCP           Mode = "tcp"
	UDP           Mode = "udp-echo"
	DNS           Mode = "dns-a"
	HTTP          Mode = "http-head"
	MaxTimeout         = 15 * time.Second
	MaxTransports      = 16
	MaxAnswers         = 32
)

type Config struct {
	AuthorizedLab bool
	Mode          Mode
	SourceIPv4    netip.Addr
	TargetIPv4    netip.Addr
	TargetPort    uint16
	Timeout       time.Duration
	DNSName       string
	URL           string
	CAFile        string
}

type Transport struct {
	Protocol      string `json:"protocol"`
	Connected     bool   `json:"connected"`
	LocalPort     uint16 `json:"local_port,omitempty"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

type Result struct {
	SchemaVersion    int          `json:"schema_version"`
	StartedAtUTC     time.Time    `json:"started_at_utc,omitzero"`
	Mode             Mode         `json:"mode,omitempty"`
	Outcome          string       `json:"outcome"`
	SourceIPv4       netip.Addr   `json:"source_ipv4"`
	TargetIPv4       netip.Addr   `json:"target_ipv4"`
	TargetPort       uint16       `json:"target_port"`
	ElapsedMicros    int64        `json:"elapsed_micros"`
	Transports       []Transport  `json:"transports"`
	ResolvedIPv4     []netip.Addr `json:"resolved_ipv4,omitempty"`
	ResolutionSource string       `json:"resolution_source,omitempty"`
	HTTPStatus       int          `json:"http_status,omitempty"`
	Scheme           string       `json:"scheme,omitempty"`
	TLSVerified      bool         `json:"tls_verified"`
}

// Observed reports success within the stated probe scope, never a policy verdict
// or the provenance of addresses returned by the system resolver.
func (r Result) Observed() bool {
	return r.Outcome == "connected" || r.Outcome == "echo_verified" || r.Outcome == "resolved_with_dns_io" || r.Outcome == "http_response"
}

var errInvalid = errors.New("probe_invalid")

func validIPv4(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsUnspecified() && !ip.IsMulticast() && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func validate(c Config) (*url.URL, error) {
	if !c.AuthorizedLab || !validIPv4(c.SourceIPv4) || !validIPv4(c.TargetIPv4) || c.TargetPort == 0 || c.Timeout <= 0 || c.Timeout > MaxTimeout {
		return nil, errInvalid
	}
	switch c.Mode {
	case TCP, UDP:
		if c.DNSName != "" || c.URL != "" || c.CAFile != "" {
			return nil, errInvalid
		}
	case DNS:
		if !validDomain(c.DNSName) || c.URL != "" || c.CAFile != "" {
			return nil, errInvalid
		}
	case HTTP:
		if c.DNSName != "" {
			return nil, errInvalid
		}
		parsed, err := url.Parse(c.URL)
		if err != nil || len(c.URL) > 2048 || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || strings.HasSuffix(parsed.Host, ":") {
			return nil, errInvalid
		}
		for _, r := range c.URL {
			if r <= 32 || r == 127 {
				return nil, errInvalid
			}
		}
		host := parsed.Hostname()
		if ip, err := netip.ParseAddr(host); err == nil {
			if ip != c.TargetIPv4 {
				return nil, errInvalid
			}
		} else if !validDomain(host) {
			return nil, errInvalid
		}
		port := uint64(80)
		if parsed.Scheme == "https" {
			port = 443
		}
		if raw := parsed.Port(); raw != "" {
			port, err = strconv.ParseUint(raw, 10, 16)
			if err != nil || raw != strconv.FormatUint(port, 10) {
				return nil, errInvalid
			}
		}
		if port != uint64(c.TargetPort) || (parsed.Scheme == "http" && c.CAFile != "") {
			return nil, errInvalid
		}
		if c.CAFile != "" && (!filepath.IsAbs(c.CAFile) || filepath.Clean(c.CAFile) != c.CAFile) {
			return nil, errInvalid
		}
		return parsed, nil
	default:
		return nil, errInvalid
	}
	return nil, nil
}

func validDomain(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '-' {
				allNumeric = false
				continue
			}
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return !allNumeric
}

func localSource(ctx context.Context, source netip.Addr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil || len(addresses) > 4096 {
		return errors.New("probe_source_unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, raw := range addresses {
		address, ok := raw.(*net.IPNet)
		if !ok || address == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(address.IP)
		if ok && ip.Unmap() == source {
			return nil
		}
	}
	return errors.New("probe_source_not_local")
}
