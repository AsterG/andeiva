// Package previewruntime hosts the persistent, isolated appliance preview.
package previewruntime

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

const ConfigPath = "/etc/andeiva-preview/config.json"
const DataDir = "/var/lib/andeiva-preview"
const RuntimeDir = "/run/andeiva-preview"
const HelperSocket = "/run/andeiva-preview-helper/helper.sock"
const HealthSocket = "/run/andeiva-preview-api/health.sock"
const WebRoot = "/usr/share/andeiva-preview/web"

var ErrConfiguration = errors.New("ANDEIVA_PREVIEW_CONFIGURATION")
var ErrIdentity = errors.New("ANDEIVA_PREVIEW_IDENTITY")
var ErrUnavailable = errors.New("ANDEIVA_PREVIEW_UNAVAILABLE")
var ErrStorage = errors.New("ANDEIVA_PREVIEW_STORAGE")
var name = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var device = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
var bootPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type Config struct {
	SchemaVersion int    `json:"schema_version"`
	ListenAddress string `json:"listen_address"`
	Interface     string `json:"interface"`
	AllowedCIDR   string `json:"allowed_cidr"`
	APIUser       string `json:"api_user"`
	HelperUser    string `json:"helper_user"`
	IPCGroup      string `json:"ipc_group"`
}

func (c Config) Validate() error {
	a, e := netip.ParseAddrPort(c.ListenAddress)
	p, pe := netip.ParsePrefix(c.AllowedCIDR)
	if c.SchemaVersion != 1 || e != nil || !a.Addr().Is4() || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Port() == 0 || a.String() != c.ListenAddress || pe != nil || !p.Addr().Is4() || p != p.Masked() || p.String() != c.AllowedCIDR || !device.MatchString(c.Interface) || !name.MatchString(c.APIUser) || !name.MatchString(c.HelperUser) || !name.MatchString(c.IPCGroup) || c.APIUser == c.HelperUser {
		return ErrConfiguration
	}
	return nil
}
func (c Config) Origin() string { return "https://" + c.ListenAddress }

type Identities struct {
	SchemaVersion int    `json:"schema_version"`
	APIUID        uint32 `json:"api_uid"`
	APIGID        uint32 `json:"api_gid"`
	HelperUID     uint32 `json:"helper_uid"`
	IPCGID        uint32 `json:"ipc_gid"`
}

func (i Identities) Validate() error {
	if i.SchemaVersion != 1 || i.APIUID == 0 || i.APIGID == 0 || i.HelperUID == 0 || i.IPCGID == 0 || i.APIGID == i.IPCGID || i.APIUID == i.HelperUID {
		return ErrIdentity
	}
	return nil
}

type Metadata struct {
	SchemaVersion    int    `json:"schema_version"`
	RunID            string `json:"run_id"`
	BootID           string `json:"boot_id"`
	HostNamespace    uint64 `json:"host_namespace"`
	GatewayNamespace uint64 `json:"gateway_namespace"`
	SourceNamespace  uint64 `json:"source_namespace"`
	SinkNamespace    uint64 `json:"sink_namespace"`
}

func (m Metadata) Validate() error {
	if m.SchemaVersion != 1 || !validHex(m.RunID, 16) || !bootPattern.MatchString(m.BootID) {
		return ErrConfiguration
	}
	seen := map[uint64]bool{}
	for _, v := range []uint64{m.HostNamespace, m.GatewayNamespace, m.SourceNamespace, m.SinkNamespace} {
		if v == 0 || seen[v] {
			return ErrConfiguration
		}
		seen[v] = true
	}
	return nil
}
func canonicalBoot(b []byte) (string, error) {
	s := strings.TrimSpace(string(b))
	if !bootPattern.MatchString(s) {
		return "", ErrConfiguration
	}
	return s, nil
}
