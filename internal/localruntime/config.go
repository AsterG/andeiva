// Package localruntime composes the explicitly authorized local-services laboratory.
package localruntime

import (
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/AsterG/andeiva/internal/localchannel"
)

var ErrUnavailable = errors.New("ANDEIVA_LOCAL_LAB_UNAVAILABLE")

const RecoveryPort = 18443
const MaxResets = 3
const maxBootstrap = 65536
const recoveryID = "local-lab-recovery"

var namePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
var directoryPattern = regexp.MustCompile(`^andeiva-local-[a-z0-9-]{8,40}$`)
var bootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Config struct {
	LANAddress   string `json:"lan_address"`
	LANInterface string `json:"lan_interface"`
	AllowedCIDR  string `json:"allowed_cidr"`
	APIUser      string `json:"api_user"`
	APIGroup     string `json:"api_group"`
	HelperUser   string `json:"helper_user"`
	HelperGroup  string `json:"helper_group"`
	WebRoot      string `json:"web_root"`
}

func (c Config) Validate() error {
	a, e := netip.ParseAddr(c.LANAddress)
	p, pe := netip.ParsePrefix(c.AllowedCIDR)
	if e != nil || !a.Is4() || a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.String() != c.LANAddress || pe != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 || p.String() != c.AllowedCIDR || !interfacePattern.MatchString(c.LANInterface) || c.LANInterface == "lo" || !filepath.IsAbs(c.WebRoot) || filepath.Clean(c.WebRoot) != c.WebRoot {
		return ErrUnavailable
	}
	for _, n := range []string{c.APIUser, c.APIGroup, c.HelperUser, c.HelperGroup} {
		if !namePattern.MatchString(n) {
			return ErrUnavailable
		}
	}
	if c.APIUser == c.HelperUser || c.APIGroup == c.HelperGroup {
		return ErrUnavailable
	}
	return nil
}

type identities struct{ APIUID, APIGID, HelperUID, HelperGID uint32 }

func (i identities) valid() bool {
	return i.APIUID > 0 && i.APIGID > 0 && i.HelperUID > 0 && i.HelperGID > 0 && i.APIUID != i.HelperUID && i.APIGID != i.HelperGID && i.APIUID <= 2147483647 && i.APIGID <= 2147483647 && i.HelperUID <= 2147483647 && i.HelperGID <= 2147483647
}
func parseID(s string) (uint32, error) {
	v, e := strconv.ParseUint(s, 10, 31)
	if e != nil || v == 0 {
		return 0, ErrUnavailable
	}
	return uint32(v), nil
}
func validDirectory(dir string) bool {
	return filepath.IsAbs(dir) && filepath.Clean(dir) == dir && filepath.Dir(dir) == "/var/tmp" && directoryPattern.MatchString(filepath.Base(dir))
}

type launch struct {
	Directory string               `json:"directory"`
	Config    Config               `json:"config"`
	IDs       identities           `json:"identities"`
	Binding   localchannel.Binding `json:"binding"`
	Host      uint64               `json:"host"`
	BootID    string               `json:"boot_id"`
}

func (l launch) valid() bool {
	return validDirectory(l.Directory) && l.Config.Validate() == nil && l.IDs.valid() && l.Binding.UID == l.IDs.APIUID && l.Binding.Namespace > 0 && l.Binding.Namespace != l.Host && l.Host > 0 && l.Binding.Generation > 0 && len(l.Binding.Run) == 32 && len(l.Binding.Instance) == 32 && bootPattern.MatchString(l.BootID)
}
