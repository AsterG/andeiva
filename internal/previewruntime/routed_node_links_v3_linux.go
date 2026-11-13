//go:build linux

package previewruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"

	"github.com/AsterG/andeiva/internal/firewallipc"
	"github.com/AsterG/andeiva/internal/jsoncheck"
)

const routedNodeLinksPathV3 = "/etc/andeiva-preview/grouped-links.json"

type routedNodeParentV3 struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	MAC   string `json:"hardware_address"`
	MTU   int    `json:"mtu"`
}

func (p routedNodeParentV3) binding() RoutedParentLinkV3 {
	return RoutedParentLinkV3{Index: p.Index, Name: p.Name, MAC: p.MAC, MTU: p.MTU}
}

type routedNodeLinksV3 struct {
	Version  int                `json:"version"`
	Identity string             `json:"identity"`
	LAN      routedNodeParentV3 `json:"lan"`
	WAN      routedNodeParentV3 `json:"wan"`
}

func (p routedNodeLinksV3) validate() error {
	lan, wan := p.LAN.binding(), p.WAN.binding()
	if p.Version != 1 || !validHex(p.Identity, 16) || !validRoutedParentV3(lan) || !validRoutedParentV3(wan) || lan.Index == wan.Index || lan.Name == wan.Name || lan.MAC == wan.MAC {
		return ErrIdentity
	}
	return nil
}
func decodeRoutedNodeLinksV3(data []byte) (routedNodeLinksV3, error) {
	var p routedNodeLinksV3
	if len(data) == 0 || len(data) > 4096 || !jsoncheck.UniqueControlFields(data) || firewallipc.Decode(data, &p) != nil || p.validate() != nil {
		return p, ErrConfiguration
	}
	return p, nil
}

// PrepareRoutedNodeLinksV3 records node-local physical bindings only. It does
// not configure interfaces or start services. Re-running never replaces a key:
// the stable MAC identity is independent of a boot or supervisor incarnation.
func PrepareRoutedNodeLinksV3(ctx context.Context, c Config, input io.Reader) error {
	if ctx == nil || ctx.Err() != nil || input == nil || os.Getuid() != 0 || os.Geteuid() != 0 || c.Validate() != nil {
		return ErrIdentity
	}
	data, err := io.ReadAll(io.LimitReader(input, 4097))
	var request struct {
		Version int    `json:"version"`
		LAN     string `json:"lan"`
		WAN     string `json:"wan"`
	}
	if err != nil || len(data) > 4096 || !jsoncheck.UniqueControlFields(data) || firewallipc.Decode(data, &request) != nil || request.Version != 1 || !device.MatchString(request.LAN) || !device.MatchString(request.WAN) || request.LAN == request.WAN {
		return ErrConfiguration
	}
	parent := func(name string) (routedNodeParentV3, error) {
		v, e := net.InterfaceByName(name)
		if e != nil || v.Flags&net.FlagLoopback != 0 || v.Flags&net.FlagUp == 0 {
			return routedNodeParentV3{}, ErrIdentity
		}
		p := routedNodeParentV3{Index: v.Index, Name: v.Name, MAC: v.HardwareAddr.String(), MTU: v.MTU}
		if !validRoutedParentV3(p.binding()) {
			return routedNodeParentV3{}, ErrIdentity
		}
		return p, nil
	}
	lan, err := parent(request.LAN)
	if err != nil {
		return err
	}
	wan, err := parent(request.WAN)
	if err != nil {
		return err
	}
	var key [16]byte
	if _, err = rand.Read(key[:]); err != nil {
		return err
	}
	record := routedNodeLinksV3{Version: 1, Identity: hex.EncodeToString(key[:]), LAN: lan, WAN: wan}
	if record.validate() != nil || ctx.Err() != nil {
		return ErrIdentity
	}
	if safeParents(routedNodeLinksPathV3) != nil {
		return ErrIdentity
	}
	root, err := os.OpenRoot("/etc/andeiva-preview")
	if err != nil {
		return err
	}
	defer root.Close()
	if err = writeNew(root, "grouped-links.json", marshal(record), 0600, 0, 0); err != nil {
		return err
	}
	return syncDirectory(root.Name())
}
