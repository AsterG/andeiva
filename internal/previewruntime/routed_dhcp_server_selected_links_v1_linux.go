//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
	"github.com/AsterG/andeiva/internal/networkinventory"
	"github.com/AsterG/andeiva/internal/networkplan"
)

type routedDHCPServerSelectedLinkV1 struct {
	Index   uint32       `json:"index"`
	Name    string       `json:"name"`
	MAC     string       `json:"mac"`
	Address netip.Prefix `json:"address"`
}

// Read the selected LANs from the retained gateway, including the IPv4
// addresses on other links so a selected address cannot be used twice. The
// caller keeps the selection barrier and compares observations around launch.
func readRoutedDHCPServerSelectedLinksV1(ctx context.Context, m Metadata, gateway, host *os.File, plan routedDHCPServerBindingPlanV1) ([]routedDHCPServerSelectedLinkV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || m.SchemaVersion != RoutedMetadataSchemaVersion || m.ValidateRouted() != nil {
		return nil, ErrIdentity
	}
	const nsenter, ip = "/usr/bin/nsenter", "/usr/bin/ip"
	if trustedRoutedExecutableV3(nsenter) != nil || trustedRoutedExecutableV3(ip) != nil {
		return nil, ErrIdentity
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pinsMatch := func() bool {
		current, err := namespaceID("/proc/thread-self/ns/net")
		return err == nil && current == m.HostNamespace && routedLinkNamespaceV3(gateway, m.GatewayNamespace) && routedLinkNamespaceV3(host, m.HostNamespace)
	}
	if !pinsMatch() {
		return nil, ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// The full address dump includes links with no IPv4 address and their
	// hardware addresses. ip -4 may omit both from its JSON output.
	cmd := exec.CommandContext(call, nsenter, "--net=/proc/self/fd/3", "--", ip, "-j", "address", "show")
	cmd.ExtraFiles = []*os.File{gateway}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var out helperOutput
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil || call.Err() != nil {
		return nil, ErrUnavailable
	}
	if !pinsMatch() {
		return nil, ErrIdentity
	}
	return matchRoutedDHCPServerSelectedLinksV1(out.Bytes(), plan)
}

type routedDHCPServerObservedAddressV1 struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Bits      *int   `json:"prefixlen"`
	Scope     string `json:"scope"`
	Label     string `json:"label"`
	Valid     uint32 `json:"valid_life_time"`
	Preferred uint32 `json:"preferred_life_time"`
}

type routedDHCPServerObservedLinkV1 struct {
	Index     uint32                              `json:"ifindex"`
	Name      string                              `json:"ifname"`
	MAC       string                              `json:"address"`
	Flags     []string                            `json:"flags"`
	Addresses []routedDHCPServerObservedAddressV1 `json:"addr_info"`
}

func matchRoutedDHCPServerSelectedLinksV1(data []byte, plan routedDHCPServerBindingPlanV1) ([]routedDHCPServerSelectedLinkV1, error) {
	var links []routedDHCPServerObservedLinkV1
	if len(plan) == 0 || len(plan) > networkplan.MaxInterfaces || len(data) == 0 || len(data) > 512<<10 || !jsoncheck.UniqueControlFields(data) ||
		json.Unmarshal(data, &links) != nil || len(links) < len(plan) || len(links) > networkinventory.MaxInterfaces {
		return nil, ErrIdentity
	}
	byName := make(map[string]routedDHCPServerObservedLinkV1, len(links))
	indices := make(map[uint32]bool, len(links))
	macs := make(map[string]int, len(links))
	addressCount := make(map[netip.Addr]int)
	for _, link := range links {
		if link.Index == 0 || indices[link.Index] || byName[link.Name].Index != 0 || !device.MatchString(link.Name) ||
			len(link.Addresses) > networkinventory.MaxAddresses {
			return nil, ErrIdentity
		}
		indices[link.Index], byName[link.Name] = true, link
		macs[link.MAC]++
		for _, a := range link.Addresses {
			ip, err := netip.ParseAddr(a.Local)
			if err != nil || ip.Zone() != "" || a.Bits == nil || !netip.PrefixFrom(ip, *a.Bits).IsValid() {
				return nil, ErrIdentity
			}
			switch a.Family {
			case "inet":
				if !ip.Is4() {
					return nil, ErrIdentity
				}
				addressCount[ip]++
			case "inet6":
				if !ip.Is6() {
					return nil, ErrIdentity
				}
			default:
				return nil, ErrIdentity
			}
		}
	}
	selected := make([]routedDHCPServerSelectedLinkV1, 0, len(plan))
	seen := make(map[uint32]bool, len(plan))
	for _, scope := range plan {
		binding := scope.kea
		want := binding.Interface.Address
		link := byName[binding.Name]
		if link.Index == 0 || seen[link.Index] || link.MAC != scope.subnet.HardwareMAC || macs[link.MAC] != 1 ||
			!validDHCPSubnetBindingV1(scope.subnet) || binding.Interface.InterfaceID != scope.subnet.InterfaceID || binding.Interface.Role != string(networkplan.LAN) ||
			!containsRoutedLinkFlagV3(link.Flags, "UP") || !want.IsValid() || want.Masked().String() != scope.subnet.Subnet || addressCount[want.Addr()] != 1 {
			return nil, ErrIdentity
		}
		// Kea listens on the configured interface name. A second IPv4 address
		// there would widen its binding even with the expected address present.
		ipv4 := 0
		for _, a := range link.Addresses {
			if a.Family != "inet" {
				continue
			}
			ipv4++
			if a.Local != want.Addr().String() || *a.Bits != want.Bits() || a.Scope != "global" || a.Label != link.Name ||
				a.Valid != math.MaxUint32 || a.Preferred != math.MaxUint32 {
				return nil, ErrIdentity
			}
		}
		if ipv4 != 1 {
			return nil, ErrIdentity
		}
		seen[link.Index] = true
		selected = append(selected, routedDHCPServerSelectedLinkV1{Index: link.Index, Name: link.Name, MAC: link.MAC, Address: want})
	}
	return selected, nil
}
