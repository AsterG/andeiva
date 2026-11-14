//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/jsoncheck"
)

type scopeRecoveryNetworkOpV3 uint8

const (
	scopeRecoveryForwardCloseV3 scopeRecoveryNetworkOpV3 = iota
	scopeRecoveryForwardReadV3
	scopeRecoveryLinksReadV3
	scopeRecoveryWANRemoveV3
	scopeRecoveryLANRemoveV3
)

func scopeRecoveryNetworkArgumentsV3(op scopeRecoveryNetworkOpV3) ([]string, error) {
	switch op {
	case scopeRecoveryForwardCloseV3:
		return []string{"/usr/sbin/sysctl", "-qw", "net.ipv4.ip_forward=0", "net.ipv4.conf.default.forwarding=0", "net.ipv6.conf.all.forwarding=0", "net.ipv6.conf.default.forwarding=0"}, nil
	case scopeRecoveryForwardReadV3:
		return []string{"/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward", "net.ipv4.conf.default.forwarding", "net.ipv6.conf.all.forwarding", "net.ipv6.conf.default.forwarding"}, nil
	case scopeRecoveryLinksReadV3:
		return []string{"/usr/bin/ip", "-d", "-j", "link", "show"}, nil
	case scopeRecoveryWANRemoveV3:
		return []string{"/usr/bin/ip", "link", "delete", "dev", "wan0"}, nil
	case scopeRecoveryLANRemoveV3:
		return []string{"/usr/bin/ip", "link", "delete", "dev", "lan0"}, nil
	default:
		return nil, ErrIdentity
	}
}
func runScopeRecoveryNetworkV3(ctx context.Context, gateway *os.File, m Metadata, op scopeRecoveryNetworkOpV3) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || m.ValidateRouted() != nil || gateway == nil || !routedLinkNamespaceV3(gateway, m.GatewayNamespace) {
		return nil, ErrIdentity
	}
	host, err := namespaceID("/proc/self/ns/net")
	if err != nil || host != m.HostNamespace {
		return nil, ErrIdentity
	}
	args, err := scopeRecoveryNetworkArgumentsV3(op)
	if err != nil || len(args) == 0 || trustedRoutedExecutableV3("/usr/bin/nsenter") != nil || trustedRoutedExecutableV3(args[0]) != nil {
		return nil, ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--"}, args...)...) // #nosec G204 -- Closed operation enum selects fixed programs/arguments inside an authenticated nonhost namespace FD.
	cmd.ExtraFiles = []*os.File{gateway}
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 200 * time.Millisecond
	var output scopeRecoveryOutputV3
	cmd.Stdout = &output
	runtime.LockOSThread()
	err = cmd.Run()
	runtime.UnlockOSThread()
	if err != nil || call.Err() != nil {
		return nil, ErrUnavailable
	}
	return output.Bytes(), nil
}
func scopeRecoveryLinksV3(raw []byte) (map[string]routedLinkObservationV3, error) {
	if len(raw) == 0 || len(raw) > 32768 || !jsoncheck.UniqueFields(raw) {
		return nil, ErrIdentity
	}
	var links []routedLinkObservationV3
	if json.Unmarshal(raw, &links) != nil || len(links) < 1 || len(links) > 3 {
		return nil, ErrIdentity
	}
	found := map[string]routedLinkObservationV3{}
	indexes := map[int]bool{}
	for _, link := range links {
		if _, ok := found[link.Name]; ok || indexes[link.Index] || link.Index <= 0 {
			return nil, ErrIdentity
		}
		indexes[link.Index] = true
		if link.Name == "lo" {
			if !containsRoutedLinkFlagV3(link.Flags, "LOOPBACK") {
				return nil, ErrIdentity
			}
		} else {
			if (link.Name != "lan0" && link.Name != "wan0") || !validRoutedParentV3(RoutedParentLinkV3{Index: link.Index, Name: link.Name, MAC: link.MAC, MTU: link.MTU}) || link.Parent <= 0 || link.Info.Kind != "macvlan" || link.Info.Data.Mode != "private" || link.Promiscuity != 0 {
				return nil, ErrIdentity
			}
		}
		// Carrier/UP flags may change with physical link state. They are not ownership.
		link.Flags = nil
		found[link.Name] = link
	}
	if _, ok := found["lo"]; !ok {
		return nil, ErrIdentity
	}
	return found, nil
}

// Scope ownership comes from retained Root anchors + current selected work, not
// matching IP/MAC values. This adapter retires that whole exclusive namespace;
// it does not adopt links into the static executor or reopen forwarding.
func closeScopeRecoveryNetworkV3(ctx context.Context, run func(context.Context, scopeRecoveryNetworkOpV3) ([]byte, error)) error {
	if ctx == nil || ctx.Err() != nil || run == nil {
		return ErrIdentity
	}
	if _, err := run(ctx, scopeRecoveryForwardCloseV3); err != nil {
		return err
	}
	raw, err := run(ctx, scopeRecoveryForwardReadV3)
	if err != nil || string(raw) != "0\n0\n0\n0\n" {
		return ErrIdentity
	}
	raw, err = run(ctx, scopeRecoveryLinksReadV3)
	if err != nil {
		return err
	}
	links, err := scopeRecoveryLinksV3(raw)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		op   scopeRecoveryNetworkOpV3
	}{{"wan0", scopeRecoveryWANRemoveV3}, {"lan0", scopeRecoveryLANRemoveV3}} {
		if _, ok := links[item.name]; !ok {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err = run(ctx, item.op); err != nil {
			return err
		}
		raw, err = run(ctx, scopeRecoveryLinksReadV3)
		if err != nil {
			return err
		}
		actual, e := scopeRecoveryLinksV3(raw)
		if e != nil {
			return e
		}
		delete(links, item.name)
		if !reflect.DeepEqual(actual, links) {
			return ErrIdentity
		}
	}
	if len(links) != 1 {
		return ErrIdentity
	}
	raw, err = run(ctx, scopeRecoveryForwardReadV3)
	if err != nil || string(raw) != "0\n0\n0\n0\n" || ctx.Err() != nil {
		return ErrIdentity
	}
	return nil
}
