//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/AsterG/andeiva/internal/previewnet"
)

const activationGroupedServiceV1 = "andeiva-preview-grouped.service"
const activationGroupedSocketV1 = "andeiva-preview-grouped.socket"
const activationClassicAPIV1 = "andeiva-preview-api.service"
const activationClassicSocketV1 = "andeiva-preview-api.socket"
const activationClassicHelperV1 = "andeiva-preview-helper.service"
const activationClassicNamespaceV1 = "andeiva-preview-namespaces.service"
const activationClassicTargetV1 = "andeiva-preview.target"

var activationClassicUnitsV1 = []string{activationClassicTargetV1, activationClassicSocketV1, activationClassicAPIV1, activationClassicHelperV1, activationClassicNamespaceV1}
var activationGroupedUnitsV1 = []string{activationGroupedServiceV1, activationGroupedSocketV1}

func activationSystemctlV1(ctx context.Context, action string, units ...string) ([]byte, error) {
	if ctx.Err() != nil || trustedRoutedExecutableV3("/usr/bin/systemctl") != nil || len(units) == 0 {
		return nil, ErrIdentity
	}
	args := []string{"--no-pager", "--no-ask-password", action}
	switch action {
	case "start", "stop", "mask", "unmask":
	case "show":
		args = append(args, "--all", "--property=LoadState,ActiveState,MainPID,ControlPID,ControlGroup")
	default:
		return nil, ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	args = append(append(args, "--"), units...)
	// #nosec G204 -- All units come from fixed installer constants and the action is allowlisted. No shell or request input.
	cmd := exec.CommandContext(call, "/usr/bin/systemctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	var output scopeRecoveryOutputV3
	cmd.Stdout = &output
	cmd.WaitDelay = 200 * time.Millisecond
	if cmd.Run() != nil || call.Err() != nil {
		return nil, ErrUnavailable
	}
	return output.Bytes(), nil
}

func activationUnitsDrainedV1(ctx context.Context, units []string, masked bool) error {
	for _, unit := range units {
		if masked {
			target, err := os.Readlink("/etc/systemd/system/" + unit) // #nosec G304 -- Fixed package unit passed by the installer.
			if err != nil || target != "/dev/null" {
				return ErrUnavailable
			}
		}
		raw, err := activationSystemctlV1(ctx, "show", unit)
		if err != nil || !activationUnitDrainedV1(string(raw), masked) {
			return ErrUnavailable
		}
	}
	return nil
}

func activationUnitDrainedV1(raw string, masked bool) bool {
	properties := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		name, value, ok := strings.Cut(line, "=")
		if _, exists := properties[name]; !ok || exists {
			return false
		}
		properties[name] = value
	}
	load := properties["LoadState"]
	active := properties["ActiveState"]
	if masked && load != "masked" || !masked && load != "masked" && load != "loaded" ||
		active != "inactive" && active != "failed" {
		return false
	}
	if properties["ControlGroup"] != "" {
		return false
	}
	for _, name := range []string{"MainPID", "ControlPID"} {
		if value := properties[name]; value != "" && value != "0" {
			return false
		}
	}
	return true
}

func activationHostClosedV1(node routedNodeLinksV3) error {
	host, err := namespaceID("/proc/self/ns/net")
	pid1, e := namespaceID("/proc/1/ns/net")
	thread, te := namespaceID("/proc/thread-self/ns/net")
	if err != nil || e != nil || te != nil || host != pid1 || host != thread {
		return ErrIdentity
	}
	paths := []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding", "/proc/sys/net/ipv6/conf/default/forwarding"}
	for _, link := range []routedNodeParentV3{node.LAN, node.WAN} {
		if !device.MatchString(link.Name) {
			return ErrIdentity
		}
		for _, entry := range []string{"bridge", "brport", "master"} {
			if _, err := os.Lstat("/sys/class/net/" + link.Name + "/" + entry); !errors.Is(err, os.ErrNotExist) {
				return ErrIdentity
			}
		}
		paths = append(paths, "/proc/sys/net/ipv6/conf/"+link.Name+"/forwarding", "/proc/sys/net/ipv4/conf/"+link.Name+"/forwarding")
	}
	for _, path := range paths {
		value, err := os.ReadFile(path) // #nosec G304 -- Fixed proc subtree, exact names and validated prepared device identifiers.
		if err != nil || strings.TrimSpace(string(value)) != "0" {
			return ErrIdentity
		}
	}
	return nil
}

func activationClassicGoneV1() error {
	for _, path := range []string{RuntimeDir + "/runtime.json", previewnet.NamespacePath, previewnet.ControlPath, HelperSocket, HealthSocket} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return ErrUnavailable
		}
	}
	return nil
}

func closeActivationClassicV1(ctx context.Context) error {
	if _, err := os.Lstat(RuntimeDir + "/runtime.json"); errors.Is(err, os.ErrNotExist) {
		return activationClassicGoneV1()
	}
	meta, err := ReadMetadata()
	if err != nil {
		return err
	}
	gateway, err := os.Open(previewnet.NamespacePath)
	if err != nil {
		return ErrIdentity
	}
	defer gateway.Close()
	if verifyRoutedMigrationScopeV3(gateway, meta, false) != nil || trustedRoutedExecutableV3("/usr/bin/nsenter") != nil ||
		trustedRoutedExecutableV3("/usr/sbin/sysctl") != nil {
		return ErrIdentity
	}
	call, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for _, op := range []scopeRecoveryNetworkOpV3{scopeRecoveryForwardCloseV3, scopeRecoveryForwardReadV3} {
		args, err := scopeRecoveryNetworkArgumentsV3(op)
		if err != nil {
			return err
		}
		// #nosec G204 -- Fixed read/close operations in the verified classic gateway, not the host.
		cmd := exec.CommandContext(call, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--"}, args...)...)
		cmd.ExtraFiles = []*os.File{gateway}
		cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
		var output scopeRecoveryOutputV3
		cmd.Stdout = &output
		if cmd.Run() != nil || op == scopeRecoveryForwardReadV3 && strings.Join(strings.Fields(string(output.Bytes())), " ") != "0 0 0 0" {
			return ErrUnavailable
		}
	}
	return nil
}
