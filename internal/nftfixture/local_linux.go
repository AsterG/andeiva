package nftfixture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

func (f *Fixture) localSetupCommands() []setupCommand {
	commands := []setupCommand{}
	for _, role := range []string{"source", "gateway", "sink"} {
		commands = append(commands, setupCommand{role, ipPath, []string{"link", "set", "lo", "up"}, "", ""})
	}
	for _, link := range localLinks() {
		commands = append(commands,
			setupCommand{"gateway", ipPath, []string{"link", "add", link.gateway, "type", "veth", "peer", "name", link.dev}, "", ""},
			setupCommand{"gateway", ipPath, []string{"link", "set", link.dev, "netns", "/proc/self/fd/4"}, link.role, ""})
		for _, device := range []struct{ role, dev string }{{"gateway", link.gateway}, {link.role, link.dev}} {
			commands = append(commands, setupCommand{device.role, ipPath, []string{"link", "set", "dev", device.dev, "addrgenmode", "none"}, "", ""})
		}
		for _, address := range []struct{ role, dev, address, family string }{
			{"gateway", link.gateway, link.gateway4 + "/29", "4"}, {link.role, link.dev, link.address4 + "/29", "4"}, {link.role, link.dev, link.alternate4 + "/29", "4"},
			{"gateway", link.gateway, link.gateway6 + "/64", "6"}, {"gateway", link.gateway, link.gatewayLinkLocal + "/64", "6"},
			{link.role, link.dev, link.address6 + "/64", "6"}, {link.role, link.dev, link.alternate6 + "/64", "6"}, {link.role, link.dev, link.linkLocal + "/64", "6"},
		} {
			args := []string{"-" + address.family, "address", "add", address.address, "dev", address.dev}
			// Addresses belong to this fresh isolated fixture; avoid a DAD timer
			// race before its explicitly scoped ND policy is installed.
			if address.family == "6" {
				args = append(args, "nodad")
			}
			commands = append(commands, setupCommand{address.role, ipPath, args, "", ""})
		}
		commands = append(commands, setupCommand{"gateway", ipPath, []string{"link", "set", link.gateway, "up"}, "", ""}, setupCommand{link.role, ipPath, []string{"link", "set", link.dev, "up"}, "", ""})
	}
	return append(commands, setupCommand{"gateway", nftPath, []string{"-f", "-"}, "", "add table inet andeiva_sentinel\n"})
}

func (f *Fixture) allowedLocalCommand(role string, args []string) bool {
	if role == "gateway" {
		if slices.Equal(args, []string{"--nft-fixture", "listen-gateway", strconv.FormatUint(f.host, 10)}) || slices.Equal(args, []string{"--nft-fixture", "check-local", strconv.FormatUint(f.host, 10)}) {
			return true
		}
		return slices.Equal(args, []string{"--local-services", strconv.FormatUint(f.host, 10), strconv.Itoa(os.Getpid())})
	}
	p, host, err := parseLocalProbe(args)
	return err == nil && host == f.host && role == p.Side
}

func (f *Fixture) checkLocalMode(ctx context.Context) error {
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd, err := f.command(deadline, "gateway", f.self, []string{"--nft-fixture", "check-local", strconv.FormatUint(f.host, 10)}, "", true, false)
	if err != nil {
		return err
	}
	_, err = runBounded(deadline, cmd, "")
	return err
}

func localNeighborCommands() []setupCommand {
	commands := []setupCommand{}
	for _, link := range localLinks() {
		for _, device := range []struct{ role, dev string }{{"gateway", link.gateway}, {link.role, link.dev}} {
			for _, family := range []string{"-4", "-6"} {
				commands = append(commands, setupCommand{device.role, ipPath, []string{family, "neigh", "flush", "dev", device.dev}, "", ""})
			}
		}
	}
	return commands
}

// ClearLocalNeighbors removes only caches of the four owned veths, for cold
// neighbor tests. It changes no addresses, rules, forwarding settings or routes.
func (f *Fixture) ClearLocalNeighbors(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.localOnly {
		return errors.New("ANDEIVA_NFT_FIXTURE_MODE")
	}
	for _, plan := range localNeighborCommands() {
		if _, err := f.run(ctx, plan.role, plan.binary, plan.args, "", ""); err != nil {
			return err
		}
	}
	return nil
}

func checkLocalIsolation() error {
	for index := range 6 {
		data, err := localForwardingFlag(index)
		if err != nil || strings.TrimSpace(string(data)) != "0" {
			return errors.New("ANDEIVA_NFT_LOCAL_FORWARDING_ENABLED")
		}
	}
	return nil
}

func localForwardingFlag(index int) ([]byte, error) {
	switch index {
	case 0:
		return os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	case 1:
		return os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	case 2:
		return os.ReadFile("/proc/sys/net/ipv4/conf/src0/forwarding")
	case 3:
		return os.ReadFile("/proc/sys/net/ipv4/conf/dst0/forwarding")
	case 4:
		return os.ReadFile("/proc/sys/net/ipv6/conf/src0/forwarding")
	case 5:
		return os.ReadFile("/proc/sys/net/ipv6/conf/dst0/forwarding")
	default:
		return nil, errors.New("ANDEIVA_NFT_LOCAL_FORWARDING_QUERY")
	}
}

// GuardLocalServices checks the fixed unprivileged runtime child before it may
// process requests. FD3 must remain the retained gateway namespace descriptor.
func GuardLocalServices(host uint64, supervisor int) error {
	if supervisor <= 1 || os.Getppid() != supervisor {
		return errors.New("ANDEIVA_NFT_FIXTURE_ORPHAN")
	}
	if err := armParentDeath(host); err != nil {
		return err
	}
	if os.Getppid() != supervisor {
		return errors.New("ANDEIVA_NFT_FIXTURE_ORPHAN")
	}
	return checkLocalIsolation()
}

// StartLocalServices starts this executable's fixed runtime role, without any
// capabilities. The caller implements --local-services and calls its guard.
func (f *Fixture) StartLocalServices(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) (*exec.Cmd, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.localOnly {
		return nil, errors.New("ANDEIVA_NFT_FIXTURE_MODE")
	}
	cmd, err := f.command(ctx, "gateway", f.self, []string{"--local-services", strconv.FormatUint(f.host, 10), strconv.Itoa(os.Getpid())}, "", true, false)
	if err != nil {
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	f.children = append(f.children, child{cmd, nil})
	return cmd, nil
}

// StartLocalEcho is an explicit TCP/UDP transport fixture, not a service engine.
// It is not started by NewLocalOwned and uses only the three fixed test ports.
func (f *Fixture) StartLocalEcho(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.localOnly {
		return errors.New("ANDEIVA_NFT_FIXTURE_MODE")
	}
	return f.startListenerRole(ctx, "gateway", "listen-gateway")
}

func (f *Fixture) ProbeLocalGateway(ctx context.Context, p LocalProbe) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.localOnly {
		return false, errors.New("ANDEIVA_NFT_FIXTURE_MODE")
	}
	args, err := localProbeArgs(p, f.host)
	if err != nil {
		return false, err
	}
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd, err := f.command(deadline, p.Side, f.self, args, "", true, false)
	if err != nil {
		return false, err
	}
	var output boundedBuffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 10 {
		return false, nil
	}
	return false, fmt.Errorf("ANDEIVA_NFT_PROBE_FAILED: %w: %s", err, output.String())
}
