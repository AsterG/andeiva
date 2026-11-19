//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeRoutedSupervisorDHCPNetworkCapsV1(t *testing.T) {
	profile := os.Getenv("ANDEIVA_NATIVE_DHCP_SUPERVISOR_CAPS_V1")
	if profile == "" {
		t.Skip("requires authorized isolated Debian systemd fixture")
	}
	scope, err := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
	threshold, thresholdErr := routedDHCPOwnerReadV3("/proc/sys/net/ipv4/ip_unprivileged_port_start", 20)
	portStart, parseErr := strconv.Atoi(strings.TrimSpace(string(threshold)))
	if os.Getuid() != 0 || os.Geteuid() != 0 || err != nil ||
		string(scope) != "0::/system.slice/andeiva-dhcp-supervisor-caps-lab.service\n" ||
		thresholdErr != nil || parseErr != nil || portStart <= 67 {
		t.Fatal("not the fixed isolated laboratory unit")
	}
	// Manager-owned properties prove isolation without reading PID 1's namespace.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	show := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "andeiva-dhcp-supervisor-caps-lab.service",
		"--no-pager", "--property=PrivateNetwork", "--property=Transient", "--property=MainPID")
	show.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	properties, err := show.Output()
	if err != nil {
		t.Fatal("verify transient systemd unit", err)
	}
	want := map[string]bool{"PrivateNetwork=yes": true, "Transient=yes": true, "MainPID=" + strconv.Itoa(os.Getpid()): true}
	for _, line := range strings.Split(strings.TrimSpace(string(properties)), "\n") {
		if !want[line] {
			t.Fatal("unexpected transient unit property")
		}
		delete(want, line)
	}
	if len(want) != 0 {
		t.Fatal("incomplete transient unit properties")
	}
	var initial uint32
	switch profile {
	case "standard":
	case "dhcp":
		initial = routedDHCPDelegatedCapsV1
	default:
		t.Fatal("invalid laboratory capability profile")
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var before, after [2]unix.CapUserData
	if err := unix.Capget(&hdr, &before[0]); err != nil ||
		before[0].Effective&routedDHCPDelegatedCapsV1 != initial ||
		before[0].Permitted&routedDHCPDelegatedCapsV1 != initial {
		t.Fatalf("unexpected initial DHCP capabilities: %v", err)
	}
	if err := dropRoutedSupervisorDHCPNetworkCapsV1(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Capget(&hdr, &after[0]); err != nil {
		t.Fatal(err)
	}
	expected := before
	expected[0].Effective &^= routedDHCPDelegatedCapsV1
	expected[0].Inheritable &^= routedDHCPDelegatedCapsV1
	if after != expected {
		t.Fatal("supervisor changed capabilities outside the approved reduction")
	}
	packet, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(packet)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("supervisor AF_PACKET socket: %v", err)
	}
	udp, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(udp)
	if err := unix.Bind(udp, &unix.SockaddrInet4{Port: 67}); !errors.Is(err, unix.EACCES) {
		t.Fatalf("supervisor UDP/67 bind: %v", err)
	}

	if profile == "dhcp" {
		// The fixture proves the capability handoff independently of Kea.
		cmd := exec.Command("/usr/bin/setpriv", "--reuid=62020", "--regid=62021", "--clear-groups",
			"--bounding-set=-all,+net_bind_service,+net_raw", "--inh-caps=-all,+net_bind_service,+net_raw",
			"--ambient-caps=-all,+net_bind_service,+net_raw", "--no-new-privs", "--", "/usr/bin/cat", "/proc/self/status")
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
		status, err := cmd.Output()
		if err != nil {
			t.Fatal("fixed child could not receive delegated capabilities", err)
		}
		for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			if !strings.Contains(string(status), "\n"+field+":\t0000000000002400\n") {
				t.Fatal("unexpected fixed child capability set", field)
			}
		}
	}
}
