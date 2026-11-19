//go:build linux

package previewruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
	case "dhcp", "delegation":
		initial = routedDHCPDelegatedCapsV1
	default:
		t.Fatal("invalid laboratory capability profile")
	}
	t.Setenv(routedDHCPRoleProfileEnvV1, "")
	if err := configureRoutedSupervisorDHCPExecutionV1(); (initial == 0 && err != nil) ||
		(initial != 0 && !errors.Is(err, ErrIdentity)) {
		t.Fatalf("unexpected result applying standard profile to the unit ceiling: %v", err)
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

	if profile == "delegation" {
		t.Setenv(routedDHCPRoleProfileEnvV1, "1")
		if err := configureRoutedSupervisorDHCPExecutionV1(); !errors.Is(err, ErrIdentity) {
			t.Fatalf("profile accepted outside the grouped service: %v", err)
		}
		if err := restrictRoutedDHCPRootExecV1(); err != nil {
			t.Fatal("secure the supervisor's child execution", err)
		}
		checkRoutedDHCPChildCapabilitiesV1(t)
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

func checkRoutedDHCPChildCapabilitiesV1(t *testing.T) {
	t.Helper()
	check := func(cmd *exec.Cmd, expected uint32) {
		t.Helper()
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
		status, err := cmd.Output()
		if err != nil {
			t.Fatalf("inspect child with expected capabilities %08x: %v", expected, err)
		}
		if !strings.Contains(string(status), fmt.Sprintf("\nCapEff:\t%016x\n", expected)) {
			t.Fatalf("unexpected child effective capabilities, wanted %08x", expected)
		}
	}
	check(exec.Command("/usr/bin/cat", "/proc/self/status"), routedSupervisorDHCPBaseCapsV1)
	for _, role := range []struct {
		caps string
		want uint32
	}{
		{"-all", 0},
		{"-all,+net_admin", 1 << unix.CAP_NET_ADMIN},
		{"-all,+net_bind_service,+net_raw", routedDHCPDelegatedCapsV1},
	} {
		cmd := exec.Command("/usr/bin/setpriv", "--reuid=62020", "--regid=62021", "--clear-groups",
			"--bounding-set="+role.caps, "--inh-caps="+role.caps, "--ambient-caps="+role.caps,
			"--no-new-privs", "--", "/usr/bin/cat", "/proc/self/status")
		if role.want == routedDHCPDelegatedCapsV1 {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			if err := setRoutedDHCPChildNetworkCapsV1(cmd.SysProcAttr); err != nil {
				t.Fatal("delegate capabilities to the fixed DHCP launch", err)
			}
		}
		check(cmd, role.want)
	}
	check(exec.Command("/usr/bin/cat", "/proc/self/status"), routedSupervisorDHCPBaseCapsV1)
	verifyRoutedDHCPProcInspectionBoundaryV1(t)
	t.Log("ordinary root exec retained baseline; API has zero capabilities; helper has NET_ADMIN; fixed DHCP child has NET_BIND_SERVICE and NET_RAW")
}

func verifyRoutedDHCPProcInspectionBoundaryV1(t *testing.T) {
	t.Helper()
	// Parent-death follows the spawning Linux thread. Keep it unavailable to
	// the short-lived namespace inspectors until this fixture has stopped.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command("/usr/bin/sleep", "3")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWNET}
	if err := setRoutedDHCPChildNetworkCapsV1(cmd.SysProcAttr); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	path := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/mnt"
	f, err := os.Open(path)
	if err == nil {
		_ = f.Close()
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("unexpected namespace access for delegated child: %v", err)
	}
	t.Log("opening the delegated child's /proc/PID/ns/mnt is denied under the supervisor profile")
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	process := os.NewFile(uintptr(pidfd), "delegated-fixture-pidfd")
	defer process.Close()
	selfMount, err := namespaceID("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	selfNet, err := namespaceID("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial := readRoutedDHCPPinnedNamespacesV1(process, false)
	if initial.err != nil {
		t.Fatal("inspect delegated child mount before bootstrap", initial.err)
	}
	defer initial.mount.Close()
	mountID, err := routedDHCPNamespaceFileIDV1(initial.mount, unix.CLONE_NEWNS)
	if err != nil || mountID == selfMount {
		t.Fatal("unexpected child mount namespace", err)
	}
	pair := readRoutedDHCPPinnedNamespacesV1(process, true)
	if pair.err != nil || pair.netID == 0 || pair.netID == selfNet {
		t.Fatal("unexpected delegated child network namespace", pair.err)
	}
	defer pair.mount.Close()
	if !routedDHCPOwnerNamespaceV3(pair.mount, unix.CLONE_NEWNS, mountID) {
		t.Fatal("the child changed its mount namespace during bootstrap")
	}
	pin, _, err := pinRoutedSupervisorDHCPOwnerV1(cmd.Process.Pid, os.Getpid(), pair.netID, mountID)
	if err != nil {
		t.Fatal("inspect both delegated child namespaces", err)
	}
	defer pin.Close()
	for _, bad := range []struct {
		parent     int
		net, mount uint64
	}{
		{os.Getpid(), selfNet, mountID},
		{os.Getpid(), pair.netID, selfMount},
		{os.Getppid(), pair.netID, mountID},
	} {
		if wrong, _, err := pinRoutedSupervisorDHCPOwnerV1(cmd.Process.Pid, bad.parent, bad.net, bad.mount); !errors.Is(err, ErrIdentity) {
			if wrong != nil {
				_ = wrong.Close()
			}
			t.Fatal("supervisor accepted a wrong namespace or process parent", err)
		}
	}
	afterMount, mountErr := namespaceID("/proc/self/ns/mnt")
	afterNet, netErr := namespaceID("/proc/self/ns/net")
	if mountErr != nil || netErr != nil || afterMount != selfMount || afterNet != selfNet {
		t.Fatal("inspection changed the supervisor's namespaces")
	}
	t.Log("the supervisor independently read both namespaces through the fixed child's pidfd")
}
