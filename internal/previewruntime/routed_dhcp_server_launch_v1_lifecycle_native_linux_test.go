//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"golang.org/x/sys/unix"
)

const serverLifecycleOptInV1 = "ANDEIVA_DHCP_SERVER_LIFECYCLE_NATIVE_V1"

type serverLifecycleProcessV1 struct {
	PID       int    `json:"pid"`
	Start     uint64 `json:"start_ticks"`
	RSS       uint64 `json:"rss_bytes"`
	PSS       uint64 `json:"pss_bytes"`
	MNT       uint64 `json:"mount_namespace"`
	Namespace uint64 `json:"network_namespace"`
	Cgroup    string `json:"cgroup"`
	fd        *os.File
}

type serverLifecycleSampleV1 struct {
	Phase        string                     `json:"phase"`
	BootNS       int64                      `json:"boot_ns"`
	OwnCPU       map[string]uint64          `json:"own_cpu"`
	ParentCPU    map[string]uint64          `json:"parent_cpu"`
	ParentMemory map[string]uint64          `json:"parent_memory"`
	ParentKernel map[string]uint64          `json:"parent_memory_stat"`
	Processes    []serverLifecycleProcessV1 `json:"processes"`
}

// FD3/4/5 pin the real host NET/MNT/PID; FD6 pins the disposable gateway;
// FD7 is the protected evidence root. Root alone invokes the outer harness.
func TestNativeRoutedDHCPServerLaunchLifecycleV1(t *testing.T) {
	if os.Getenv(serverLifecycleOptInV1) == "" {
		t.Skip("authorized Debian13 isolated launcher fixture only")
	}
	if os.Getenv(serverLifecycleOptInV1) != "1" || os.Getenv("CI") != "" || os.Geteuid() != 0 || os.Getuid() != 0 {
		t.Fatal("native lifecycle profile refused")
	}
	release, err := os.ReadFile("/etc/os-release")
	kernel, other := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil || other != nil || !bytes.Contains(release, []byte("ID=debian\n")) || !bytes.Contains(release, []byte("VERSION_ID=\"13\"")) || bytes.Contains(bytes.ToLower(kernel), []byte("microsoft")) {
		t.Fatal("Debian13 native only")
	}
	var originalIDs [3]uint64
	for i, kind := range []int{unix.CLONE_NEWNET, unix.CLONE_NEWNS, unix.CLONE_NEWPID} {
		fd := i + 3
		var st unix.Stat_t
		var fs unix.Statfs_t
		actual, e := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if e != nil || actual != kind || unix.Fstat(fd, &st) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
			t.Fatal("original host pin")
		}
		originalIDs[i] = st.Ino
		name := []string{"net", "mnt", "pid"}[i]
		current, e := namespaceID("/proc/self/ns/" + name)
		thread, te := namespaceID("/proc/thread-self/ns/" + name)
		if e != nil || te != nil || current == st.Ino || current != thread {
			t.Fatal("original/current namespace overlap")
		}
		unix.CloseOnExec(fd)
	}
	if routedDHCPOwnerCgroupV3() != nil {
		t.Fatal("exclusive empty supervisor required")
	}
	fixture := os.NewFile(7, "lifecycle-fixture")
	defer fixture.Close()
	var fst unix.Stat_t
	if unix.Fstat(7, &fst) != nil || fst.Mode != unix.S_IFDIR|0700 || fst.Uid != 0 || !fenceNoACLV3(fixture, true) {
		t.Fatal("fixture root")
	}
	root, err := os.OpenRoot("/proc/self/fd/7")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	unix.CloseOnExec(7)
	gw := os.NewFile(6, "lifecycle-gateway")
	defer gw.Close()
	unix.CloseOnExec(6)
	gwInfo, err := gw.Stat()
	if err != nil {
		t.Fatal(err)
	}
	gwID := gwInfo.Sys().(*syscall.Stat_t).Ino
	if gwID == originalIDs[0] || !routedDHCPOwnerNamespaceV3(gw, unix.CLONE_NEWNET, gwID) {
		t.Fatal("gateway pin")
	}
	host, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hostMount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer hostMount.Close()
	hostID, err := namespaceID("/proc/self/ns/net")
	if err != nil || hostID == gwID {
		t.Fatal("gateway is supervisor namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	nftBefore := serverLifecycleCommandV1(t, ctx, gw, "/usr/sbin/nft", "-s", "-j", "list", "ruleset")
	socketsBefore := serverLifecycleSocketsV1(t, ctx, gw)
	if len(bytes.TrimSpace(socketsBefore)) != 0 {
		t.Fatal("gateway already has sockets")
	}
	closed := func() {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
			if !bytes.Equal(serverLifecycleCommandV1(t, ctx, gw, "/usr/bin/cat", path), []byte("0\n")) {
				t.Fatal("fixture forwarding is not closed")
			}
		}
		if !bytes.Equal(nftBefore, serverLifecycleCommandV1(t, ctx, gw, "/usr/sbin/nft", "-s", "-j", "list", "ruleset")) {
			t.Fatal("closed fixture rules changed")
		}
	}
	closed()
	parent, err := routedDHCPServiceParentV1()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	var samples []serverLifecycleSampleV1
	samples = append(samples, serverLifecycleSampleAtV1(t, "before-infrastructure", parent, nil, nil))
	if disabled, e := PrepareRoutedDHCPServerServiceSetV1(ctx, RoutedDHCPServerServiceSetOptionsV1{}); e != nil || disabled != nil {
		t.Fatal("disabled allocated infrastructure", e)
	}
	nonce := func() string {
		var n [16]byte
		if _, e := rand.Read(n[:]); e != nil {
			t.Fatal(e)
		}
		return hex.EncodeToString(n[:])
	}
	wanRun, lanRun := nonce(), nonce()
	set, err := PrepareRoutedDHCPServerServiceSetV1(ctx, RoutedDHCPServerServiceSetOptionsV1{LANEnabled: true, WANIncarnation: wanRun, LANIncarnation: lanRun})
	if err != nil {
		t.Fatal(err)
	}
	// Containment on failure is exact-owned drainage, never a foreign PID kill.
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if e := set.DestroyV1(c); e != nil {
			t.Errorf("retained service set requires outer containment: %v", e)
		}
	})
	pins, err := set.ReadOnlyPinsV1()
	if err != nil {
		t.Fatal(err)
	}
	for _, pin := range pins {
		defer pin.Directory.Close()
	}
	var lan *os.File
	var lanName string
	for _, pin := range pins {
		if pin.Role == "lan" {
			lan = pin.Directory
			lanName = pin.Name
		}
	}
	if lan == nil {
		t.Fatal("missing LAN slot")
	}
	samples = append(samples, serverLifecycleSampleAtV1(t, "infrastructure-only", parent, lan, nil))
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil {
		t.Fatal(err)
	}
	config := dhcpserver.Config{SchemaVersion: 1, Enabled: true, Scopes: []dhcpserver.Scope{{ID: "lifecycle-lan", InterfaceID: "lan", Subnet: "198.18.1.0/24", Router: "198.18.1.1", Pools: []dhcpserver.Pool{{First: "198.18.1.100", Last: "198.18.1.100"}}, LeaseSeconds: 120, RenewSeconds: 60, RebindSeconds: 105}}}
	bindings := []dhcpkea.Binding{{Interface: dhcpserver.Binding{InterfaceID: "lan", Role: "lan", Address: netip.MustParsePrefix("198.18.1.1/24")}, Name: "lan0", SubnetID: 17}}
	artifact, err := dhcpkea.Compile(config, bindings)
	if err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile("runtime-config.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(artifact.JSON); err == nil {
		err = file.Chown(0, int(gid))
	}
	if err == nil {
		err = file.Chmod(0440)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("compiled fixture config", err, closeErr)
	}
	file, err = root.OpenFile("runtime-config.json", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = root.Mkdir("leases", 0700); err != nil {
		t.Fatal(err)
	}
	leases, err := root.OpenFile("leases", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer leases.Close()
	if err = leases.Chown(int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	bootID, err := canonicalBoot(boot)
	if err != nil {
		t.Fatal(err)
	}
	o := RoutedDHCPServerResourcesV1{Metadata: Metadata{SchemaVersion: 2, RunID: lanRun, BootID: bootID, HostNamespace: hostID, GatewayNamespace: gwID}, Gateway: gw, Host: host, HostMount: hostMount, Configuration: file, Leases: leases, Config: config, Bindings: bindings, ServiceCgroups: pins, LeaseBudgetBytes: 4 << 20}
	start := StartRoutedDHCPServerV1
	cancelStartup := func() {}
	selectedLifetime := os.Getenv("ANDEIVA_NATIVE_DHCP_SERVER_SELECTED_LIFETIME_V2") == "1"
	if selectedLifetime {
		start = func(lifetime context.Context, resources RoutedDHCPServerResourcesV1) (*RoutedDHCPServerLaunchV1, error) {
			call, cancel := context.WithTimeout(lifetime, 10*time.Second)
			cancelStartup = cancel
			return startRoutedDHCPServerScopedV2(call, lifetime, resources)
		}
	}
	launch, err := start(ctx, o)
	defer cancelStartup()
	if err != nil {
		t.Fatal("launcher", err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		_ = launch.Stop(c)
	})
	roleStart, _, err := routedDHCPOwnerProcessV3(launch.PID())
	if err != nil {
		t.Fatal(err)
	}
	var links []struct {
		Index int    `json:"ifindex"`
		Name  string `json:"ifname"`
	}
	if err = json.Unmarshal(serverLifecycleCommandV1(t, ctx, gw, "/usr/bin/ip", "-j", "link", "show", "dev", "lan0"), &links); err != nil || len(links) != 1 || links[0].Index <= 0 || links[0].Name != "lan0" {
		t.Fatal("exact LAN ifindex", err)
	}
	var engine serverLifecycleProcessV1
	ready := time.NewTicker(50 * time.Millisecond)
	defer ready.Stop()
	for engine.PID == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("engine observation deadline", ctx.Err())
		case <-ready.C:
			if !launch.Alive() {
				t.Fatal("role exited before engine readiness")
			}
			engine, err = serverLifecycleEngineV1(lan, launch.PID(), roleStart, uid, gid, gwID, links[0].Index)
			if err != nil {
				t.Fatal("engine observation", err)
			}
		}
	}
	ready.Stop()
	defer engine.fd.Close()
	if selectedLifetime {
		if err := launch.acceptStartupV2(); err != nil {
			t.Fatal("qualify Kea startup", err)
		}
		cancelStartup()
	}

	pids := serverLifecycleMembersV1(t, lan)
	if len(pids) != 2 || !((pids[0] == launch.PID() && pids[1] == engine.PID) || (pids[1] == launch.PID() && pids[0] == engine.PID)) {
		t.Fatal("unexpected process or LFC worker in serving leaf")
	}
	processes := serverLifecycleProcessesV1(t, pids, gwID, "0::"+routedSupervisorCgroupV3+"/"+lanName+"\n")
	for _, process := range processes {
		if process.PID == launch.PID() {
			serverLifecycleNoMountPinsV2(t, process, file, leases)
		}
	}
	selfFD, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatal("parent descriptor proof", err)
	}
	selfPin := os.NewFile(uintptr(selfFD), "mount-pin-parent-proof")
	selfStart, _, err := routedDHCPOwnerProcessV3(os.Getpid())
	if err != nil {
		_ = selfPin.Close()
		t.Fatal(err)
	}
	serverLifecycleNoMountPinsV2(t, serverLifecycleProcessV1{PID: os.Getpid(), Start: selfStart, fd: selfPin}, file, leases)
	if err := selfPin.Close(); err != nil {
		t.Fatal(err)
	}
	closed()
	for _, pin := range pins {
		if pin.Role == "wan" && len(serverLifecycleMembersV1(t, pin.Directory)) != 0 {
			t.Fatal("LAN fixture started WAN work")
		}
	}
	defer func() {
		for _, p := range processes {
			_ = p.fd.Close()
		}
	}()
	samples = append(samples, serverLifecycleSampleAtV1(t, "enabled-start", parent, lan, processes))
	serverLifecycleWaitV1(t, ctx, 4*time.Second)
	if !launch.Alive() {
		t.Fatal("role died during enabled sample")
	}
	samples = append(samples, serverLifecycleSampleAtV1(t, "enabled-end", parent, lan, serverLifecycleRefreshV1(t, processes)))
	observed, err := serverLifecycleEngineV1(lan, launch.PID(), roleStart, uid, gid, gwID, links[0].Index)
	if err != nil || observed.PID != engine.PID || observed.Start != engine.Start {
		t.Fatal("engine/RAW identity changed during enabled sample", err)
	}
	_ = observed.fd.Close()
	nativeKeaReadbackV1(t, ctx, gw, host, lan, routedKeaEngineIdentityV1{
		pid: engine.PID, parent: launch.PID(), start: engine.Start, namespace: gwID, uid: uid, gid: gid,
	})
	if selectedLifetime {
		t.Log("same Kea process and sockets remained active after cancelling the startup context")
	}
	stopCtx, stop := context.WithTimeout(ctx, 15*time.Second)
	err = launch.Stop(stopCtx)
	stop()
	if err != nil {
		t.Fatal("bounded stop", err)
	}
	drainCtx, drainStop := context.WithTimeout(ctx, 3*time.Second)
	err = set.DrainFeatureV1(drainCtx, "lan")
	drainStop()
	if err != nil {
		t.Fatal("LAN leaf drain", err)
	}
	if launch.Alive() || len(serverLifecycleMembersV1(t, lan)) != 0 {
		t.Fatal("own processes survive disable")
	}
	for _, p := range append(processes, engine) {
		poll := []unix.PollFd{{Fd: int32(p.fd.Fd()), Events: unix.POLLIN}}
		if n, e := unix.Poll(poll, 0); e != nil || n != 1 || poll[0].Revents&unix.POLLIN == 0 {
			t.Fatal("retained process identity remains alive", p.PID, e)
		}
	}
	serverLifecycleNoMountUsersV1(t, processes)
	closed()
	if !bytes.Equal(nftBefore, serverLifecycleCommandV1(t, ctx, gw, "/usr/sbin/nft", "-s", "-j", "list", "ruleset")) || !bytes.Equal(socketsBefore, serverLifecycleSocketsV1(t, ctx, gw)) {
		t.Fatal("rules or UDP/RAW/PACKET/UNIX sockets survive disable")
	}
	// The role's mount namespace has no live process and no observer holds its
	// namespace FD. Close/unlink only generated runtime input; retain leases.
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = root.Remove("runtime-config.json"); err != nil {
		t.Fatal(err)
	}
	leaseBefore := serverLifecycleLeaseDigestsV1(t, leases, uid, gid)
	samples = append(samples, serverLifecycleSampleAtV1(t, "disabled-start", parent, lan, nil))
	serverLifecycleWaitV1(t, ctx, 4*time.Second)
	if len(serverLifecycleMembersV1(t, lan)) != 0 || !bytes.Equal(socketsBefore, serverLifecycleSocketsV1(t, ctx, gw)) {
		t.Fatal("feature resources returned while disabled")
	}
	if !maps.Equal(leaseBefore, serverLifecycleLeaseDigestsV1(t, leases, uid, gid)) {
		t.Fatal("operational leases changed during disabled sample")
	}
	if _, e := root.Stat("runtime-config.json"); !os.IsNotExist(e) {
		t.Fatal("live runtime configuration retained", e)
	}
	samples = append(samples, serverLifecycleSampleAtV1(t, "disabled-end", parent, lan, nil))
	retained, err := set.ReadOnlyPinsV1()
	if err != nil {
		t.Fatal("reserved inode identity changed", err)
	}
	for i, pin := range retained {
		if pin.Name != pins[i].Name || pin.Identity != pins[i].Identity || len(serverLifecycleMembersV1(t, pin.Directory)) != 0 {
			t.Fatal("reserved disabled service set changed")
		}
		_ = pin.Directory.Close()
	}
	destroyCtx, destroyStop := context.WithTimeout(ctx, 3*time.Second)
	err = set.DestroyV1(destroyCtx)
	destroyStop()
	if err != nil {
		t.Fatal("whole-incarnation retirement", err)
	}
	if routedDHCPOwnerCgroupV3() != nil {
		t.Fatal("retired incarnation left child cgroups")
	}
	for _, pin := range pins {
		_ = pin.Directory.Close()
	}
	samples = append(samples, serverLifecycleSampleAtV1(t, "after-infrastructure", parent, nil, nil))
	primaryLeaseDigest := leaseBefore["kea-leases4.csv"]
	report := struct {
		Version                      int                       `json:"version"`
		DisabledBeforeSupervisorExit bool                      `json:"disabled_before_supervisor_exit"`
		MountPinsClosedAfterTransfer bool                      `json:"mount_pins_closed_after_transfer"`
		LeaseDigest                  string                    `json:"lease_digest"`
		LeaseFilesVerified           int                       `json:"lease_files_verified"`
		Samples                      []serverLifecycleSampleV1 `json:"samples"`
	}{2, true, true, hex.EncodeToString(primaryLeaseDigest[:]), len(leaseBefore), samples}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err = root.WriteFile("lifecycle-result.json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("launcher_disable_before_unit_exit=true own_processes=0 own_sockets=0 rules_unchanged=true active_config_absent=true leases_retained=true native_DORA_tested=false")
}

func serverLifecycleFDFlagsV2(raw []byte) (uint64, error) {
	if len(raw) > 4096 {
		return 0, ErrIdentity
	}
	found := false
	var flags uint64
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "flags:" {
			continue
		}
		if found || len(fields) != 2 {
			return 0, ErrIdentity
		}
		value, err := strconv.ParseUint(fields[1], 8, 64)
		if err != nil {
			return 0, ErrIdentity
		}
		found, flags = true, value
	}
	if !found {
		return 0, ErrIdentity
	}
	return flags, nil
}

// Detached-tree capabilities must be closed in both parent and role after
// transfer. Original borrowed descriptors remain valid and are not O_PATH.
func serverLifecycleNoMountPinsV2(t *testing.T, process serverLifecycleProcessV1, configuration, leases *os.File) {
	t.Helper()
	if !routedDHCPOwnerPIDFDAliveV3(process.fd, process.PID) {
		t.Fatal("descriptor proof process unavailable")
	}
	var originals [2]unix.Stat_t
	for i, source := range []*os.File{configuration, leases} {
		if unix.Fstat(int(source.Fd()), &originals[i]) != nil {
			t.Fatal("descriptor proof original")
		}
	}
	dir, err := os.Open("/proc/" + strconv.Itoa(process.PID) + "/fd")
	if err != nil {
		t.Fatal(err)
	}
	entries, readErr := dir.ReadDir(257)
	closeErr := dir.Close()
	if readErr != nil && readErr != io.EOF || closeErr != nil || len(entries) > 256 {
		t.Fatal("bounded descriptor observation", readErr, closeErr)
	}
	for _, entry := range entries {
		fd, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil || strconv.FormatUint(fd, 10) != entry.Name() {
			t.Fatal("descriptor name")
		}
		prefix := "/proc/" + strconv.Itoa(process.PID)
		var st unix.Stat_t
		if err := unix.Stat(prefix+"/fd/"+entry.Name(), &st); err != nil {
			if err == unix.ENOENT {
				continue
			}
			t.Fatal("descriptor identity", err)
		}
		for _, source := range originals {
			if source.Dev != st.Dev || source.Ino != st.Ino {
				continue
			}
			raw, err := routedDHCPOwnerReadV3(prefix+"/fdinfo/"+entry.Name(), 4096)
			if err != nil {
				t.Fatal("descriptor flags", err)
			}
			flags, err := serverLifecycleFDFlagsV2(raw)
			if err != nil || flags&unix.O_PATH != 0 {
				t.Fatal("detached mount descriptor retained after transfer", err)
			}
		}
	}
	start, _, err := routedDHCPOwnerProcessV3(process.PID)
	if err != nil || start != process.Start || !routedDHCPOwnerPIDFDAliveV3(process.fd, process.PID) {
		t.Fatal("descriptor proof process changed")
	}
}

func serverLifecycleWaitV1(t *testing.T, ctx context.Context, d time.Duration) {
	t.Helper()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func serverLifecycleCommandV1(t *testing.T, ctx context.Context, gw *os.File, executable string, args ...string) []byte {
	t.Helper()
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", append([]string{"--net=/proc/self/fd/3", "--", executable}, args...)...)
	cmd.ExtraFiles = []*os.File{gw}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	var out routedDHCPServerLogV1
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil || out.overflow {
		t.Fatal("bounded namespace observation", executable, err)
	}
	return append([]byte(nil), out.data...)
}

func serverLifecycleSocketsV1(t *testing.T, ctx context.Context, gw *os.File) []byte {
	return serverLifecycleCommandV1(t, ctx, gw, "/usr/bin/ss", "-H", "-a", "-n", "-t", "-u", "-w", "-x", "-0")
}

func serverLifecycleMembersV1(t *testing.T, leaf *os.File) []int {
	t.Helper()
	raw, err := routedDHCPServiceReadAtV1(leaf, "cgroup.procs", 4096)
	if err != nil {
		t.Fatal(err)
	}
	pids, err := serverLifecycleParseMembersV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return pids
}
func serverLifecycleParseMembersV1(raw []byte) ([]int, error) {
	if len(raw) > 4096 {
		return nil, ErrIdentity
	}
	fields := strings.Fields(string(raw))
	if len(fields) > 16 {
		return nil, ErrIdentity
	}
	out := []int{}
	seen := map[int]bool{}
	for _, f := range fields {
		n, e := strconv.Atoi(f)
		if e != nil || n <= 1 || seen[n] || strconv.Itoa(n) != f {
			return nil, ErrIdentity
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

func serverLifecycleCountersV1(raw []byte) (map[string]uint64, error) {
	if len(raw) > 8192 {
		return nil, ErrIdentity
	}
	out := map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, ErrIdentity
		}
		if _, ok := out[fields[0]]; ok {
			return nil, ErrIdentity
		}
		n, e := strconv.ParseUint(fields[1], 10, 64)
		if e != nil {
			return nil, ErrIdentity
		}
		out[fields[0]] = n
	}
	return out, nil
}

func serverLifecycleCPUStatsV1(raw []byte) (map[string]uint64, error) {
	counters, err := serverLifecycleCountersV1(raw)
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"usage_usec", "user_usec", "system_usec"} {
		if _, ok := counters[key]; !ok {
			return nil, ErrIdentity
		}
	}
	return counters, nil
}

func serverLifecycleSampleAtV1(t *testing.T, phase string, parent, leaf *os.File, pids []serverLifecycleProcessV1) serverLifecycleSampleV1 {
	t.Helper()
	now, err := routedDHCPOwnerBootNowV3()
	if err != nil {
		t.Fatal(err)
	}
	sample := serverLifecycleSampleV1{Phase: phase, BootNS: now, ParentMemory: map[string]uint64{}, Processes: pids}
	read := func(dir *os.File, name string) []byte {
		raw, e := routedDHCPServiceReadAtV1(dir, name, 8192)
		if e != nil {
			t.Fatal(name, e)
		}
		return raw
	}
	sample.ParentCPU, err = serverLifecycleCPUStatsV1(read(parent, "cpu.stat"))
	if err != nil {
		t.Fatal(err)
	}
	if leaf != nil {
		sample.OwnCPU, err = serverLifecycleCPUStatsV1(read(leaf, "cpu.stat"))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"memory.current", "memory.peak"} {
		value, e := strconv.ParseUint(strings.TrimSpace(string(read(parent, name))), 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		sample.ParentMemory[name] = value
	}
	sample.ParentKernel, err = serverLifecycleCountersV1(read(parent, "memory.stat"))
	if err != nil {
		t.Fatal(err)
	}
	return sample
}

func serverLifecycleProcessesV1(t *testing.T, pids []int, ns uint64, group string) []serverLifecycleProcessV1 {
	t.Helper()
	var out []serverLifecycleProcessV1
	for _, pid := range pids {
		fd, e := unix.PidfdOpen(pid, 0)
		if e != nil {
			t.Fatal(e)
		}
		p := serverLifecycleProcessV1{PID: pid, Namespace: ns, Cgroup: group, fd: os.NewFile(uintptr(fd), "lifecycle-pidfd")}
		p.Start, _, e = routedDHCPOwnerProcessV3(pid)
		if e != nil {
			_ = p.fd.Close()
			t.Fatal("process start identity", e)
		}
		actual, ne := namespaceID(fmt.Sprintf("/proc/%d/ns/net", pid))
		p.MNT, e = namespaceID(fmt.Sprintf("/proc/%d/ns/mnt", pid))
		if e != nil || ne != nil || actual != ns || !routedDHCPOwnerPIDFDAliveV3(p.fd, pid) {
			p.fd.Close()
			t.Fatal("process identity")
		}
		out = append(out, p)
	}
	return serverLifecycleRefreshV1(t, out)
}

func serverLifecycleNoMountUsersV1(t *testing.T, processes []serverLifecycleProcessV1) {
	t.Helper()
	want := map[uint64]bool{}
	current, err := namespaceID("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range processes {
		if p.MNT == 0 || p.MNT == current {
			t.Fatal("engine configuration did not use a private mount namespace")
		}
		want[p.MNT] = true
	}
	entries, err := os.ReadDir("/proc")
	if err != nil || len(entries) > 1024 {
		t.Fatal("bounded private process inventory", err)
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		ns, err := namespaceID("/proc/" + entry.Name() + "/ns/mnt")
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if want[ns] {
			t.Fatal("active private configuration mount still has a process")
		}
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(fds) > 256 {
		t.Fatal("bounded observer descriptor inventory", err)
	}
	for _, entry := range fds {
		link, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for id := range want {
			if link == fmt.Sprintf("mnt:[%d]", id) {
				t.Fatal("observer retained an active configuration mount")
			}
		}
	}
}

func serverLifecycleRefreshV1(t *testing.T, pids []serverLifecycleProcessV1) []serverLifecycleProcessV1 {
	t.Helper()
	out := append([]serverLifecycleProcessV1(nil), pids...)
	for i := range out {
		p := &out[i]
		raw, e := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/%d/smaps_rollup", p.PID), 8192)
		if e != nil {
			t.Fatal(e)
		}
		var rss, pss bool
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 3 && (f[0] == "Rss:" || f[0] == "Pss:") {
				n, e := strconv.ParseUint(f[1], 10, 64)
				if e != nil || f[2] != "kB" || n > ^uint64(0)/1024 {
					t.Fatal("smaps units")
				}
				if f[0] == "Rss:" {
					p.RSS = n * 1024
					rss = true
				} else {
					p.PSS = n * 1024
					pss = true
				}
			}
		}
		start, _, e := routedDHCPOwnerProcessV3(p.PID)
		group, ge := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/%d/cgroup", p.PID), 4096)
		ns, ne := namespaceID(fmt.Sprintf("/proc/%d/ns/net", p.PID))
		if e != nil || ge != nil || ne != nil || string(group) != p.Cgroup || ns != p.Namespace || start != p.Start || !rss || !pss || !routedDHCPOwnerPIDFDAliveV3(p.fd, p.PID) {
			t.Fatal("resource sample changed process identity")
		}
	}
	return out
}

func serverLifecycleEngineV1(leaf *os.File, parent int, parentStart uint64, uid, gid uint32, ns uint64, lanIndex int) (serverLifecycleProcessV1, error) {
	start, _, err := routedDHCPOwnerProcessV3(parent)
	if err != nil || start != parentStart {
		return serverLifecycleProcessV1{}, ErrIdentity
	}
	raw, err := routedDHCPServiceReadAtV1(leaf, "cgroup.procs", 4096)
	if err != nil {
		return serverLifecycleProcessV1{}, err
	}
	pids, err := serverLifecycleParseMembersV1(raw)
	if err != nil {
		return serverLifecycleProcessV1{}, err
	}
	for _, pid := range pids {
		exe, e := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if e != nil || exe != "/usr/sbin/kea-dhcp4" {
			continue
		}
		fd, e := unix.PidfdOpen(pid, 0)
		if e != nil {
			return serverLifecycleProcessV1{}, e
		}
		p := serverLifecycleProcessV1{PID: pid, fd: os.NewFile(uintptr(fd), "lifecycle-kea-pidfd")}
		p.Start, _, e = routedDHCPOwnerProcessV3(pid)
		_, ppid, pe := routedDHCPOwnerProcessV3(pid)
		actual, ne := namespaceID(fmt.Sprintf("/proc/%d/ns/net", pid))
		status, se := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/%d/status", pid), 65536)
		profile, ae := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/%d/attr/current", pid), 4096)
		valid := e == nil && pe == nil && ppid == parent && ne == nil && actual == ns && se == nil && ae == nil && strings.TrimSpace(string(profile)) == "kea-dhcp4 (enforce)"
		for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			valid = valid && bytes.Contains(status, []byte(field+":\t0000000000002400\n"))
		}
		for _, line := range []string{fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid), fmt.Sprintf("Gid:\t%d\t%d\t%d\t%d\n", gid, gid, gid, gid), "NoNewPrivs:\t1\n"} {
			valid = valid && bytes.Contains(status, []byte(line))
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Groups:") && len(strings.Fields(strings.TrimPrefix(line, "Groups:"))) != 0 {
				valid = false
			}
		}
		if !valid || !routedDHCPOwnerPIDFDAliveV3(p.fd, pid) {
			p.fd.Close()
			return serverLifecycleProcessV1{}, ErrIdentity
		}
		packet, e := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/%d/net/packet", pid), 65536)
		fds, fe := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if e != nil || fe != nil || len(fds) > 256 {
			p.fd.Close()
			return serverLifecycleProcessV1{}, ErrIdentity
		}
		owned := map[string]bool{}
		for _, item := range fds {
			link, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, item.Name()))
			if e == nil && strings.HasPrefix(link, "socket:[") {
				owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
		for _, line := range strings.Split(string(packet), "\n") {
			f := strings.Fields(line)
			if len(f) == 9 && f[2] == "3" && f[3] == "0003" && f[4] == strconv.Itoa(lanIndex) && f[7] == strconv.FormatUint(uint64(uid), 10) && owned[f[8]] {
				after, pp, e := routedDHCPOwnerProcessV3(pid)
				if e == nil && after == p.Start && pp == parent && routedDHCPOwnerPIDFDAliveV3(p.fd, pid) {
					return p, nil
				}
			}
		}
		p.fd.Close()
	}
	return serverLifecycleProcessV1{}, nil
}

func serverLifecycleLeaseDigestsV1(t *testing.T, leases *os.File, uid, gid uint32) map[string][sha256.Size]byte {
	t.Helper()
	const budget = 4 << 20
	// A new open description must acquire the worker lock after disable. A
	// retained borrowed directory FD must not hide an inherited stale flock.
	lockFD, err := unix.Openat(int(leases.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	lock := os.NewFile(uintptr(lockFD), "disabled-lease-lock-check")
	defer lock.Close()
	if err = unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("lease worker lock survives disable", err)
	}
	defer func() {
		if err := unix.Flock(lockFD, unix.LOCK_UN); err != nil {
			t.Error(err)
		}
	}()
	if err = routedDHCPServerLeasesV1(lock, uid, gid, budget); err != nil {
		t.Fatal("lease storage identity", err)
	}
	entries, err := lock.ReadDir(6)
	if err != nil && err != io.EOF || len(entries) >= 6 {
		t.Fatal("lease inventory bound", err)
	}
	digests := make(map[string][sha256.Size]byte, len(entries))
	remaining := int64(budget)
	for _, entry := range entries {
		name := entry.Name()
		if !routedDHCPServerLeaseNameV1(name) {
			t.Fatal("unexpected lease artifact")
		}
		fd, err := unix.Openat(lockFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal("open retained lease artifact", err)
		}
		file := os.NewFile(uintptr(fd), "operational-leases")
		digest := sha256.New()
		n, err := io.Copy(digest, io.LimitReader(file, remaining+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil || n == 0 || n > remaining {
			t.Fatal("lease digest bound", err, closeErr)
		}
		remaining -= n
		digests[name] = [sha256.Size]byte(digest.Sum(nil))
	}
	if _, present := digests["kea-leases4.csv"]; !present {
		t.Fatal("operational lease file absent")
	}
	return digests
}

func TestRoutedDHCPServerLifecycleParsersV1(t *testing.T) {
	if got, e := serverLifecycleParseMembersV1([]byte("5\n3\n")); e != nil || len(got) != 2 || got[0] != 3 {
		t.Fatal(got, e)
	}
	for _, raw := range []string{"1\n", "03\n", "3\n3\n", "x\n", strings.Repeat("2\n", 17)} {
		if _, e := serverLifecycleParseMembersV1([]byte(raw)); e == nil {
			t.Fatal("invalid membership accepted", raw)
		}
	}
	if got, e := serverLifecycleCountersV1([]byte("usage_usec 123\nuser_usec 100\n")); e != nil || got["usage_usec"] != 123 {
		t.Fatal(got, e)
	}
	for _, raw := range []string{"usage_usec -1\n", "usage_usec 1\nusage_usec 2\n", "usage_usec 1 extra\n", strings.Repeat("x", 8193)} {
		if _, e := serverLifecycleCountersV1([]byte(raw)); e == nil {
			t.Fatal("invalid resource counters accepted")
		}
	}
	if got, err := serverLifecycleCPUStatsV1([]byte("usage_usec 123\nuser_usec 100\nsystem_usec 23\nnr_periods 2\n")); err != nil || got["usage_usec"] != 123 || got["system_usec"] != 23 {
		t.Fatal("valid CPU sample", got, err)
	}
	for _, raw := range []string{"bogus 1\n", "usage_usec 1\n", "usage_usec 1\nuser_usec 1\n", "user_usec 1\nsystem_usec 1\n", "usage_usec 1\nuser_usec 0\nsystem_usec -1\n", "usage_usec 1\nuser_usec 0\nsystem_usec 1\nsystem_usec 1\n"} {
		if _, err := serverLifecycleCPUStatsV1([]byte(raw)); err == nil {
			t.Fatal("incomplete or malformed CPU evidence accepted", raw)
		}
	}
}
