//go:build linux

package previewruntime

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpsockets"
	"github.com/AsterG/andeiva/internal/localobserve"
	"golang.org/x/sys/unix"
)

func TestSplitRoutedDHCPServerSocketsV1(t *testing.T) {
	const lanUID = 103
	state, _, _, _ := serviceSocketModelV1()
	lan := routedDHCPServerSocketBindingV1{index: state.wanIndex + 1, address: netip.MustParseAddr("198.18.0.1")}
	id := RoutedDHCPServiceCgroupIdentityV1{Device: 9, Inode: 377}
	holders := []uint64{91, 93}
	fresh := func() routedDHCPSocketCaptureV1 {
		c, _, _, _ := serviceSocketModelV1()
		c.udp = append(c.udp, dhcpsockets.Socket{Address: lan.address, Port: 67, Inode: 91, Cookie: 92, UID: lanUID, CreationCgroup: id.Inode})
		c.tables = append(c.tables, localobserve.Socket{Protocol: "udp", Family: "ipv4", Address: lan.address.String(), Port: 67, Inode: 91, UID: lanUID})
		c.packet = append(c.packet, dhcpsockets.PacketSocket{Interface: lan.index, Protocol: unix.ETH_P_ALL, Type: unix.SOCK_RAW, Flags: 1, Inode: 93, Cookie: 94, UID: lanUID})
		return c
	}
	remainder, facts, err := splitRoutedDHCPServerSocketsV1(fresh(), id, lanUID, []routedDHCPServerSocketBindingV1{lan}, holders)
	if err != nil || !reflect.DeepEqual(remainder, state) || len(facts.udp) != 1 || len(facts.packet) != 1 {
		t.Fatalf("did not preserve the WAN capture: %+v, %+v, %v", remainder, facts, err)
	}
	for name, change := range map[string]func(*routedDHCPSocketCaptureV1){
		"wrong cgroup":            func(c *routedDHCPSocketCaptureV1) { c.udp[1].CreationCgroup++ },
		"wrong uid in LAN cgroup": func(c *routedDHCPSocketCaptureV1) { c.udp[1].UID++ },
		"wrong LAN address":       func(c *routedDHCPSocketCaptureV1) { c.udp[1].Address = netip.MustParseAddr("198.18.0.2") },
		"wrong UDP interface":     func(c *routedDHCPSocketCaptureV1) { c.udp[1].Interface = state.wanIndex },
		"wrong packet interface":  func(c *routedDHCPSocketCaptureV1) { c.packet[1].Interface = state.wanIndex },
		"foreign holder same UID": func(c *routedDHCPSocketCaptureV1) { c.packet[1].Inode++ },
		"packet not running":      func(c *routedDHCPSocketCaptureV1) { c.packet[1].Flags = 0 },
		"unpaired table row":      func(c *routedDHCPSocketCaptureV1) { c.tables[1].Inode++ },
		"wildcard table row":      func(c *routedDHCPSocketCaptureV1) { c.tables[1].Wildcard = true },
		"missing packet socket":   func(c *routedDHCPSocketCaptureV1) { c.packet = c.packet[:1] },
		"duplicate packet socket": func(c *routedDHCPSocketCaptureV1) { c.packet = append(c.packet, c.packet[1]) },
	} {
		t.Run(name, func(t *testing.T) {
			c := fresh()
			change(&c)
			if _, _, err := splitRoutedDHCPServerSocketsV1(c, id, lanUID, []routedDHCPServerSocketBindingV1{lan}, holders); err == nil {
				t.Fatal("invalid LAN observation was accepted")
			}
		})
	}
	if _, _, err := splitRoutedDHCPServerSocketsV1(fresh(), id, lanUID, []routedDHCPServerSocketBindingV1{{index: state.wanIndex, address: lan.address}}, holders); err == nil {
		t.Fatal("WAN was accepted as an expected LAN interface")
	}
}

// The readback is called only by the authorized lifecycle fixture after
// independently observing the real Kea role and the exact service cgroup.
func nativeKeaReadbackV1(t *testing.T, ctx context.Context, gateway, host, lane *os.File, engine routedKeaEngineIdentityV1) {
	t.Helper()
	holders := nativeKeaReadRestrictedHoldersV1(t, engine)
	var values []string
	for _, inode := range holders {
		values = append(values, strconv.FormatUint(inode, 10))
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil {
		t.Fatal("trusted native binary required", err)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", self,
		"-test.run", "^TestNativeRoutedKeaSocketReadbackV1$", "-test.v", "-test.count=1")
	cmd.ExtraFiles = []*os.File{gateway, host, lane}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C", "ANDEIVA_NATIVE_KEA_SOCKET_READBACK_V1=1",
		"ANDEIVA_NATIVE_KEA_SOCKET_HOLDERS_V1=" + strings.Join(values, ",")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Kea socket readback: %v\n%s", err, out)
	}
	t.Log(string(out))
}

func nativeKeaReadRestrictedHoldersV1(t *testing.T, engine routedKeaEngineIdentityV1) []uint64 {
	t.Helper()
	type result struct {
		values []uint64
		err    error
	}
	inspect := func() result {
		hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		allowed := uint32(routedKeaEngineNetworkCapsV1 | 1<<unix.CAP_SETUID | 1<<unix.CAP_SETGID)
		caps := [2]unix.CapUserData{{Effective: allowed, Permitted: allowed}, {}}
		if err := unix.Capset(&hdr, &caps[0]); err != nil {
			return result{err: err}
		}
		values, err := readRoutedKeaEngineFDsV1(engine)
		return result{values, err}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			defer runtime.UnlockOSThread()
			nonleader := make(chan result, 1)
			go func() {
				runtime.LockOSThread()
				nonleader <- inspect()
			}()
			done <- <-nonleader
			return
		}
		done <- inspect()
	}()
	got := <-done
	if got.err != nil {
		t.Fatal("observe engine descriptor with provisioned role capabilities", got.err)
	}
	return got.values
}

func TestNativeRoutedKeaSocketReadbackV1(t *testing.T) {
	if os.Getenv("ANDEIVA_NATIVE_KEA_SOCKET_READBACK_V1") != "1" {
		t.Skip("requires the pinned native Kea fixture")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv("CI") != "" {
		t.Fatal("requires root in the isolated lab")
	}
	raw, err := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
	if err != nil || string(raw) != "0::"+routedSupervisorCgroupV3+"\n" {
		t.Fatal("requires fixed laboratory cgroup", err)
	}
	namespace, err := namespaceID("/proc/self/fd/3")
	outside, other := namespaceID("/proc/self/fd/4")
	if err != nil || other != nil || namespace == outside || namespace == 0 || outside == 0 {
		t.Fatal("expected distinct pinned namespaces")
	}
	service := os.NewFile(5, "fixture-kea-leaf")
	defer service.Close()
	id, err := routedDHCPServiceDirectoryV1(service)
	if err != nil {
		t.Fatal("expected exact service cgroup", err)
	}
	uid, _, err := routedDHCPServerAccountV1()
	if err != nil {
		t.Fatal("expected dedicated Kea account", err)
	}
	link, err := net.InterfaceByName("lan0")
	if err != nil || link.Index <= 0 {
		t.Fatal("expected the fixture LAN link", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	l := &routedEmptyListenersV3{kernel: &routedKernelV3{namespace: namespace, host: outside}}
	c, err := l.capture(ctx, nil, RoutedDHCPOwnerFactV3{})
	if err != nil {
		t.Fatal("capture packet and table rows", err)
	}
	c.udp, err = dhcpsockets.CaptureIPv4UDP(ctx)
	if err != nil {
		t.Fatal("capture UDP cgroup identity", err)
	}
	var holders []uint64
	for _, raw := range strings.Split(os.Getenv("ANDEIVA_NATIVE_KEA_SOCKET_HOLDERS_V1"), ",") {
		inode, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || inode == 0 {
			t.Fatal("invalid fixture descriptor identity", err)
		}
		holders = append(holders, inode)
	}
	b := routedDHCPServerSocketBindingV1{index: uint32(link.Index), address: netip.MustParseAddr("198.18.1.1")}
	others, facts, err := splitRoutedDHCPServerSocketsV1(c, id, uid, []routedDHCPServerSocketBindingV1{b}, holders)
	if err != nil || len(facts.udp) != 1 || len(facts.packet) != 1 || len(others.udp)+len(others.packet)+len(others.tables) != 0 {
		t.Fatal("expected just one owned Kea UDP and packet socket", err)
	}
	t.Log("verified dedicated Kea UDP/67 and AF_PACKET sockets on selected LAN")
}
