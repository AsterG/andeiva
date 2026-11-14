//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"golang.org/x/sys/unix"
)

// Root's native harness supplies host NET/MNT/PID pins at FD3/4/5, enters
// separate NET/MNT/PID namespaces, binds its private fixture directory at
// /fixture, and keeps clients isolated until prepared.json is observed. No
// privileged invocation in WSL or CI. This is not managed-product readiness.
func TestNativeRoutedDHCPServerV1(t *testing.T) {
	mode := os.Getenv("ANDEIVA_DHCP_SERVER_NATIVE_V1")
	if mode == "" {
		t.Skip("requires reviewed Debian 13 isolated fixture")
	}
	if mode != "serve" && mode != "corrupt" || os.Getenv("CI") != "" || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("native profile refused")
	}
	var pins [3]*os.File
	var ids [3]uint64
	// Validate every namespace capability before opening anything else, then
	// seal all three so no host pin can leak to setpriv, Kea or its LFC child.
	for i, kind := range []int{unix.CLONE_NEWNET, unix.CLONE_NEWNS, unix.CLONE_NEWPID} {
		fd := i + 3
		var fs unix.Statfs_t
		var st unix.Stat_t
		actual, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
		if err != nil || actual != kind || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC || unix.Fstat(fd, &st) != nil {
			t.Fatal("namespace descriptor refused")
		}
		ids[i] = st.Ino
	}
	for i := range pins {
		fd := i + 3
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		pins[i] = os.NewFile(uintptr(fd), "native-host-namespace")
		defer pins[i].Close()
	}
	for i, kind := range []string{"net", "mnt", "pid"} {
		actual, err := namespaceID("/proc/self/ns/" + kind)
		thread, other := namespaceID("/proc/thread-self/ns/" + kind)
		if err != nil || other != nil || actual == ids[i] || actual != thread {
			t.Fatal("host/current namespace refused")
		}
	}
	_ = pins[2].Close()
	release, err := os.ReadFile("/etc/os-release")
	kernel, other := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil || other != nil || !bytes.Contains(release, []byte("ID=debian\n")) || !bytes.Contains(release, []byte("VERSION_ID=\"13\"")) || bytes.Contains(bytes.ToLower(kernel), []byte("microsoft")) {
		t.Fatal("Debian native only")
	}
	fixture, err := os.OpenRoot("/fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	info, err := fixture.Stat(".")
	if err != nil || info.Mode() != os.ModeDir|0700 || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("fixture root")
	}
	if _, err = fixture.Stat("prepared.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale prepared observation")
	}
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil {
		t.Fatal(err)
	}
	leaseDir, err := fixture.OpenFile("leases", os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer leaseDir.Close()
	c := dhcpserver.Config{SchemaVersion: 1, Enabled: true, Scopes: []dhcpserver.Scope{{ID: "native-lan", InterfaceID: "lan", Subnet: "198.18.1.0/24", Router: "198.18.1.1", Pools: []dhcpserver.Pool{{First: "198.18.1.100", Last: "198.18.1.100"}}, LeaseSeconds: 120, RenewSeconds: 60, RebindSeconds: 105}}}
	b := []dhcpkea.Binding{{Interface: dhcpserver.Binding{InterfaceID: "lan", Role: "lan", Address: netip.MustParsePrefix("198.18.1.1/24")}, Name: "lan0", SubnetID: 17}}
	a, err := dhcpkea.Compile(c, b)
	if err != nil {
		t.Fatal(err)
	}
	config, err := fixture.OpenFile("config.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, err = config.Write(a.JSON)
		if err == nil {
			err = config.Chown(0, int(gid))
		}
		if err == nil {
			err = config.Chmod(0440)
		}
		if err == nil {
			err = config.Sync()
		}
		_ = config.Close()
	}
	if err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	config, err = fixture.OpenFile("config.json", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if err = routedDHCPServerConfigFileV1(config, a.JSON, gid); err != nil {
		t.Fatal(err)
	}
	gw, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	ns, err := namespaceID("/proc/self/ns/net")
	if err != nil {
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
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	o := RoutedDHCPServerResourcesV1{Metadata: Metadata{SchemaVersion: 2, RunID: hex.EncodeToString(nonce[:]), BootID: bootID, HostNamespace: ids[0], GatewayNamespace: ns}, Gateway: gw, Host: pins[0], HostMount: pins[1], Configuration: config, Leases: leaseDir, Config: c, Bindings: b, LeaseBudgetBytes: 4 << 20}
	sig, cancelSignal := signal.NotifyContext(context.Background(), unix.SIGTERM)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(sig, 120*time.Second)
	defer cancel()
	if mode == "corrupt" {
		original, e := fixture.ReadFile("leases/kea-leases4.csv")
		if e != nil {
			t.Fatal(e)
		}
		before := sha256.Sum256(original)
		err = RunRoutedDHCPServerComponentV1(ctx, o)
		after, e := fixture.ReadFile("leases/kea-leases4.csv")
		if !errors.Is(err, errRoutedDHCPServerLeaseRowV1) || e != nil || before != sha256.Sum256(after) {
			t.Fatal("corrupt-row gate did not preserve/reject", err, e)
		}
		t.Log("maintained loader rejected corrupt row; original unchanged; no serving process launched")
		return
	}
	done := make(chan error, 1)
	go func() { done <- RunRoutedDHCPServerComponentV1(ctx, o) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	prepared := false
	for !prepared {
		select {
		case err := <-done:
			t.Fatal("component exited before observed preparation", err)
		case <-ctx.Done():
			t.Fatal("native preparation deadline")
		case <-ticker.C:
			pid := nativeRoutedDHCPServerObservedV1(uid, gid, ns)
			if pid == 0 {
				continue
			}
			file, e := fixture.OpenFile("prepared.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				t.Fatal(e)
			}
			e = json.NewEncoder(file).Encode(struct {
				PID       int    `json:"pid"`
				Namespace uint64 `json:"namespace"`
				UID       uint32 `json:"uid"`
				Digest    string `json:"config_sha256"`
			}{pid, ns, uid, a.Digest})
			if e == nil {
				e = file.Sync()
			}
			_ = file.Close()
			if e != nil {
				t.Fatal(e)
			}
			prepared = true
		}
	}
	err = <-done
	if !errors.Is(err, context.Canceled) || sig.Err() == nil {
		t.Fatal("component did not stop through explicit native SIGTERM", err)
	}
	if nativeRoutedDHCPServerObservedV1(uid, gid, ns) != 0 {
		t.Fatal("engine remains")
	}
	t.Log("component prepared and explicitly stopped; DORA/restart assertions belong to outer fixture")
}

// Test-only observation: actual dedicated process, both capability sets and
// AppArmor enforcement plus a LAN raw socket owned by that exact process.
func nativeRoutedDHCPServerObservedV1(uid, gid uint32, ns uint64) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	lan, err := net.InterfaceByName("lan0")
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid <= 1 {
			continue
		}
		prefix := "/proc/" + entry.Name()
		exe, e := os.Readlink(prefix + "/exe")
		if e != nil || exe != "/usr/sbin/kea-dhcp4" {
			continue
		}
		actual, e := namespaceID(prefix + "/ns/net")
		if e != nil || actual != ns {
			continue
		}
		_, parent, e := routedDHCPOwnerProcessV3(pid)
		if e != nil || parent != os.Getpid() {
			continue
		}
		status, e := os.ReadFile(prefix + "/status")
		if e != nil {
			continue
		}
		good := true
		for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
			if !bytes.Contains(status, []byte(field+":\t0000000000002400\n")) {
				good = false
			}
		}
		for _, line := range []string{fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid), fmt.Sprintf("Gid:\t%d\t%d\t%d\t%d\n", gid, gid, gid, gid), "NoNewPrivs:\t1\n"} {
			if !bytes.Contains(status, []byte(line)) {
				good = false
			}
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Groups:") && len(strings.Fields(strings.TrimPrefix(line, "Groups:"))) != 0 {
				good = false
			}
		}
		profile, e := os.ReadFile(prefix + "/attr/current")
		if e != nil || strings.TrimSpace(string(profile)) != "kea-dhcp4 (enforce)" || !good {
			continue
		}
		fds, e := os.ReadDir(prefix + "/fd")
		if e != nil || len(fds) > 256 {
			continue
		}
		owned := map[string]bool{}
		for _, fd := range fds {
			link, e := os.Readlink(prefix + "/fd/" + fd.Name())
			if e == nil && strings.HasPrefix(link, "socket:[") {
				owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
		raw, e := os.ReadFile(prefix + "/net/packet")
		if e != nil || len(raw) > 65536 {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 9 && fields[2] == "3" && fields[3] == "0003" && fields[4] == strconv.Itoa(lan.Index) && fields[7] == strconv.FormatUint(uint64(uid), 10) && owned[fields[8]] {
				return pid
			}
		}
	}
	return 0
}
