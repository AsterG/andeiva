//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"golang.org/x/sys/unix"
)

const routedDHCPServerConfigV1 = "/etc/kea/kea-dhcp4.conf"

var errRoutedDHCPServerLeaseRowV1 = errors.New("ANDEIVA_DHCP_LEASE_ROW_INVALID")

// Component resources are borrowed from trusted Root assembly, never an API.
// The caller runs this in a dedicated Root role already entered into the owned
// gateway and a private mount namespace, inside the existing grouped cgroup.
// Selection authorization, policy and stable subnet IDs remain assembly gates.
type RoutedDHCPServerResourcesV1 struct {
	Metadata                                        Metadata
	Gateway, Host, HostMount, Configuration, Leases *os.File
	Config                                          dhcpserver.Config
	Bindings                                        []dhcpkea.Binding
	// Trusted storage-plan budget for existing lease/LFC files, not a request
	// option. This preflight bound does not enforce ongoing filesystem quotas.
	LeaseBudgetBytes int64
}

// Run is an opt-in component, not a production dispatch or readiness API. The
// context must have a deadline; Root owns its execution budget. It preserves
// lease files and drains its children before returning. The role must then exit
// to release its private mounts; outer cgroup drainage remains mandatory.
func RunRoutedDHCPServerComponentV1(ctx context.Context, o RoutedDHCPServerResourcesV1) (result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrIdentity
	}
	if o.LeaseBudgetBytes <= 0 || o.LeaseBudgetBytes > (math.MaxInt64-dhcpkea.MaxArtifactBytes)/2 {
		return ErrIdentity
	}
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil {
		return err
	}
	a, err := dhcpkea.Compile(o.Config, o.Bindings)
	if err != nil || !a.Enabled || o.Metadata.ValidateRouted() != nil {
		return ErrIdentity
	}
	if err = routedDHCPServerScopeV1(o); err != nil {
		return fmt.Errorf("dhcp server isolated scope: %w", err)
	}
	if err = routedDHCPServerConfigFileV1(o.Configuration, a.JSON); err != nil {
		return fmt.Errorf("dhcp server compiled configuration: %w", err)
	}
	if err = routedDHCPServerLeasesV1(o.Leases, uid, gid, o.LeaseBudgetBytes); err != nil {
		return err
	}
	// Lock the owned directory for the whole run. No new configuration database
	// or package-manager lock is created; cooperating engine owners share this FD.
	if unix.Flock(int(o.Leases.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return ErrUnavailable
	}
	defer func() { result = errors.Join(result, unix.Flock(int(o.Leases.Fd()), unix.LOCK_UN)) }()
	if err = routedDHCPServerLeasesV1(o.Leases, uid, gid, o.LeaseBudgetBytes); err != nil {
		return err
	}
	if err = routedDHCPServerNoChildrenV1(); err != nil {
		return err
	}
	// Dedicated role only: seal even unknown inherited descriptors before the
	// first exec, including host namespace pins. New Go descriptors use CLOEXEC.
	if unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC) != nil {
		return ErrIdentity
	}
	unix.Umask(0077)
	for _, path := range []string{"/usr/bin/setpriv", "/usr/sbin/kea-dhcp4", "/usr/sbin/kea-lfc"} {
		if trustedRoutedExecutableV3(path) != nil {
			return ErrIdentity
		}
	}
	if err = routedDHCPServerMountsV1(o, uid, gid); err != nil {
		return fmt.Errorf("dhcp server private mounts: %w", err)
	}
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		return ErrIdentity
	}
	defer func() { result = errors.Join(result, routedDHCPOwnerDrainV3()) }()
	// -T forces persist=false in Kea 2.6.3 and cannot validate lease history.
	// Use its maintained LFC reader on private copies, never the original data.
	if err = routedDHCPServerCheckCopiesV1(ctx, o, uid, gid); err != nil {
		return fmt.Errorf("dhcp server maintained lease reader: %w", err)
	}
	if err = routedDHCPOwnerDrainV3(); err != nil {
		return err
	}
	if err = routedDHCPServerLeasesV1(o.Leases, uid, gid, o.LeaseBudgetBytes); err != nil {
		return err
	}
	if err = routedDHCPServerBindV1(o.Leases, "/var/lib/kea", false); err != nil {
		return err
	}
	return routedDHCPServerExecV1(ctx, uid, gid, false, os.Stdout)
}

func routedDHCPServerAccountV1() (uint32, uint32, error) {
	u, err := user.Lookup("_kea")
	if err != nil {
		return 0, 0, ErrIdentity
	}
	uid, e := strconv.ParseUint(u.Uid, 10, 32)
	gid, g := strconv.ParseUint(u.Gid, 10, 32)
	if e != nil || g != nil || uid == 0 || gid == 0 || uid >= 1<<31 || gid >= 1<<31 {
		return 0, 0, ErrIdentity
	}
	return uint32(uid), uint32(gid), nil
}

func routedDHCPServerScopeV1(o RoutedDHCPServerResourcesV1) error {
	m := o.Metadata
	if o.HostMount == nil {
		return ErrIdentity
	}
	if m.GatewayNamespace == m.HostNamespace || !routedDHCPOwnerNamespaceV3(o.Gateway, unix.CLONE_NEWNET, m.GatewayNamespace) || !routedDHCPOwnerNamespaceV3(o.Host, unix.CLONE_NEWNET, m.HostNamespace) {
		return ErrIdentity
	}
	hostMountInfo, err := o.HostMount.Stat()
	if err != nil {
		return ErrIdentity
	}
	hostMount := hostMountInfo.Sys().(*syscall.Stat_t).Ino
	if !routedDHCPOwnerNamespaceV3(o.HostMount, unix.CLONE_NEWNS, hostMount) {
		return ErrIdentity
	}
	for _, path := range []string{"/proc/self/ns/net", "/proc/thread-self/ns/net"} {
		id, e := namespaceID(path)
		if e != nil || id != m.GatewayNamespace {
			return ErrIdentity
		}
	}
	mount, err := namespaceID("/proc/self/ns/mnt")
	threadMount, e := namespaceID("/proc/thread-self/ns/mnt")
	if err != nil || e != nil || mount == hostMount || mount != threadMount {
		return ErrIdentity
	}
	boot, err := routedDHCPOwnerReadV3("/proc/sys/kernel/random/boot_id", 128)
	id, e := canonicalBoot(boot)
	if err != nil || e != nil || id != m.BootID || routedDHCPOwnerCgroupV3() != nil {
		return ErrIdentity
	}
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		raw, err := routedDHCPOwnerReadV3(path, 16)
		if err != nil || string(raw) != "0\n" {
			return ErrIdentity
		}
	}
	for _, b := range o.Bindings {
		iface, e := net.InterfaceByName(b.Name)
		if e != nil || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			return ErrIdentity
		}
		addresses, e := iface.Addrs()
		if e != nil {
			return ErrIdentity
		}
		found := false
		for _, address := range addresses {
			if address.String() == b.Interface.Address.String() {
				found = true
			}
		}
		if !found {
			return ErrIdentity
		}
	}
	return nil
}

func routedDHCPServerConfigFileV1(f *os.File, expected []byte) error {
	if f == nil {
		return ErrIdentity
	}
	var st unix.Stat_t
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0444 && st.Mode&07777 != 0644 || st.Nlink != 1 || st.Size != int64(len(expected)) || !fenceNoACLV3(f, false) {
		return ErrIdentity
	}
	actual := make([]byte, len(expected))
	if _, err = f.ReadAt(actual, 0); err != nil || !bytes.Equal(actual, expected) {
		return ErrIdentity
	}
	return nil
}

func routedDHCPServerLeasesV1(f *os.File, uid, gid uint32, budget int64) error {
	if f == nil || uid == 0 || gid == 0 || budget <= 0 {
		return ErrIdentity
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != uid || st.Gid != gid || !fenceNoACLV3(f, true) {
		return ErrIdentity
	}
	// A separate open description avoids changing the caller's directory offset.
	fd, err := unix.Openat(int(f.Fd()), ".", unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIdentity
	}
	dir := os.NewFile(uintptr(fd), "kea-lease-directory")
	defer dir.Close()
	entries, err := dir.ReadDir(7)
	if err != nil && err != io.EOF || len(entries) > 6 {
		return ErrIdentity
	}
	var total int64
	for _, entry := range entries {
		if !routedDHCPServerLeaseNameV1(entry.Name()) {
			return ErrIdentity
		}
		fd, e := unix.Openat(int(f.Fd()), entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e != nil {
			return ErrIdentity
		}
		lease := os.NewFile(uintptr(fd), "kea-lease-file")
		valid := unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Nlink == 1 && st.Uid == uid && st.Gid == gid && st.Size > 0 && st.Size <= budget-total && fenceNoACLV3(lease, false)
		_ = lease.Close()
		if !valid {
			return ErrIdentity
		}
		total += st.Size
	}
	return nil
}

func routedDHCPServerLeaseNameV1(name string) bool {
	switch name {
	case "kea-leases4.csv", "kea-leases4.csv.1", "kea-leases4.csv.2", "kea-leases4.csv.output", "kea-leases4.csv.completed":
		return true
	default:
		return false // Includes active/uncertain LFC pid files and aliases.
	}
}

func routedDHCPServerNoChildrenV1() error {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil || len(tasks) > 128 {
		return ErrIdentity
	}
	for _, task := range tasks {
		tid, e := strconv.Atoi(task.Name())
		if e != nil || tid <= 0 {
			return ErrIdentity
		}
		raw, e := routedDHCPOwnerReadV3(fmt.Sprintf("/proc/self/task/%d/children", tid), 8192)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || len(strings.Fields(string(raw))) != 0 {
			return ErrIdentity
		}
	}
	return nil
}

// Only after current-thread and process namespace proofs, never on the host.
func routedDHCPServerMountsV1(o RoutedDHCPServerResourcesV1, uid, gid uint32) error {
	if uid == 0 || gid == 0 || uid >= 1<<31 || gid >= 1<<31 {
		return ErrIdentity
	}
	for _, path := range []string{"/etc", "/etc/kea", "/var", "/var/lib", "/run"} {
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 || st.Uid != 0 {
			return ErrIdentity
		}
	}
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		return ErrUnavailable
	}
	// Same bounded scratch profile as the existing isolated DHCP owner; the
	// persistent directory is a bind, never tmpfs or a configuration snapshot.
	for _, path := range []string{"/run", "/var/lib", "/etc/kea"} {
		if unix.Mount("tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=4m,nr_inodes=128") != nil {
			return ErrUnavailable
		}
	}
	// Packages installed without autostart need not have created /var/lib/kea.
	// Make the destination only after hiding /var/lib with private tmpfs.
	if os.Mkdir("/var/lib/kea", 0700) != nil || os.Chown("/var/lib/kea", int(uid), int(gid)) != nil {
		return ErrUnavailable
	}
	for _, path := range []string{"/run/kea", "/run/lock", "/run/lock/kea"} {
		if os.Mkdir(path, 0755) != nil {
			return ErrUnavailable
		}
		if path != "/run/lock" && os.Chown(path, int(uid), int(gid)) != nil {
			return ErrUnavailable
		}
	}
	file, err := os.OpenFile(routedDHCPServerConfigV1, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
	if err != nil {
		return ErrUnavailable
	}
	if file.Close() != nil {
		return ErrUnavailable
	}
	return routedDHCPServerBindV1(o.Configuration, routedDHCPServerConfigV1, true)
}

func routedDHCPServerBindV1(file *os.File, path string, readonly bool) error {
	if unix.Mount(fmt.Sprintf("/proc/self/fd/%d", file.Fd()), path, "", unix.MS_BIND, "") != nil {
		return ErrUnavailable
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if readonly {
		flags |= unix.MS_RDONLY
	}
	if unix.Mount("", path, "", flags, "") != nil {
		return ErrUnavailable
	}
	before, e := file.Stat()
	after, other := os.Stat(path)
	if e != nil || other != nil || !os.SameFile(before, after) {
		return ErrIdentity
	}
	return nil
}

func routedDHCPServerCommandV1(uid, gid uint32, check bool) *exec.Cmd {
	caps := "-all,+net_bind_service,+net_raw"
	profile := "kea-dhcp4"
	engine := []string{"/usr/sbin/kea-dhcp4", "-c", routedDHCPServerConfigV1}
	if check {
		caps, profile = "-all", "kea-lfc"
		engine = []string{"/usr/sbin/kea-lfc", "-4", "-d", "-p", dhcpkea.LeaseFile + ".pid", "-x", dhcpkea.LeaseFile + ".2", "-i", dhcpkea.LeaseFile + ".1", "-o", dhcpkea.LeaseFile + ".output", "-f", dhcpkea.LeaseFile + ".completed", "-c", routedDHCPServerConfigV1}
	}
	args := []string{"--reuid=" + strconv.FormatUint(uint64(uid), 10), "--regid=" + strconv.FormatUint(uint64(gid), 10), "--clear-groups", "--bounding-set=" + caps, "--inh-caps=" + caps, "--ambient-caps=" + caps, "--no-new-privs", "--pdeathsig=SIGKILL", "--apparmor-profile=" + profile, "--"}
	args = append(args, engine...)
	cmd := exec.Command("/usr/bin/setpriv", args...) // #nosec G204 -- Fixed binaries, options and path; numeric Root-validated dedicated account only.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	return cmd
}

func routedDHCPServerExecV1(ctx context.Context, uid, gid uint32, check bool, output io.Writer) error {
	cmd := routedDHCPServerCommandV1(uid, gid, check)
	cmd.Stdout, cmd.Stderr = output, output
	// No ExtraFiles: host namespace, lease and config FDs must remain CLOEXEC.
	started := make(chan error, 1)
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err == nil {
			err = cmd.Wait()
		}
		done <- err
	}()
	if err := <-started; err != nil {
		return ErrUnavailable
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		<-done
		return ErrUnavailable
	}
	defer unix.Close(fd)
	select {
	case err = <-done:
		if err != nil || ctx.Err() != nil || !check {
			return ErrUnavailable
		}
		return nil
	case <-ctx.Done():
		_ = unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0)
		select {
		case <-done:
		case <-time.After(5 * time.Second): // Existing DHCP owner shutdown budget.
			_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
			<-done
		}
		return ctx.Err()
	}
}

// Bounded private capture; no lease data or engine diagnostics enter public
// errors. LFC exit zero alone is insufficient (see its LFC_TERMINATE message).
type routedDHCPServerLogV1 struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *routedDHCPServerLogV1) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > dhcpkea.MaxArtifactBytes-len(b.data) {
		b.overflow = true
		return 0, ErrUnavailable
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
