//go:build linux

package previewruntime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpclient"
	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

type routedDHCPOwnerSourceV3 interface {
	Current() (routedDHCPOwnerLeaseV3, error)
}
type routedDHCPOwnerClientV3 struct{ client *dhcpclient.Client }

func (s routedDHCPOwnerClientV3) Current() (routedDHCPOwnerLeaseV3, error) {
	o, err := s.client.ObserveAcquisition()
	if err == nil && o.State == dhcpclient.AcquisitionInitialWaiting {
		return routedDHCPOwnerLeaseV3{}, errRoutedDHCPInitialWaitingV1
	}
	if err == nil && o.State == dhcpclient.AcquisitionNoLease && o.ObservedEpoch > 0 {
		return routedDHCPOwnerLeaseV3{}, routedDHCPNoLeaseV1{o.ObservedEpoch}
	}
	if err != nil || o.State != dhcpclient.AcquisitionGranted {
		return routedDHCPOwnerLeaseV3{}, ErrUnavailable
	}
	l := o.Lease
	return routedDHCPOwnerLeaseV3{l.Event, l.Epoch, l.DeadlineBootNS}, err
}

func serveRoutedDHCPOwnerV3(ctx context.Context, request, reply *os.File, incarnation string, source routedDHCPOwnerSourceV3) error {
	if ctx == nil || request == nil || reply == nil || source == nil || !ValidRun(incarnation) {
		return ErrIdentity
	}
	stop := context.AfterFunc(ctx, func() { _ = request.Close(); _ = reply.Close() })
	defer stop()
	scan := routedDHCPOwnerScannerV3(request)
	var sequence uint64
	for scan.Scan() {
		var q routedDHCPOwnerRequestV3
		if sequence == ^uint64(0) || routedDHCPOwnerDecodeV3(scan.Bytes(), &q) != nil || q.Version != 3 || q.Incarnation != incarnation || q.Sequence != sequence+1 || q.Operation != "current" || ctx.Err() != nil {
			return ErrIdentity
		}
		sequence = q.Sequence
		lease, err := source.Current()
		r := routedDHCPOwnerReplyV3{Version: 3, Incarnation: incarnation, Sequence: sequence, Unavailable: err != nil}
		if err == nil {
			r.Lease = &lease
		}
		if reply.SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPOwnerWriteV3(reply, r) != nil {
			return ErrUnavailable
		}
	}
	return ErrUnavailable // EOF never leaves an acquisition owner running.
}

func routedDHCPOwnerPrivateMountsV3() error {
	// Called only after the bootstrap proves a different root-created mount
	// namespace. All mount targets and tmpfs quotas are fixed, never DHCP data.
	for _, path := range []string{"/run", "/var/lib"} {
		for part := path; ; part = filepath.Dir(part) {
			var st unix.Stat_t
			if unix.Lstat(part, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
				return ErrIdentity
			}
			if part == "/" {
				break
			}
		}
	}
	if unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "") != nil {
		return ErrUnavailable
	}
	for _, path := range []string{"/run", "/var/lib"} {
		if unix.Mount("tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=4m,nr_inodes=128") != nil {
			return ErrUnavailable
		}
	}
	for _, path := range []string{"/run/dhcpcd", "/run/andeiva-dhcp", "/var/lib/dhcpcd"} {
		// The mounted root permits privsep traversal; its hidden mountpoint is
		// private even under a restrictive supervisor umask.
		if os.Mkdir(path, 0700) != nil || unix.Mount("tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=1m,nr_inodes=128") != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// Run is a root-only dispatch entry, not a user command. FDs 3..11 belong to
// this separate role, not to the helper's integrity/retirement descriptor map.
func RunRoutedDHCPOwnerRoleV3(parent context.Context) (result error) {
	return runRoutedDHCPOwnerProfileV3(parent, 3)
}
func runRoutedDHCPOwnerProfileV3(parent context.Context, profile int) (result error) {
	if profile != 3 && profile != 4 {
		return ErrIdentity
	}
	if parent == nil || parent.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	var files [9]*os.File
	defer func() {
		for _, f := range files {
			if f != nil {
				_ = f.Close()
			}
		}
	}()
	// Validate the ninth descriptor before pipe initialization can allocate a
	// poll descriptor into a missing inherited slot.
	files[8] = os.NewFile(11, "dhcp-service-cgroup")
	if _, e := routedDHCPServiceDirectoryV1(files[8]); e != nil {
		return e
	}
	unix.CloseOnExec(11)
	for i := range 8 {
		fd := i + 3
		if fd >= 6 && unix.SetNonblock(fd, true) != nil {
			return ErrIdentity
		}
		files[i] = os.NewFile(uintptr(fd), "routed-dhcp-owner")
		unix.CloseOnExec(fd)
	}
	for i, access := range map[int]int{3: unix.O_RDONLY, 4: unix.O_WRONLY, 5: unix.O_RDONLY, 6: unix.O_WRONLY, 7: unix.O_RDONLY} {
		if !routedDHCPOwnerPipeV3(files[i], access) {
			return ErrIdentity
		}
	}
	if files[3].SetReadDeadline(time.Now().Add(10*time.Second)) != nil {
		return ErrIdentity
	}
	scan := routedDHCPOwnerScannerV3(files[3])
	if !scan.Scan() {
		return ErrIdentity
	}
	var b routedDHCPOwnerBootstrapV3
	if routedDHCPOwnerDecodeV3(scan.Bytes(), &b) != nil || scan.Scan() || scan.Err() != nil || b.Version != profile || !ValidRun(b.Incarnation) || b.Metadata.ValidateRouted() != nil || b.ParentPID != os.Getppid() || b.ParentPID <= 1 || b.MountNamespace == 0 || b.MountNamespace == b.HostMountNamespace {
		return ErrIdentity
	}
	_ = files[3].Close()
	start, _, err := routedDHCPOwnerProcessV3(b.ParentPID)
	status, statusErr := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(b.ParentPID)+"/status", 65536)
	if err != nil || start != b.ParentStartTicks || statusErr != nil || !rootRoutedParentStatusV3(status, b.ParentPID) || validateRoutedDHCPServiceRoleV1(files[8], b.Incarnation, b.ServiceCgroupVersion, RoutedDHCPServiceCgroupIdentityV1{b.ServiceCgroupDevice, b.ServiceCgroupInode}) != nil {
		return ErrIdentity
	}
	if unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0) != nil || b.ParentPID != os.Getppid() {
		return ErrIdentity
	}
	if !routedDHCPOwnerNamespaceV3(files[0], unix.CLONE_NEWNET, b.Metadata.GatewayNamespace) || !routedDHCPOwnerNamespaceV3(files[1], unix.CLONE_NEWNET, b.Metadata.HostNamespace) || !routedDHCPOwnerNamespaceV3(files[2], unix.CLONE_NEWNS, b.HostMountNamespace) {
		return ErrIdentity
	}
	for kind, want := range map[string]uint64{"net": b.Metadata.GatewayNamespace, "mnt": b.MountNamespace} {
		leader, e := namespaceID("/proc/self/ns/" + kind)
		thread, other := namespaceID("/proc/thread-self/ns/" + kind)
		if e != nil || other != nil || leader != want || thread != want {
			return ErrIdentity
		}
	}
	desired, err := networkexecutor.CanonicalLANBootstrapPlanV3(b.Desired)
	if err != nil || desired.Hash != b.Desired.Hash {
		return ErrIdentity
	}
	var wan networkplan.Binding
	for _, iface := range desired.Config.Interfaces {
		if iface.Role == networkplan.WAN {
			wan = iface.Binding
		}
	}
	iface, err := net.InterfaceByName(wan.Name)
	if err != nil || iface.HardwareAddr.String() != wan.HardwareAddress || iface.Flags&net.FlagUp == 0 {
		return ErrIdentity
	}
	if err = routedDHCPOwnerPrivateMountsV3(); err != nil {
		return err
	}
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil || unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		return ErrIdentity
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if profile == 4 {
		return runRoutedDHCPDeferredRoleV4(ctx, b, [8]*os.File(files[:8]), dhcpclient.Scope{HostNetwork: files[1], HostMount: files[2], Interface: wan.Name, Index: iface.Index, HardwareAddress: wan.HardwareAddress})
	}
	client, err := dhcpclient.StartIsolated(ctx, dhcpclient.Scope{HostNetwork: files[1], HostMount: files[2], Interface: wan.Name, Index: iface.Index, HardwareAddress: wan.HardwareAddress})
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		client.Stop()
		if e := routedDHCPOwnerDrainV3(); e != nil {
			result = e
		}
	}()
	leasePID, err := strconv.Atoi(client.PID())
	if err != nil {
		return ErrIdentity
	}
	leaseStart, ppid, err := routedDHCPOwnerProcessV3(leasePID)
	if err != nil || ppid != os.Getpid() {
		return ErrIdentity
	}
	roleStart, ppid, err := routedDHCPOwnerProcessV3(os.Getpid())
	if err != nil || ppid != b.ParentPID {
		return ErrIdentity
	}
	ready := routedDHCPOwnerReadyV3{3, b.Incarnation, os.Getpid(), roleStart, leasePID, leaseStart, false}
	if files[4].SetWriteDeadline(time.Now().Add(10*time.Second)) != nil || routedDHCPOwnerWriteV3(files[4], ready) != nil {
		return ErrUnavailable
	}
	var control sync.WaitGroup
	validStop := false
	control.Go(func() {
		controlScan := routedDHCPOwnerScannerV3(files[7])
		if controlScan.Scan() {
			var q routedDHCPOwnerRequestV3
			validStop = routedDHCPOwnerDecodeV3(controlScan.Bytes(), &q) == nil && q.Version == 3 && q.Incarnation == b.Incarnation && q.Sequence == 1 && q.Operation == "stop"
		}
		// Every root control event, including malformed input/EOF, only stops.
		cancel()
	})
	result = serveRoutedDHCPOwnerV3(ctx, files[5], files[6], b.Incarnation, routedDHCPOwnerClientV3{client})
	cancel()
	_ = files[7].Close()
	control.Wait()
	client.Stop()
	if err = routedDHCPOwnerDrainV3(); err != nil {
		return err
	}
	if !validStop {
		return ErrUnavailable
	}
	ready.Stopped = true
	if files[4].SetWriteDeadline(time.Now().Add(routedDHCPOwnerCallV3)) != nil || routedDHCPOwnerWriteV3(files[4], ready) != nil {
		return ErrUnavailable
	}
	return nil
}
