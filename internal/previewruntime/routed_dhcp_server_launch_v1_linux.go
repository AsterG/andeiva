//go:build linux

package previewruntime

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"golang.org/x/sys/unix"
)

const RoutedDHCPServerRoleV1 = "--andeiva-routed-dhcp-server-v1"
const RoutedDHCPServerRoleV2 = "--andeiva-routed-dhcp-server-v2"
const RoutedDHCPServerRoleV3 = "--andeiva-routed-dhcp-server-v3"
const routedDHCPServerBootstrapLimitV1 = 2*dhcpserver.MaxConfigBytes + 4096
const routedDHCPServerStopGraceV1 = 5*time.Second + routedDHCPOwnerCallV3 // Existing engine shutdown plus role IPC budget.

type routedDHCPServerBindingWireV1 struct {
	InterfaceID string `json:"interface_id"`
	Role        string `json:"role"`
	Address     string `json:"address"`
	Name        string `json:"name"`
	SubnetID    uint32 `json:"subnet_id"`
}

type routedDHCPServerCgroupWireV1 struct {
	Role   string `json:"role"`
	Name   string `json:"name"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type routedDHCPServerBootstrapV2 struct {
	Version            int                             `json:"version"`
	ParentPID          int                             `json:"parent_pid"`
	ParentStartTicks   uint64                          `json:"parent_start_ticks"`
	HostMountNamespace uint64                          `json:"host_mount_namespace"`
	DeadlineBootNS     int64                           `json:"deadline_boot_ns"`
	SupervisorLifetime bool                            `json:"supervisor_lifetime,omitempty"`
	Metadata           Metadata                        `json:"metadata"`
	Config             dhcpserver.Config               `json:"config"`
	Bindings           []routedDHCPServerBindingWireV1 `json:"bindings"`
	ServiceCgroups     []routedDHCPServerCgroupWireV1  `json:"service_cgroups"`
	LeaseBudgetBytes   int64                           `json:"lease_budget_bytes"`
	MountPins          []routedDHCPServerMountWireV2   `json:"mount_pins"`
}

// Handle pins the dedicated root role, not readiness or traffic permission.
// Root must independently observe Kea and drain its exact service cgroup before
// removing the namespace. No API/helper receives its control or writable FD.
type RoutedDHCPServerLaunchV1 struct {
	mu               sync.Mutex
	pid              int
	pidfd            int
	control          *os.File
	done             <-chan error
	stopOnce         sync.Once
	stopError        error
	stopWatch        func() bool
	startup          context.Context
	lifetime         context.Context
	startupBootNS    int64
	stopStartupWatch func() bool
	closed           bool
	stopping         bool
	waitGate         chan struct{}
	socketObserver   *routedKeaSocketObserverV1
}

func (s *RoutedDHCPServerLaunchV1) PID() int {
	if s == nil {
		return 0
	}
	return s.pid
}

func (s *RoutedDHCPServerLaunchV1) Alive() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aliveUnderV1()
}

func (s *RoutedDHCPServerLaunchV1) aliveUnderV1() bool {
	if s.closed || s.pidfd < 0 || s.pidfd > math.MaxInt32 {
		return false
	}
	poll := []unix.PollFd{{Fd: int32(s.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	return err == nil && n == 0
}

func (s *RoutedDHCPServerLaunchV1) inspectSocketsV3(ctx context.Context) (routedKeaSocketProofV1, error) {
	if s == nil || s.socketObserver == nil {
		return routedKeaSocketProofV1{}, ErrUnavailable
	}
	active := func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return !s.stopping && s.aliveUnderV1()
	}
	if !active() {
		return routedKeaSocketProofV1{}, ErrUnavailable
	}
	proof, err := s.socketObserver.observe(ctx)
	if err != nil || !active() {
		return routedKeaSocketProofV1{}, ErrUnavailable
	}
	return proof, nil
}

// Start is called only after selected-policy authorization under closed
// forwarding. It creates no configuration store, listener or timer when absent.
// The supplied lease directory is operational state and is never replaced.
func StartRoutedDHCPServerV1(ctx context.Context, o RoutedDHCPServerResourcesV1) (*RoutedDHCPServerLaunchV1, error) {
	return startRoutedDHCPServerScopedV2(ctx, nil, o)
}

// An authenticated selected-runtime caller supplies its supervisor context.
// The sealed bootstrap deadline bounds setup. The control pipe owns serving.
func startRoutedDHCPServerScopedV2(ctx, lifetime context.Context, o RoutedDHCPServerResourcesV1) (launch *RoutedDHCPServerLaunchV1, result error) {
	supervisorLifetime := lifetime != nil
	if o.socketProof && !supervisorLifetime {
		return nil, ErrIdentity
	}
	if !supervisorLifetime {
		lifetime = ctx
	}
	if ctx == nil || ctx.Err() != nil || lifetime.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || o.Metadata.ValidateRouted() != nil {
		return nil, ErrIdentity
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, ErrIdentity
	}
	now, err := routedDHCPOwnerBootNowV3()
	remaining := time.Until(deadline)
	if err != nil || remaining <= 0 || now > math.MaxInt64-int64(remaining) {
		return nil, ErrIdentity
	}
	if !routedDHCPOwnerNamespaceV3(o.Gateway, unix.CLONE_NEWNET, o.Metadata.GatewayNamespace) || !routedDHCPOwnerNamespaceV3(o.Host, unix.CLONE_NEWNET, o.Metadata.HostNamespace) {
		return nil, ErrIdentity
	}
	current, err := namespaceID("/proc/self/ns/net")
	thread, other := namespaceID("/proc/thread-self/ns/net")
	if err != nil || other != nil || current != o.Metadata.HostNamespace || thread != current {
		return nil, ErrIdentity
	}
	hostMount, err := namespaceID("/proc/self/ns/mnt")
	if err != nil || !routedDHCPOwnerNamespaceV3(o.HostMount, unix.CLONE_NEWNS, hostMount) {
		return nil, ErrIdentity
	}
	raw, err := routedDHCPOwnerReadV3("/proc/self/cgroup", 4096)
	if err != nil || string(raw) != "0::"+routedSupervisorCgroupV3+"\n" {
		return nil, ErrIdentity
	}
	parent, err := routedDHCPServiceParentV1()
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err = validateRoutedDHCPServerCgroupPinsV1(parent, o.ServiceCgroups); err != nil {
		return nil, err
	}
	var own *os.File
	for _, pin := range o.ServiceCgroups {
		if pin.Role == "lan" {
			own = pin.Directory
		}
	}
	if own == nil {
		return nil, ErrIdentity
	}
	uid, gid, err := routedDHCPServerAccountV1()
	if err != nil {
		return nil, err
	}
	artifact, err := dhcpkea.Compile(o.Config, o.Bindings)
	if err != nil || !artifact.Enabled || routedDHCPServerConfigFileV1(o.Configuration, artifact.JSON, gid) != nil {
		return nil, ErrIdentity
	}
	if err := routedDHCPServerLeasesV1(o.Leases, uid, gid, o.LeaseBudgetBytes); err != nil {
		return nil, err
	}
	mountPins, mountWire, err := prepareRoutedDHCPServerMountPinsV2(o.Configuration, o.Leases)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := mountPins.closeV2(); closeErr != nil {
			result = errors.Join(result, ErrUnavailable, closeErr)
			if launch != nil {
				result = errors.Join(result, launch.Stop(ctx))
				launch = nil
			}
		}
	}()
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/nsenter") != nil {
		return nil, ErrIdentity
	}
	start, _, err := routedDHCPOwnerProcessV3(os.Getpid())
	if err != nil {
		return nil, err
	}
	b := routedDHCPServerBootstrapV2{Version: 2, ParentPID: os.Getpid(), ParentStartTicks: start, HostMountNamespace: hostMount, DeadlineBootNS: now + int64(remaining), SupervisorLifetime: supervisorLifetime, Metadata: o.Metadata, Config: o.Config, LeaseBudgetBytes: o.LeaseBudgetBytes, MountPins: mountWire}
	var proof *net.UnixConn
	var roleProof *os.File
	if o.socketProof {
		proof, roleProof, err = routedDHCPJobPairV4()
		if err != nil {
			return nil, err
		}
		defer roleProof.Close()
		defer func() {
			if launch == nil {
				_ = proof.Close()
			}
		}()
		b.Version = 3
	}
	for _, binding := range o.Bindings {
		b.Bindings = append(b.Bindings, routedDHCPServerBindingWireV1{binding.Interface.InterfaceID, binding.Interface.Role, binding.Interface.Address.String(), binding.Name, binding.SubnetID})
	}
	for _, pin := range o.ServiceCgroups {
		b.ServiceCgroups = append(b.ServiceCgroups, routedDHCPServerCgroupWireV1{pin.Role, pin.Name, pin.Identity.Device, pin.Identity.Inode})
	}
	bootstrap, err := routedDHCPServerSealedBootstrapV2(b)
	if err != nil {
		return nil, err
	}
	defer bootstrap.Close()
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		return nil, ErrUnavailable
	}
	defer controlRead.Close()
	files := []*os.File{o.Gateway, o.Host, o.HostMount, o.Configuration, o.Leases, bootstrap, controlRead, mountPins.configuration, mountPins.leases}
	for _, pin := range o.ServiceCgroups {
		files = append(files, pin.Directory)
	}
	if roleProof != nil {
		files = append(files, roleProof)
	}
	if ctx.Err() != nil || lifetime.Err() != nil || !routedDHCPServerBeforeBootDeadlineV2(b.DeadlineBootNS) {
		return nil, errors.Join(ErrUnavailable, controlWrite.Close())
	}
	cmd := routedDHCPServerRoleCommandV1(self, files, int(own.Fd()))
	if roleProof != nil {
		cmd.Args[len(cmd.Args)-1] = RoutedDHCPServerRoleV3
	}
	fd, done, err := routedDHCPServerStartV1(cmd)
	if err != nil {
		return nil, errors.Join(err, controlWrite.Close())
	}
	s := &RoutedDHCPServerLaunchV1{pid: cmd.Process.Pid, pidfd: fd, control: controlWrite, done: done}
	if proof != nil {
		s.socketObserver = &routedKeaSocketObserverV1{conn: proof, peer: routedDHCPJobPeerV4{pid: s.pid}}
	}
	s.stopWatch = context.AfterFunc(lifetime, func() { _ = s.control.Close() })
	if supervisorLifetime {
		s.startup, s.lifetime, s.startupBootNS = ctx, lifetime, b.DeadlineBootNS
		s.stopStartupWatch = context.AfterFunc(ctx, func() { _ = s.control.Close() })
	}
	if ctx.Err() != nil || lifetime.Err() != nil || !routedDHCPServerBeforeBootDeadlineV2(b.DeadlineBootNS) {
		cleanup, cancel := context.WithTimeout(context.Background(), routedDHCPServerStopGraceV1)
		defer cancel()
		return nil, errors.Join(ErrUnavailable, s.Stop(cleanup))
	}
	return s, nil
}

// acceptStartupV2 hands lifetime to the retained control pipe after the caller
// verifies readiness and the selected Work again. It grants no network authority.
func (s *RoutedDHCPServerLaunchV1) acceptStartupV2() error {
	if s == nil {
		return ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.startup == nil || s.stopStartupWatch == nil {
		return ErrUnavailable
	}
	available := func() bool {
		return s.startup.Err() == nil && s.lifetime != nil && s.lifetime.Err() == nil && routedDHCPServerBeforeBootDeadlineV2(s.startupBootNS)
	}
	if !available() || !s.stopStartupWatch() || !available() {
		_ = s.control.Close()
		return ErrUnavailable
	}
	s.startup = nil
	return nil
}

func routedDHCPServerBeforeBootDeadlineV2(deadline int64) bool {
	now, err := routedDHCPOwnerBootNowV3()
	return err == nil && now > 0 && now < deadline
}

func routedDHCPServerRoleCommandV1(executable string, files []*os.File, cgroupFD int) *exec.Cmd {
	cmd := exec.Command("/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", executable, RoutedDHCPServerRoleV2) // #nosec G204 -- Fixed role, retained gateway FD and current root-trusted executable only.
	cmd.ExtraFiles = files
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: cgroupFD}
	return cmd
}

func routedDHCPServerSealedBootstrapV2(b routedDHCPServerBootstrapV2) (*os.File, error) {
	raw, err := json.Marshal(b)
	if err != nil || len(raw) == 0 || len(raw) > routedDHCPServerBootstrapLimitV1 {
		return nil, ErrIdentity
	}
	fd, err := unix.MemfdCreate("andeiva-dhcp-server-bootstrap", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), "sealed-dhcp-server-bootstrap")
	if _, err = file.Write(raw); err == nil {
		err = file.Chmod(0400)
	}
	if err == nil {
		_, err = unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
	}
	if err != nil {
		return nil, errors.Join(ErrUnavailable, file.Close())
	}
	return file, nil
}

// Stop waits for the role leader. It does not claim that its descendants or RAW
// sockets are gone; Root retains and verifies/drains the service cgroup next.
func (s *RoutedDHCPServerLaunchV1) Stop(ctx context.Context) error {
	if s == nil || ctx == nil || s.control == nil || s.done == nil || s.pid <= 1 || s.pidfd < 0 {
		return ErrIdentity
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrIdentity
	}
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopping = true
		s.mu.Unlock()
		if s.stopStartupWatch != nil {
			s.stopStartupWatch()
		}
		if s.stopWatch != nil {
			s.stopWatch()
		}
		_ = s.control.Close()
		if s.socketObserver != nil {
			_ = s.socketObserver.conn.Close()
		}
	})
	// Revocation is one-shot. Waiting is retryable: a timed-out caller retains
	// the pidfd until another bounded call observes Wait and closes it once.
	s.mu.Lock()
	if s.closed {
		err := s.stopError
		s.mu.Unlock()
		return err
	}
	if s.waitGate == nil {
		s.waitGate = make(chan struct{}, 1)
	}
	gate := s.waitGate
	s.mu.Unlock()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return errors.Join(ctx.Err(), s.killV1())
	}
	s.mu.Lock()
	closed, closeErr := s.closed, s.stopError
	s.mu.Unlock()
	if closed {
		return closeErr
	}
	grace := time.NewTimer(routedDHCPServerStopGraceV1)
	defer grace.Stop()
	select {
	case <-s.done:
	case <-ctx.Done():
		return errors.Join(ctx.Err(), s.killV1())
	case <-grace.C:
		if err := s.killV1(); err != nil {
			return err
		}
		select {
		case <-s.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.stopError = unix.Close(s.pidfd)
	return s.stopError
}

func (s *RoutedDHCPServerLaunchV1) killV1() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	err := unix.PidfdSendSignal(s.pidfd, unix.SIGKILL, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}
