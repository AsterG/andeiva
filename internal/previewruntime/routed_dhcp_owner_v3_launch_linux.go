//go:build linux

package previewruntime

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/AsterG/andeiva/internal/networkexecutor"
	"github.com/AsterG/andeiva/internal/networkplan"
	"golang.org/x/sys/unix"
)

type routedDHCPOwnerBootstrapV3 struct {
	Version            int                  `json:"version"`
	ParentPID          int                  `json:"parent_pid"`
	ParentStartTicks   uint64               `json:"parent_start_ticks"`
	Metadata           Metadata             `json:"metadata"`
	Desired            networkplan.Revision `json:"desired"`
	Incarnation        string               `json:"incarnation"`
	MountNamespace     uint64               `json:"mount_namespace"`
	HostMountNamespace uint64               `json:"host_mount_namespace"`
}
type routedDHCPOwnerReadyV3 struct {
	Version         int    `json:"version"`
	Incarnation     string `json:"incarnation"`
	RolePID         int    `json:"role_pid"`
	RoleStartTicks  uint64 `json:"role_start_ticks"`
	LeasePID        int    `json:"lease_pid"`
	LeaseStartTicks uint64 `json:"lease_start_ticks"`
	Stopped         bool   `json:"stopped,omitempty"`
}

type RoutedDHCPOwnerV3 struct {
	mu                     sync.Mutex
	cmd                    *exec.Cmd
	control, events, mount *os.File
	scanner                *bufio.Scanner
	files                  RoutedDHCPOwnerFilesV3
	binding                RoutedDHCPOwnerBindingV3
	done                   chan struct{}
	closed, transferred    bool
	closeErr               error
}

// Start launches only the current trusted executable's fixed DHCP role. The
// caller must dispatch that role, retain the dedicated cgroup and finally use
// the existing whole-cgroup drainage gate before retiring its gateway scope.
// It starts acquisition immediately: trusted root must first complete helper
// integrity readiness, LAN bootstrap/readback and independent EmptyListeners
// validation for this exact Desired revision. This function is not an API gate.
func StartRoutedDHCPOwnerV3(ctx context.Context, o RoutedDHCPOwnerOptionsV3) (_ *RoutedDHCPOwnerV3, result error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || o.Metadata.ValidateRouted() != nil || !routedDHCPOwnerNamespaceV3(o.Gateway, unix.CLONE_NEWNET, o.Metadata.GatewayNamespace) || !routedDHCPOwnerNamespaceV3(o.Host, unix.CLONE_NEWNET, o.Metadata.HostNamespace) || routedDHCPOwnerCgroupV3() != nil {
		return nil, ErrIdentity
	}
	current, err := namespaceID("/proc/self/ns/net")
	thread, threadErr := namespaceID("/proc/thread-self/ns/net")
	if err != nil || threadErr != nil || current != o.Metadata.HostNamespace || thread != current {
		return nil, ErrIdentity
	}
	bootBytes, err := routedDHCPOwnerReadV3("/proc/sys/kernel/random/boot_id", 128)
	boot, bootErr := canonicalBoot(bootBytes)
	if err != nil || bootErr != nil || boot != o.Metadata.BootID {
		return nil, ErrIdentity
	}
	desired, err := networkexecutor.CanonicalLANBootstrapPlanV3(o.Desired)
	if err != nil || desired.Hash != o.Desired.Hash {
		return nil, ErrIdentity
	}
	self, err := os.Executable()
	if err != nil || trustedRoutedExecutableV3(self) != nil || trustedRoutedExecutableV3("/usr/bin/nsenter") != nil {
		return nil, ErrIdentity
	}
	hostMount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		return nil, ErrIdentity
	}
	defer hostMount.Close()
	hostMountID, err := namespaceID("/proc/self/ns/mnt")
	if err != nil {
		return nil, ErrIdentity
	}
	parentStart, _, err := routedDHCPOwnerProcessV3(os.Getpid())
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	incarnation := hex.EncodeToString(nonce[:])
	var pipes []*os.File
	defer func() {
		for _, f := range pipes {
			_ = f.Close()
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		r, w, e := os.Pipe()
		if e == nil {
			pipes = append(pipes, r, w)
		}
		return r, w, e
	}
	bootR, bootW, err := pipe()
	if err != nil {
		return nil, err
	}
	eventR, eventW, err := pipe()
	if err != nil {
		return nil, err
	}
	queryR, queryW, err := pipe()
	if err != nil {
		return nil, err
	}
	replyR, replyW, err := pipe()
	if err != nil {
		return nil, err
	}
	controlR, controlW, err := pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/usr/bin/nsenter", "--net=/proc/self/fd/3", "--", self, RoutedDHCPOwnerRoleV3) // #nosec G204 -- Fixed nsenter role, current root-trusted executable, inherited namespace FD; no caller path or shell.
	cmd.ExtraFiles = []*os.File{o.Gateway, o.Host, hostMount, bootR, eventW, queryR, replyW, controlR}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LC_ALL=C"}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS, Pdeathsig: syscall.SIGKILL}
	s := &RoutedDHCPOwnerV3{cmd: cmd, control: controlW, events: eventR, scanner: routedDHCPOwnerScannerV3(eventR), done: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		e := cmd.Start()
		started <- e
		if e == nil {
			_ = cmd.Wait()
			close(s.done)
		}
	}()
	if err = <-started; err != nil {
		return nil, ErrUnavailable
	}
	failed := true
	defer func() {
		if failed {
			_ = cmd.Process.Kill()
			select {
			case <-s.done:
			case <-time.After(5 * time.Second):
			}
			if s.mount != nil {
				_ = s.mount.Close()
			}
			_ = s.files.Close()
		}
	}()
	for _, f := range []*os.File{bootR, eventW, queryR, replyW, controlR} {
		_ = f.Close()
	}
	pid := cmd.Process.Pid
	if pid <= 1 || pid > math.MaxInt32 {
		return nil, ErrIdentity
	}
	s.mount, err = os.Open("/proc/" + strconv.Itoa(pid) + "/ns/mnt")
	if err != nil {
		return nil, ErrIdentity
	}
	info, err := s.mount.Stat()
	if err != nil {
		return nil, ErrIdentity
	}
	mountID := info.Sys().(*syscall.Stat_t).Ino
	if mountID == hostMountID || !routedDHCPOwnerNamespaceV3(s.mount, unix.CLONE_NEWNS, mountID) {
		return nil, ErrIdentity
	}
	startup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := startup.Deadline()
	if bootW.SetWriteDeadline(deadline) != nil || eventR.SetReadDeadline(deadline) != nil {
		return nil, ErrUnavailable
	}
	b := routedDHCPOwnerBootstrapV3{3, os.Getpid(), parentStart, o.Metadata, desired, incarnation, mountID, hostMountID}
	if routedDHCPOwnerWriteV3(bootW, b) != nil {
		return nil, ErrUnavailable
	}
	_ = bootW.Close()
	if !s.scanner.Scan() {
		return nil, ErrUnavailable
	}
	var ready routedDHCPOwnerReadyV3
	if routedDHCPOwnerDecodeV3(s.scanner.Bytes(), &ready) != nil || ready.Version != 3 || ready.Incarnation != incarnation || ready.RolePID != pid || ready.LeasePID <= 1 || ready.LeasePID > math.MaxInt32 || ready.Stopped || startup.Err() != nil {
		return nil, ErrIdentity
	}
	roleFD, roleStart, err := routedDHCPOwnerPinV3(pid, os.Getpid(), o.Metadata.GatewayNamespace, mountID)
	if err != nil {
		return nil, err
	}
	s.files.RolePIDFD = roleFD
	leaseFD, leaseStart, err := routedDHCPOwnerPinV3(ready.LeasePID, pid, o.Metadata.GatewayNamespace, mountID)
	if err != nil {
		return nil, err
	}
	s.files.LeasePIDFD = leaseFD
	if roleStart != ready.RoleStartTicks || leaseStart != ready.LeaseStartTicks {
		return nil, ErrIdentity
	}
	s.binding = RoutedDHCPOwnerBindingV3{Version: 3, RolePID: int32(pid), RoleStartTicks: roleStart, MountNamespace: mountID, HostMountNamespace: hostMountID, Desired: desired, Owner: networkexecutor.LeaseOwner{Namespace: o.Metadata.GatewayNamespace, BootID: o.Metadata.BootID, RunID: o.Metadata.RunID, Incarnation: incarnation, PID: uint32(ready.LeasePID), StartTicks: leaseStart}}
	if !routedDHCPOwnerBindingValidV3(s.binding) {
		return nil, ErrIdentity
	}
	s.files.Request, s.files.Reply = queryW, replyR
	// Successful startup transfers precisely these four pipe endpoints to s.
	pipes = []*os.File{bootR, bootW, eventW, queryR, replyW, controlR}
	failed = false
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.done:
		}
	}()
	return s, nil
}

func (s *RoutedDHCPOwnerV3) TakeReaderFiles() (RoutedDHCPOwnerFilesV3, RoutedDHCPOwnerBindingV3, error) {
	if s == nil {
		return RoutedDHCPOwnerFilesV3{}, RoutedDHCPOwnerBindingV3{}, ErrIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.transferred || !routedDHCPOwnerPIDFDAliveV3(s.files.RolePIDFD, int(s.binding.RolePID)) || !routedDHCPOwnerPIDFDAliveV3(s.files.LeasePIDFD, int(s.binding.Owner.PID)) {
		return RoutedDHCPOwnerFilesV3{}, RoutedDHCPOwnerBindingV3{}, ErrUnavailable
	}
	b, err := jsonOwnerBindingV3(s.binding)
	if err != nil {
		return RoutedDHCPOwnerFilesV3{}, RoutedDHCPOwnerBindingV3{}, err
	}
	f := s.files
	s.files = RoutedDHCPOwnerFilesV3{}
	s.transferred = true
	return f, b, nil
}
func (s *RoutedDHCPOwnerV3) Done() <-chan struct{} {
	if s == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return s.done
}
func (s *RoutedDHCPOwnerV3) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	defer func() { _ = s.control.Close(); _ = s.events.Close(); _ = s.mount.Close(); _ = s.files.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	if s.control.SetWriteDeadline(deadline) != nil || s.events.SetReadDeadline(deadline) != nil || routedDHCPOwnerWriteV3(s.control, routedDHCPOwnerRequestV3{3, s.binding.Owner.Incarnation, 1, "stop"}) != nil || !s.scanner.Scan() {
		s.closeErr = ErrUnavailable
	} else {
		var stopped routedDHCPOwnerReadyV3
		if routedDHCPOwnerDecodeV3(s.scanner.Bytes(), &stopped) != nil || stopped.Version != 3 || !stopped.Stopped || stopped.Incarnation != s.binding.Owner.Incarnation || stopped.RolePID != int(s.binding.RolePID) || stopped.RoleStartTicks != s.binding.RoleStartTicks || stopped.LeasePID != int(s.binding.Owner.PID) || stopped.LeaseStartTicks != s.binding.Owner.StartTicks {
			s.closeErr = ErrUnavailable
		}
	}
	if s.closeErr != nil {
		_ = s.cmd.Process.Kill()
	}
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.closeErr = ErrUnavailable
		_ = s.cmd.Process.Kill()
	}
	return s.closeErr
}
