//go:build linux

package previewruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/AsterG/andeiva/internal/dhcpkea"
	"github.com/AsterG/andeiva/internal/dhcpserver"
	"github.com/AsterG/andeiva/internal/jsoncheck"
	"golang.org/x/sys/unix"
)

func decodeRoutedDHCPServerBootstrapV2(raw []byte) (routedDHCPServerBootstrapV2, error) {
	return decodeRoutedDHCPServerBootstrapForRoleV1(raw, 2)
}

func decodeRoutedDHCPServerBootstrapForRoleV1(raw []byte, version int) (routedDHCPServerBootstrapV2, error) {
	var b routedDHCPServerBootstrapV2
	if len(raw) == 0 || len(raw) > routedDHCPServerBootstrapLimitV1 || !jsoncheck.UniqueControlFields(raw) {
		return b, ErrIdentity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || b.Version != version || (version == 3 && !b.SupervisorLifetime) || b.ParentPID <= 1 || b.ParentStartTicks == 0 || b.HostMountNamespace == 0 || b.DeadlineBootNS <= 0 || b.Metadata.ValidateRouted() != nil || len(b.Bindings) == 0 || len(b.Bindings) > 64 || len(b.ServiceCgroups) == 0 || len(b.ServiceCgroups) > 2 || b.LeaseBudgetBytes <= 0 || !routedDHCPServerMountWireValidV2(b.MountPins) {
		return routedDHCPServerBootstrapV2{}, ErrIdentity
	}
	canonical, err := json.Marshal(b)
	if err != nil || !bytes.Equal(raw, canonical) {
		return routedDHCPServerBootstrapV2{}, ErrIdentity
	}
	roles := map[string]bool{}
	identities := map[RoutedDHCPServiceCgroupIdentityV1]bool{}
	for _, pin := range b.ServiceCgroups {
		id := RoutedDHCPServiceCgroupIdentityV1{Device: pin.Device, Inode: pin.Inode}
		if roles[pin.Role] || identities[id] || !routedDHCPServerCgroupPinNameV1(RoutedDHCPServerCgroupPinV1{Role: pin.Role, Name: pin.Name, Identity: id}) {
			return routedDHCPServerBootstrapV2{}, ErrIdentity
		}
		roles[pin.Role], identities[id] = true, true
	}
	if !roles["lan"] {
		return routedDHCPServerBootstrapV2{}, ErrIdentity
	}
	return b, nil
}

// The retired wire cannot start a component or negotiate a protocol fallback.
func RunRoutedDHCPServerRoleV1(context.Context) error { return ErrIdentity }

// The fixed role receives FD3 gateway,4 hostNET,5 hostMNT,6 config,7 leases,
// 8 sealed bootstrap,9 lifetime control,10/11 detached mounts,12..13 cgroup pins.
// It never reads an administrative URL, path or shell command.
func RunRoutedDHCPServerRoleV2(parent context.Context) error {
	return runRoutedDHCPServerRoleV1(parent, 2)
}

func RunRoutedDHCPServerRoleV3(parent context.Context) error {
	return runRoutedDHCPServerRoleV1(parent, 3)
}

func runRoutedDHCPServerRoleV1(parent context.Context, version int) (result error) {
	if parent == nil || parent.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrIdentity
	}
	// Read the regular sealed bootstrap before constructing pollable pipe files,
	// so a missing inherited service pin cannot be filled by a Go poller FD.
	var st unix.Stat_t
	seals, err := unix.FcntlInt(8, unix.F_GET_SEALS, 0)
	wantSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals != wantSeals || unix.Fstat(8, &st) != nil || st.Mode != unix.S_IFREG|0400 || st.Uid != 0 || st.Size <= 0 || st.Size > routedDHCPServerBootstrapLimitV1 {
		return ErrIdentity
	}
	raw := make([]byte, st.Size)
	n, err := unix.Pread(8, raw, 0)
	if err != nil || n != len(raw) {
		return ErrIdentity
	}
	b, err := decodeRoutedDHCPServerBootstrapForRoleV1(raw, version)
	if err != nil {
		return err
	}
	if err := captureRoutedDHCPServerRawFDsV2(b); err != nil {
		return err
	}
	var proof *net.UnixConn
	if version == 3 {
		fd := 12 + len(b.ServiceCgroups)
		unix.CloseOnExec(fd)
		file := os.NewFile(uintptr(fd), "kea-engine-proof")
		proof, err = routedDHCPJobSocketV4(file)
		_ = file.Close()
		if err != nil {
			return err
		}
		defer proof.Close()
	}
	var pins []RoutedDHCPServerCgroupPinV1
	for i, wire := range b.ServiceCgroups {
		fd := i + 12
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrIdentity
		}
		pin := RoutedDHCPServerCgroupPinV1{Role: wire.Role, Name: wire.Name, Identity: RoutedDHCPServiceCgroupIdentityV1{Device: wire.Device, Inode: wire.Inode}, Directory: os.NewFile(uintptr(fd), "dhcp-server-service-pin")}
		pins = append(pins, pin)
		defer pin.Directory.Close()
		unix.CloseOnExec(fd)
		actual, err := routedDHCPServiceDirectoryV1(pin.Directory)
		if err != nil || actual != pin.Identity || !routedDHCPServerCgroupPinNameV1(pin) {
			return ErrIdentity
		}
	}
	if b.ParentPID != os.Getppid() {
		return ErrIdentity
	}
	start, _, err := routedDHCPOwnerProcessV3(b.ParentPID)
	status, statusErr := routedDHCPOwnerReadV3("/proc/"+strconv.Itoa(b.ParentPID)+"/status", 65536)
	if err != nil || start != b.ParentStartTicks || statusErr != nil || !rootRoutedParentStatusV3(status, b.ParentPID) {
		return ErrIdentity
	}
	if unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0) != nil || b.ParentPID != os.Getppid() {
		return ErrIdentity
	}
	controlFlags, err := unix.FcntlInt(9, unix.F_GETFL, 0)
	if err != nil || controlFlags&unix.O_ACCMODE != unix.O_RDONLY || unix.Fstat(9, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || unix.SetNonblock(9, true) != nil {
		return ErrIdentity
	}
	var files [7]*os.File
	for i := range files {
		fd := i + 3
		files[i] = os.NewFile(uintptr(fd), "routed-dhcp-server-role")
		defer files[i].Close()
		unix.CloseOnExec(fd)
	}
	mountPins := &routedDHCPServerMountPinsV2{configuration: os.NewFile(10, "configuration-mount"), leases: os.NewFile(11, "leases-mount")}
	defer func() { result = errors.Join(result, mountPins.closeV2()) }()
	unix.CloseOnExec(10)
	unix.CloseOnExec(11)
	if !routedDHCPOwnerPipeV3(files[6], unix.O_RDONLY) {
		return ErrIdentity
	}
	if !routedDHCPOwnerNamespaceV3(files[2], unix.CLONE_NEWNS, b.HostMountNamespace) {
		return ErrIdentity
	}
	var bindings []dhcpkea.Binding
	for _, wire := range b.Bindings {
		prefix, err := netip.ParsePrefix(wire.Address)
		if err != nil || prefix.String() != wire.Address {
			return ErrIdentity
		}
		bindings = append(bindings, dhcpkea.Binding{Interface: dhcpserver.Binding{InterfaceID: wire.InterfaceID, Role: wire.Role, Address: prefix}, Name: wire.Name, SubnetID: wire.SubnetID})
	}
	now, err := routedDHCPOwnerBootNowV3()
	if err != nil || b.DeadlineBootNS <= now {
		return ErrIdentity
	}
	lifetime, cancel := context.WithCancel(parent)
	defer cancel()
	ctx, cancelStartup := context.WithTimeout(lifetime, time.Duration(b.DeadlineBootNS-now))
	defer cancelStartup()
	// EOF is revocation. Any byte is a protocol error, never a command.
	controlDone := make(chan error, 1)
	go func() {
		var one [1]byte
		n, err := files[6].Read(one[:])
		if n != 0 {
			err = ErrIdentity
		}
		if err == nil {
			err = ErrIdentity
		}
		controlDone <- err
		cancel()
	}()
	defer func() {
		_ = files[6].Close()
		controlErr := <-controlDone
		if controlErr != io.EOF && !errors.Is(controlErr, os.ErrClosed) {
			result = errors.Join(result, ErrIdentity)
		}
	}()
	o := RoutedDHCPServerResourcesV1{Metadata: b.Metadata, Gateway: files[0], Host: files[1], HostMount: files[2], Configuration: files[3], Leases: files[4], Config: b.Config, Bindings: bindings, ServiceCgroups: pins, LeaseBudgetBytes: b.LeaseBudgetBytes, mountPins: mountPins}
	if proof != nil {
		o.inspect = func(ctx context.Context, fd, pid int, uid, gid uint32) error {
			engine, identity, err := routedKeaSocketEngineV1(fd, pid, uid, gid, b.Metadata.GatewayNamespace)
			if err != nil {
				return err
			}
			return serveRoutedKeaSocketProofV1(ctx, proof, routedDHCPJobPeerV4{pid: b.ParentPID}, engine, identity)
		}
	}
	if b.SupervisorLifetime {
		return runRoutedDHCPServerComponentScopedV2(ctx, lifetime, b.DeadlineBootNS, o)
	}
	return RunRoutedDHCPServerComponentV1(ctx, o)
}
